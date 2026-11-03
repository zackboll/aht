--  Copyright (C) 2026 Contributors to AHT
--  SPDX-License-Identifier: Apache-2.0

--  TLS.Try_Write, TLS.Try_Flush and TLS.Pending_Output, both backends.
--  Every nonblocking call is timed against Call_Bound, generous so a
--  loaded runner cannot fail it while a call that parks on the socket
--  would exceed it by orders of magnitude.
--
--  Cases:
--    1. the HTTPS fixture (8766): nothing pending on a fresh session;
--       a request accepted whole and flushed in one call; the
--       response collected with Try_Read; the graceful Close
--    2. the deaf fixture (8769), which never reads: Try_Write reports
--       Would_Block once the window is full, never parks, accepts no
--       further plaintext (Pending_Output stays put over repeated
--       calls), Try_Flush keeps reporting Would_Block; Abortive_Close
--       is prompt with ciphertext still queued, and idempotent
--    3. the sink fixture (8779), which stops reading on command and
--       hashes what it receives: plaintext written through a full
--       window, flushed in several Would_Block/Flushed rounds, then
--       more written with the blocking Write; the fixture's byte count
--       and SHA-256 prove every accepted byte reached it once, in order
--    4. the abrupt fixture (8771), which closes under us: Try_Write
--       raises, the session is poisoned, Abortive_Close still works
--    5. an `openssl s_server -tls1_2` sending a HelloRequest: both
--       engines refuse renegotiation with a warning alert queued inside
--       Try_Read, which Pending_Output exposes and Try_Flush ships
--       without any application plaintext; the server, which treats
--       the refusal as fatal, then ends the session, observed through
--       Try_Read. SKIPs without an OpenSSL 3 CLI, as test_tls_keyupdate.
--
--  Does not cover:
--    - Needs_Read: neither engine asks for input from a write once
--      the handshake is done and renegotiation is refused, so the
--      status is unreachable with these fixtures
--    - the timing of case 3's first Would_Block from Try_Flush: the
--      fixture holds for a fixed time, so that observation is as
--      deterministic as the hold is long. The byte accounting that the
--      case is about does not depend on it.

with Ada.Command_Line;
with Ada.Directories;
with Ada.Environment_Variables;
with Ada.Exceptions;
with Ada.Real_Time; use Ada.Real_Time;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO; use Ada.Text_IO;

with GNAT.Expect;
with GNAT.OS_Lib;
with GNAT.SHA256;

with AHT.Bytes;
with AHT.Transport;
with AHT.Transport.TLS;
with AHT.URL;

procedure Test_TLS_Try_Write is

   use AHT.Transport.TLS;

   HTTPS_Port  : constant AHT.URL.Port_Number := 8766;
   Deaf_Port   : constant AHT.URL.Port_Number := 8769;
   Abrupt_Port : constant AHT.URL.Port_Number := 8771;
   Sink_Port   : constant AHT.URL.Port_Number := 8779;
   Renego_Port : constant AHT.URL.Port_Number := 8780;

   CA_File  : constant String := "tests/server/certs/server.crt";
   Key_File : constant String := "tests/server/certs/server.key";

   Call_Bound : constant Time_Span := Milliseconds (500);
   Patience   : constant Time_Span := Seconds (10);
   Poll_Gap   : constant Duration := 0.005;
   CRLF       : constant String := ASCII.CR & ASCII.LF;

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_tls_try_write: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   function Contains (Haystack, Needle : String) return Boolean is
     (Ada.Strings.Fixed.Index (Haystack, Needle) /= 0);

   procedure Check_Bound (Started : Time; Where : String) is
   begin
      if Clock - Started > Call_Bound then
         Fail (Where & ": call took "
               & Duration'Image (To_Duration (Clock - Started)) & " s");
      end if;
   end Check_Bound;

   procedure Timed_Try_Write
     (T      : in out TLS_Transport;
      Data   : AHT.Bytes.Byte_Array;
      Count  : out Natural;
      Status : out Try_Write_Status;
      Where  : String)
   is
      Started : constant Time := Clock;
   begin
      T.Try_Write (Data, Count, Status);
      Check_Bound (Started, Where & ": Try_Write");
      if Count > Data'Length then
         Fail (Where & ": Try_Write accepted" & Count'Image
               & " of" & Data'Length'Image);
      end if;
      if Status /= Accepted and then Count /= 0 then
         Fail (Where & ": " & Status'Image & " with Count" & Count'Image);
      end if;
   end Timed_Try_Write;

   procedure Timed_Try_Flush
     (T      : in out TLS_Transport;
      Status : out Try_Flush_Status;
      Where  : String)
   is
      Started : constant Time := Clock;
   begin
      T.Try_Flush (Status);
      Check_Bound (Started, Where & ": Try_Flush");
      if Status = Flushed and then T.Pending_Output /= 0 then
         Fail (Where & ": Flushed with" & T.Pending_Output'Image
               & " bytes pending");
      elsif Status = Would_Block and then T.Pending_Output = 0 then
         Fail (Where & ": Would_Block with nothing pending");
      end if;
   end Timed_Try_Flush;

   --  Try_Read until something other than Would_Block, or Patience.
   procedure Poll_Read
     (T         : in out TLS_Transport;
      Data      : out AHT.Bytes.Byte_Array;
      Last      : out Natural;
      Status    : out Try_Read_Status;
      Timed_Out : out Boolean;
      Where     : String)
   is
      Give_Up : constant Time := Clock + Patience;
   begin
      Timed_Out := False;
      loop
         declare
            Started : constant Time := Clock;
         begin
            T.Try_Read (Data, Last, Status);
            Check_Bound (Started, Where & ": Try_Read");
         end;
         exit when Status /= Would_Block;
         if Clock > Give_Up then
            Timed_Out := True;
            exit;
         end if;
         delay Poll_Gap;
      end loop;
   end Poll_Read;

   --  Write Data to completion through Try_Write/Try_Flush, resuming
   --  from Count and never passing an accepted byte twice. Counts the
   --  Would_Block flushes it took so the caller can assert on them.
   --  Gives up after Patience.
   procedure Write_Whole
     (T       : in out TLS_Transport;
      Data    : AHT.Bytes.Byte_Array;
      Blocked : in out Natural;
      Where   : String)
   is
      Give_Up : constant Time := Clock + Patience;
      Pos     : Natural := Data'First;
      Count   : Natural;
      WS      : Try_Write_Status;
      FS      : Try_Flush_Status;
   begin
      while Pos <= Data'Last loop
         Timed_Try_Write (T, Data (Pos .. Data'Last), Count, WS, Where);
         case WS is
            when Accepted =>
               Pos := Pos + Count;
            when Would_Block =>
               Blocked := Blocked + 1;
               delay Poll_Gap;
            when Needs_Read =>
               Fail (Where & ": Needs_Read from a settled session");
               return;
         end case;
         if Clock > Give_Up then
            Fail (Where & ": write did not complete within Patience");
            return;
         end if;
      end loop;
      loop
         Timed_Try_Flush (T, FS, Where);
         exit when FS = Flushed;
         Blocked := Blocked + 1;
         if Clock > Give_Up then
            Fail (Where & ": flush did not complete within Patience");
            return;
         end if;
         delay Poll_Gap;
      end loop;
   end Write_Whole;

   procedure Timed_Abortive_Close
     (T : in out TLS_Transport; Where : String)
   is
      Started : constant Time := Clock;
   begin
      T.Abortive_Close;
      Check_Bound (Started, Where & ": Abortive_Close");
      if T.Is_Connected then
         Fail (Where & ": Is_Connected after Abortive_Close");
      end if;
      if T.Pending_Output /= 0 then
         Fail (Where & ": Pending_Output after Abortive_Close");
      end if;
   exception
      when E : others =>
         Fail (Where & ": Abortive_Close raised "
               & Ada.Exceptions.Exception_Name (E) & " — "
               & Ada.Exceptions.Exception_Message (E));
   end Timed_Abortive_Close;

   Buf    : AHT.Bytes.Byte_Array (1 .. 4096);
   Last   : Natural;
   RS     : Try_Read_Status;
   WS     : Try_Write_Status;
   FS     : Try_Flush_Status;
   Count  : Natural;
   Timed_Out : Boolean;

begin
   --  Case 1: the ordinary path. Nothing is pending after the
   --  handshake; a small request is accepted whole and its record
   --  goes out in the same call, so Try_Flush has nothing to do.
   declare
      T   : TLS_Transport;
      Acc : Unbounded_String;
      Req : constant AHT.Bytes.Byte_Array := AHT.Bytes.From_String
        ("GET /hello HTTP/1.1" & CRLF & "Host: localhost" & CRLF
         & "Connection: close" & CRLF & CRLF);
   begin
      T.Connect ("localhost", HTTPS_Port, Insecure => False,
                 CA_Path => CA_File);
      if T.Pending_Output /= 0 then
         Fail ("https: " & T.Pending_Output'Image
               & " bytes pending after Connect");
      end if;
      Timed_Try_Flush (T, FS, "https/idle");
      if FS /= Flushed then
         Fail ("https: idle Try_Flush gave " & FS'Image);
      end if;
      Timed_Try_Write (T, Buf (1 .. 0), Count, WS, "https/empty");
      if WS /= Accepted or else Count /= 0 then
         Fail ("https: empty Try_Write gave " & WS'Image & Count'Image);
      end if;
      Timed_Try_Write (T, Req, Count, WS, "https");
      if WS /= Accepted or else Count /= Req'Length then
         Fail ("https: request gave " & WS'Image & Count'Image
               & " of" & Req'Length'Image);
      end if;
      if T.Pending_Output /= 0 then
         Fail ("https: " & T.Pending_Output'Image
               & " bytes pending after an unobstructed Try_Write");
      end if;
      loop
         Poll_Read (T, Buf, Last, RS, Timed_Out, "https");
         if Timed_Out then
            Fail ("https: response not completed within Patience");
            exit;
         end if;
         exit when RS = Peer_Closed;
         Append (Acc, AHT.Bytes.To_String (Buf (1 .. Last)));
      end loop;
      if not Contains (To_String (Acc), "200")
        or else not Contains (To_String (Acc), "hello, world")
      then
         Fail ("https: bad response — """ & To_String (Acc) & """");
      end if;
      T.Close;
      if T.Is_Connected then
         Fail ("https: Is_Connected after Close");
      end if;
   exception
      when E : others =>
         Fail ("https: " & Ada.Exceptions.Exception_Name (E) & " — "
               & Ada.Exceptions.Exception_Message (E));
   end;

   --  Case 2: a peer that never reads. Writes land in the socket until
   --  the window is full, then Would_Block, and from then on nothing
   --  moves: no call parks, no plaintext is taken, the queue does not
   --  grow. Abortive_Close reclaims it all without a wait.
   declare
      T        : TLS_Transport;
      Chunk    : constant AHT.Bytes.Byte_Array (1 .. 16_384) :=
        [others => 16#41#];
      Accepted_Bytes : Natural := 0;
      Blocked  : Boolean := False;
      Pending  : Natural;
   begin
      T.Connect ("127.0.0.1", Deaf_Port, Insecure => True);
      for I in 1 .. 10_000 loop
         Timed_Try_Write (T, Chunk, Count, WS, "deaf");
         case WS is
            when Accepted =>
               Accepted_Bytes := Accepted_Bytes + Count;
            when Would_Block =>
               Blocked := True;
               exit;
            when Needs_Read =>
               Fail ("deaf: Needs_Read");
               exit;
         end case;
      end loop;
      if not Blocked then
         Fail ("deaf: never reported Would_Block after"
               & Accepted_Bytes'Image & " accepted bytes");
      end if;
      Pending := T.Pending_Output;
      if Pending = 0 then
         Fail ("deaf: Would_Block with nothing pending");
      end if;
      for I in 1 .. 20 loop
         Timed_Try_Write (T, Chunk, Count, WS, "deaf/repeat");
         if WS /= Would_Block or else Count /= 0 then
            Fail ("deaf: repeat Try_Write gave " & WS'Image & Count'Image);
            exit;
         end if;
         Timed_Try_Flush (T, FS, "deaf/repeat");
         if FS /= Would_Block then
            Fail ("deaf: repeat Try_Flush gave " & FS'Image);
            exit;
         end if;
         if T.Pending_Output /= Pending then
            Fail ("deaf: pending output moved from" & Pending'Image
                  & " to" & T.Pending_Output'Image
                  & " while the socket refused everything");
            exit;
         end if;
      end loop;
      if not T.Is_Connected then
         Fail ("deaf: Would_Block poisoned the session");
      end if;
      Timed_Abortive_Close (T, "deaf");
      Timed_Abortive_Close (T, "deaf (second)");
      begin
         T.Try_Write (Chunk, Count, WS);
         Fail ("deaf: Try_Write after Abortive_Close returned " & WS'Image);
      exception
         when AHT.Transport.Transport_Error => null;  --  expected
         when E : others =>
            Fail ("deaf: Try_Write after Abortive_Close raised "
                  & Ada.Exceptions.Exception_Name (E));
      end;
      begin
         T.Try_Flush (FS);
         Fail ("deaf: Try_Flush after Abortive_Close returned " & FS'Image);
      exception
         when AHT.Transport.Transport_Error => null;  --  expected
         when E : others =>
            Fail ("deaf: Try_Flush after Abortive_Close raised "
                  & Ada.Exceptions.Exception_Name (E));
      end;
   exception
      when E : others =>
         Fail ("deaf: " & Ada.Exceptions.Exception_Name (E) & " — "
               & Ada.Exceptions.Exception_Message (E));
   end;

   --  Case 3: byte accounting through backpressure. The fixture reads
   --  payload, holds on HOLD, and on SUM answers with the count and
   --  SHA-256 of everything it received. Phase A writes through the
   --  hold with Try_Write/Try_Flush, so records are accepted while
   --  their ciphertext waits in the queue across several flushes;
   --  phase B writes more with the blocking Write, which must ship the
   --  queue first; the digest then proves order and uniqueness.
   declare
      T       : TLS_Transport;
      Ctx     : GNAT.SHA256.Context;
      Sent    : Natural := 0;
      Blocked : Natural := 0;
      Acc     : Unbounded_String;
      --  Payload lines carry no newline of their own; the fixture
      --  hashes a line with its terminator, so the terminator is sent
      --  and hashed here too.
      Line_Len : constant := 40_000;
      Line     : AHT.Bytes.Byte_Array (1 .. Line_Len + 1);
      Rounds   : constant := 120;
      --  Rounds * Line_Len is well past any loopback send buffer, so
      --  the hold is met by a full window.
      Before   : constant Natural := Failures;

      procedure Account (Data : AHT.Bytes.Byte_Array) is
      begin
         GNAT.SHA256.Update (Ctx, AHT.Bytes.To_String (Data));
         Sent := Sent + Data'Length;
      end Account;
   begin
      for I in 1 .. Line_Len loop
         Line (I) := AHT.Bytes.Octet (16#61# + (I mod 26));
      end loop;
      Line (Line'Last) := 10;

      T.Connect ("127.0.0.1", Sink_Port, Insecure => True);
      T.Set_Write_Deadline (30.0);
      T.Set_Read_Deadline (30.0);

      --  Phase A: nonblocking, through the hold.
      Write_Whole (T, AHT.Bytes.From_String ("HOLD" & ASCII.LF),
                   Blocked, "sink/hold");
      for R in 1 .. Rounds loop
         Write_Whole (T, Line, Blocked, "sink/line");
         Account (Line);
         exit when Failures > Before;
      end loop;
      if Blocked = 0 then
         Fail ("sink: no Would_Block in" & Rounds'Image
               & " rounds against a holding peer");
      end if;

      --  Phase B: the blocking Write after nonblocking progression.
      --  A record is left queued on purpose (Try_Write without the
      --  flush) so Write has to ship it before its own.
      Timed_Try_Write (T, Line, Count, WS, "sink/leftover");
      if WS = Accepted then
         Account (Line (1 .. Count));
      end if;
      T.Write (Line);
      Account (Line);
      T.Write (AHT.Bytes.From_String ("SUM" & ASCII.LF));
      if T.Pending_Output /= 0 then
         Fail ("sink:" & T.Pending_Output'Image
               & " bytes pending after the blocking Write");
      end if;

      loop
         T.Read (Buf, Last);
         exit when Last = 0;
         Append (Acc, AHT.Bytes.To_String (Buf (1 .. Last)));
         exit when Contains (To_String (Acc), ASCII.LF & "")
           or else Contains (To_String (Acc), "SUM ");
      end loop;
      declare
         Expected : constant String :=
           "SUM" & Sent'Image & " " & GNAT.SHA256.Digest (Ctx) & ASCII.LF;
      begin
         if To_String (Acc) /= Expected then
            Fail ("sink: peer saw """ & To_String (Acc)
                  & """, sent """ & Expected & """ ("
                  & Blocked'Image & " blocked calls)");
         end if;
      end;
      T.Close;
   exception
      when E : others =>
         Fail ("sink: " & Ada.Exceptions.Exception_Name (E) & " — "
               & Ada.Exceptions.Exception_Message (E));
   end;

   --  Case 4: the peer closes without close_notify. The kernel may
   --  take a first send before the reset lands; a later one fails,
   --  and that failure must poison, not report Would_Block.
   declare
      T      : TLS_Transport;
      Chunk  : constant AHT.Bytes.Byte_Array (1 .. 1024) :=
        [others => 16#42#];
      Raised : Boolean := False;
      Give_Up : constant Time := Clock + Patience;
   begin
      T.Connect ("127.0.0.1", Abrupt_Port, Insecure => True);
      --  The banner, then the stream ends without close_notify.
      begin
         loop
            Poll_Read (T, Buf, Last, RS, Timed_Out, "abrupt");
            exit when Timed_Out or else RS /= Data_Ready;
         end loop;
      exception
         when TLS_Error => null;  --  the truncation, as in Try_Read
      end;
      loop
         begin
            Timed_Try_Write (T, Chunk, Count, WS, "abrupt");
            if WS = Would_Block then
               Fail ("abrupt: Would_Block from a dead peer");
               exit;
            end if;
         exception
            when AHT.Transport.Transport_Error | TLS_Error =>
               Raised := True;
               exit;
         end;
         if Clock > Give_Up then
            Fail ("abrupt: no error within Patience");
            exit;
         end if;
         delay Poll_Gap;
      end loop;
      if Raised and then T.Is_Connected then
         Fail ("abrupt: Is_Connected after the fatal send");
      end if;
      if Raised then
         begin
            T.Try_Flush (FS);
            Fail ("abrupt: Try_Flush on the poisoned session gave "
                  & FS'Image);
         exception
            when AHT.Transport.Transport_Error | TLS_Error => null;
         end;
      end if;
      Timed_Abortive_Close (T, "abrupt");
      Timed_Abortive_Close (T, "abrupt (second)");
   exception
      when E : others =>
         Fail ("abrupt: " & Ada.Exceptions.Exception_Name (E) & " — "
               & Ada.Exceptions.Exception_Message (E));
   end;

   --  Case 5: protocol output generated inside Try_Read. A TLS 1.2
   --  server's HelloRequest makes both engines queue a
   --  no_renegotiation warning alert while reading. Nothing but a
   --  flush can ship it; the server treats the refusal as fatal and
   --  ends the session, which Try_Read then reports.
   declare
      function Openssl_Bin return String is
         Dir : constant String :=
           (if Ada.Environment_Variables.Exists ("AHT_OPENSSL_DIR")
            then Ada.Environment_Variables.Value ("AHT_OPENSSL_DIR")
            else "/usr");
      begin
         return Dir & "/bin/openssl";
      end Openssl_Bin;

      function CLI_Is_Openssl3 (Bin : String) return Boolean is
         use GNAT.OS_Lib;
         Status : aliased Integer;
         Args   : constant Argument_List := [1 => new String'("version")];
         Output : constant String :=
           GNAT.Expect.Get_Command_Output
             (Bin, Args, "", Status'Access, Err_To_Out => True);
      begin
         for A of Args loop
            declare
               P : GNAT.OS_Lib.String_Access := A;
            begin
               Free (P);
            end;
         end loop;
         return Status = 0
           and then Ada.Strings.Fixed.Index (Output, "OpenSSL 3") = 1;
      end CLI_Is_Openssl3;

      procedure Renegotiation_Case (Bin : String) is
         use GNAT.Expect;
         use GNAT.OS_Lib;

         Fd : Process_Descriptor;
         Q  : constant Character := '"';
         --  stdout discarded, as in test_tls_keyupdate: an undrained
         --  pipe would stall the server. stdin stays ours for 'r'.
         --  Not -quiet: that mode forwards stdin as data instead of
         --  reading it as commands.
         Command : constant String :=
           Q & Bin & Q & " s_server -accept 8780 -tls1_2"
           & " -cert " & Q & CA_File & Q
           & " -key " & Q & Key_File & Q
           & " -naccept 1 >/dev/null 2>&1";
         Args : constant Argument_List :=
           [new String'("-c"), new String'(Command)];
         T : TLS_Transport;
         Connected : Boolean := False;
         Ended     : Boolean := False;
         Settle    : constant Time_Span := Milliseconds (300);
      begin
         Non_Blocking_Spawn (Fd, "/bin/sh", Args, Buffer_Size => 8192);
         for A of Args loop
            declare
               P : GNAT.OS_Lib.String_Access := A;
            begin
               Free (P);
            end;
         end loop;

         for Attempt in 1 .. 50 loop
            begin
               T.Connect ("localhost", Renego_Port,
                          Insecure => False, CA_Path => CA_File,
                          Connect_Timeout    => 2.0,
                          Handshake_Deadline => 5.0);
               Connected := True;
               exit;
            exception
               when others => delay 0.1;
            end;
         end loop;
         if not Connected then
            Fail ("renego: could not connect to s_server on 8780");
            Close (Fd);
            return;
         end if;

         --  'r' = send a HelloRequest. Read until the engine has
         --  queued its answer; Try_Read itself reports Would_Block,
         --  there being no application data.
         Send (Fd, "r");
         declare
            Give_Up : constant Time := Clock + Patience;
         begin
            loop
               T.Try_Read (Buf, Last, RS);
               if RS /= Would_Block then
                  Fail ("renego: Try_Read gave " & RS'Image
                        & " on the HelloRequest");
                  exit;
               end if;
               exit when T.Pending_Output > 0;
               if Clock > Give_Up then
                  Fail ("renego: no output queued within Patience");
                  exit;
               end if;
               delay Poll_Gap;
            end loop;
         end;

         if T.Pending_Output > 0 then
            --  While the alert sits in our queue the server waits for
            --  a ClientHello and sends nothing; a Try_Read in that
            --  window is Would_Block.
            declare
               Till : constant Time := Clock + Settle;
            begin
               loop
                  T.Try_Read (Buf, Last, RS);
                  if RS /= Would_Block then
                     Fail ("renego: " & RS'Image & " before the flush");
                     exit;
                  end if;
                  exit when Clock > Till;
                  delay Poll_Gap;
               end loop;
            end;
            Timed_Try_Flush (T, FS, "renego");
            if FS /= Flushed then
               Fail ("renego: Try_Flush gave " & FS'Image);
            end if;
            --  The alert delivered, the server fails the session.
            begin
               Poll_Read (T, Buf, Last, RS, Timed_Out, "renego/after");
               if Timed_Out then
                  Fail ("renego: server did not react within Patience");
               elsif RS = Peer_Closed then
                  Ended := True;
               else
                  Fail ("renego: " & RS'Image & " after the flush");
               end if;
            exception
               when TLS_Error => Ended := True;
            end;
            if not Ended then
               Fail ("renego: session did not end after the flush");
            end if;
         end if;

         Timed_Abortive_Close (T, "renego");
         Close (Fd);
      exception
         when E : others =>
            Fail ("renego: " & Ada.Exceptions.Exception_Name (E) & " — "
                  & Ada.Exceptions.Exception_Message (E));
            begin
               Close (Fd);
            exception
               when others => null;
            end;
      end Renegotiation_Case;

      Bin : constant String := Openssl_Bin;
   begin
      if Ada.Directories.Exists (Bin) and then CLI_Is_Openssl3 (Bin) then
         Renegotiation_Case (Bin);
      else
         Put_Line ("test_tls_try_write: SKIP renegotiation case (no "
                   & "OpenSSL 3 CLI at " & Bin & ")");
      end if;
   end;

   if Failures = 0 then
      Put_Line ("test_tls_try_write: OK (idle, deaf, sink, abrupt, "
                & "renegotiation refusal)");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_tls_try_write:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_TLS_Try_Write;