--  Copyright (C) 2026 Contributors to AHT
--  SPDX-License-Identifier: Apache-2.0

--  Receive-side fatal lifecycle, both backends, against
--  tests/server/server_tls_reset.py (127.0.0.1:8781), which ends a
--  session on the client's command: an echo record, a TCP reset
--  (SO_LINGER 0, so the kernel sends RST), half a record then the
--  reset, a close_notify, or a bare FIN. The reset is a real
--  ECONNRESET from a real socket; nothing is injected in-process.
--
--  Cases:
--    1. established session, reset: Read raises Transport_Error (the
--       TCP identity, unchanged), Is_Connected is False afterwards,
--       a further Read and a Write are rejected without touching the
--       engine, and Abortive_Close is prompt and idempotent
--    2. the same through Try_Read: the reset surfaces as
--       Transport_Error from Try_Read, never as Would_Block or
--       Peer_Closed, and the session is poisoned the same way
--    3. half a record then the reset: with a partial record buffered
--       the engine wants more; the reset that answers is fatal, not
--       Would_Block, on Try_Read, and the same for Read
--    4. close_notify: Read gives Last = 0, Try_Read gives Peer_Closed,
--       and Is_Connected stays True (a clean end is not a fault)
--    5. FIN without close_notify: Try_Read raises TLS_Error on both
--       backends and poisons; the blocking Read keeps its backend
--       policy (TLS_Error on openssl, Last = 0 on mbedtls), and only
--       the error poisons
--    6. corrupted authentication tag (server_tls_corrupt.py, 8773):
--       TLS_Error, poisoned; the receive-side change leaves the
--       integrity path alone
--    7. Would_Block does not poison: a silent interval after an echo
--       reports Would_Block repeatedly, and the session still serves
--       the next echo
--    8. a fatal read followed by Read, Try_Read, Write, Try_Write and
--       Try_Flush: every one rejected, none within the session
--    9. fifty reset-then-Abortive_Close cycles, with a second
--       Abortive_Close and a Close each time: the fd count is back
--       where it started (Linux: /proc/self/fd; SKIPs the count
--       elsewhere, the cycles still run)
--
--  Every nonblocking call is timed against Call_Bound so a call that
--  parked on the dead socket would fail the test rather than hang.

with Ada.Command_Line;
with Ada.Directories;
with Ada.Exceptions;
with Ada.Real_Time; use Ada.Real_Time;
with Ada.Text_IO; use Ada.Text_IO;

with GNAT.Directory_Operations;

with AHT.Bytes;
with AHT.Transport;
with AHT.Transport.TLS;
with AHT.URL;

procedure Test_TLS_Reset is

   use AHT.Transport.TLS;

   Reset_Port   : constant AHT.URL.Port_Number := 8781;
   Corrupt_Port : constant AHT.URL.Port_Number := 8773;

   Banner : constant String := "RESET-FIXTURE-BANNER";

   Call_Bound : constant Time_Span := Milliseconds (500);
   --  Upper bound for one nonblocking call or Abortive_Close.
   Patience   : constant Duration := 10.0;
   --  Read deadline: bounds a blocking Read that missed the event.
   Quiet      : constant Time_Span := Milliseconds (200);
   --  How long case 7 polls a silent peer.
   Poll_Gap   : constant Duration := 0.005;
   Cycles     : constant := 50;

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_tls_reset: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   function Image (E : Ada.Exceptions.Exception_Occurrence) return String
   is (Ada.Exceptions.Exception_Name (E) & " — "
       & Ada.Exceptions.Exception_Message (E));

   function Count_Entries (Path : String) return Natural is
      use GNAT.Directory_Operations;
      Dir  : Dir_Type;
      Name : String (1 .. 256);
      Last : Natural;
      N    : Natural := 0;
   begin
      Open (Dir, Path);
      loop
         Read (Dir, Name, Last);
         exit when Last = 0;
         if Name (1 .. Last) /= "." and then Name (1 .. Last) /= ".." then
            N := N + 1;
         end if;
      end loop;
      Close (Dir);
      return N;
   exception
      when others =>
         if Is_Open (Dir) then
            Close (Dir);
         end if;
         raise;
   end Count_Entries;

   function Have_Proc return Boolean is
     (Ada.Directories.Exists ("/proc/self/fd"));

   Buf    : AHT.Bytes.Byte_Array (1 .. 4096);
   Last   : Natural;
   Status : Try_Read_Status;

   procedure Connect (T : in out TLS_Transport) is
   begin
      T.Connect ("127.0.0.1", Reset_Port, Insecure => True);
      T.Set_Read_Deadline (Patience);
   end Connect;

   procedure Command (T : in out TLS_Transport; C : Character) is
   begin
      T.Write (AHT.Bytes.From_String ([1 => C]));
   end Command;

   --  One Try_Read, timed against Call_Bound.
   procedure Timed_Try_Read
     (T     : in out TLS_Transport;
      Where : String)
   is
      Started : constant Time := Clock;
   begin
      T.Try_Read (Buf, Last, Status);
      if Clock - Started > Call_Bound then
         Fail (Where & ": Try_Read took "
               & Duration'Image (To_Duration (Clock - Started)) & " s");
      end if;
   end Timed_Try_Read;

   --  Poll Try_Read until it reports something other than Would_Block
   --  or Patience runs out (then Timed_Out). Exceptions propagate.
   procedure Poll
     (T         : in out TLS_Transport;
      Timed_Out : out Boolean;
      Where     : String)
   is
      Give_Up : constant Time := Clock + To_Time_Span (Patience);
   begin
      Timed_Out := False;
      loop
         Timed_Try_Read (T, Where);
         exit when Status /= Would_Block;
         if Clock > Give_Up then
            Timed_Out := True;
            exit;
         end if;
         delay Poll_Gap;
      end loop;
   end Poll;

   --  The echo round trip through Try_Read: proves the session is
   --  usable at this point.
   procedure Echo_Via_Try_Read (T : in out TLS_Transport; Where : String)
   is
      Timed_Out : Boolean;
   begin
      Command (T, 'E');
      Poll (T, Timed_Out, Where);
      if Timed_Out then
         Fail (Where & ": echo not received within Patience");
      elsif Status /= Data_Ready
        or else AHT.Bytes.To_String (Buf (1 .. Last)) /= Banner
      then
         Fail (Where & ": expected the banner, got " & Status'Image
               & " """ & AHT.Bytes.To_String (Buf (1 .. Last)) & """");
      end if;
   end Echo_Via_Try_Read;

   procedure Timed_Abortive_Close
     (T : in out TLS_Transport; Where : String)
   is
      Started : constant Time := Clock;
   begin
      T.Abortive_Close;
      if Clock - Started > Call_Bound then
         Fail (Where & ": Abortive_Close took "
               & Duration'Image (To_Duration (Clock - Started)) & " s");
      end if;
      if T.Is_Connected then
         Fail (Where & ": Is_Connected after Abortive_Close");
      end if;
   exception
      when E : others =>
         Fail (Where & ": Abortive_Close raised " & Image (E));
   end Timed_Abortive_Close;

   --  What a dead session must look like: Is_Connected False, every
   --  operation refused with Transport_Error or TLS_Error (the entry
   --  guard or the engine's dead flag; either is a rejection), never
   --  a result.
   procedure Expect_Dead (T : in out TLS_Transport; Where : String) is
      Count : Natural;
      WS    : Try_Write_Status;
      FS    : Try_Flush_Status;
   begin
      if T.Is_Connected then
         Fail (Where & ": Is_Connected True after the fatal error");
      end if;
      begin
         T.Read (Buf, Last);
         Fail (Where & ": Read after the fatal error returned Last ="
               & Last'Image);
      exception
         when AHT.Transport.Transport_Error | TLS_Error => null;
         when E : others =>
            Fail (Where & ": Read after the fatal error raised "
                  & Image (E));
      end;
      begin
         Timed_Try_Read (T, Where & "/dead");
         Fail (Where & ": Try_Read after the fatal error returned "
               & Status'Image);
      exception
         when AHT.Transport.Transport_Error | TLS_Error => null;
         when E : others =>
            Fail (Where & ": Try_Read after the fatal error raised "
                  & Image (E));
      end;
      begin
         T.Write (AHT.Bytes.From_String ("E"));
         Fail (Where & ": Write after the fatal error succeeded");
      exception
         when AHT.Transport.Transport_Error | TLS_Error => null;
         when E : others =>
            Fail (Where & ": Write after the fatal error raised "
                  & Image (E));
      end;
      begin
         T.Try_Write (AHT.Bytes.From_String ("E"), Count, WS);
         Fail (Where & ": Try_Write after the fatal error returned "
               & WS'Image);
      exception
         when AHT.Transport.Transport_Error | TLS_Error => null;
         when E : others =>
            Fail (Where & ": Try_Write after the fatal error raised "
                  & Image (E));
      end;
      begin
         T.Try_Flush (FS);
         Fail (Where & ": Try_Flush after the fatal error returned "
               & FS'Image);
      exception
         when AHT.Transport.Transport_Error | TLS_Error => null;
         when E : others =>
            Fail (Where & ": Try_Flush after the fatal error raised "
                  & Image (E));
      end;
   end Expect_Dead;

   --  Drive a blocking Read to the end the fixture sends on Command.
   type Outcome is (None, Transport, TLS, Other);

   function Read_Until_Error
     (T : in out TLS_Transport; Where : String) return Outcome is
   begin
      loop
         T.Read (Buf, Last);
         if Last = 0 then
            return None;
         end if;
      end loop;
   exception
      when AHT.Transport.Transport_Error => return Transport;
      when TLS_Error => return TLS;
      when E : others =>
         Fail (Where & ": unexpected " & Image (E));
         return Other;
   end Read_Until_Error;

begin
   --  Case 1: established session, then the reset, seen by Read.
   declare
      T : TLS_Transport;
   begin
      Connect (T);
      Echo_Via_Try_Read (T, "reset/read");
      Command (T, 'R');
      case Read_Until_Error (T, "reset/read") is
         when Transport => null;
         when None =>
            Fail ("reset/read: the reset read as a clean EOF");
         when TLS =>
            Fail ("reset/read: the reset surfaced as TLS_Error, not the "
                  & "TCP identity");
         when Other => null;
      end case;
      Expect_Dead (T, "reset/read");
      Timed_Abortive_Close (T, "reset/read");
      Timed_Abortive_Close (T, "reset/read (second)");
   exception
      when E : others =>
         Fail ("reset/read: " & Image (E));
   end;

   --  Case 2: the reset seen by Try_Read.
   declare
      T         : TLS_Transport;
      Timed_Out : Boolean;
   begin
      Connect (T);
      Echo_Via_Try_Read (T, "reset/try");
      Command (T, 'R');
      begin
         Poll (T, Timed_Out, "reset/try");
         if Timed_Out then
            Fail ("reset/try: the reset never surfaced through Try_Read");
         else
            Fail ("reset/try: the reset surfaced as " & Status'Image);
         end if;
      exception
         when AHT.Transport.Transport_Error => null;
         when TLS_Error =>
            Fail ("reset/try: the reset surfaced as TLS_Error, not the "
                  & "TCP identity");
      end;
      Expect_Dead (T, "reset/try");
      Timed_Abortive_Close (T, "reset/try");
      Timed_Abortive_Close (T, "reset/try (second)");
   exception
      when E : others =>
         Fail ("reset/try: " & Image (E));
   end;

   --  Case 3: half a record, then the reset. The partial record is
   --  buffered in the engine (Would_Block alone would be right until
   --  the rest arrived); the reset that follows must be fatal.
   declare
      T         : TLS_Transport;
      Timed_Out : Boolean;
   begin
      Connect (T);
      Command (T, 'H');
      begin
         Poll (T, Timed_Out, "half/try");
         if Timed_Out then
            Fail ("half/try: the reset never surfaced through Try_Read");
         else
            Fail ("half/try: the reset surfaced as " & Status'Image);
         end if;
      exception
         when AHT.Transport.Transport_Error => null;
         when TLS_Error =>
            Fail ("half/try: the reset surfaced as TLS_Error, not the "
                  & "TCP identity");
      end;
      Expect_Dead (T, "half/try");
      Timed_Abortive_Close (T, "half/try");
   exception
      when E : others =>
         Fail ("half/try: " & Image (E));
   end;
   declare
      T : TLS_Transport;
   begin
      Connect (T);
      Command (T, 'H');
      case Read_Until_Error (T, "half/read") is
         when Transport => null;
         when None =>
            Fail ("half/read: the reset read as a clean EOF");
         when TLS =>
            Fail ("half/read: the reset surfaced as TLS_Error, not the "
                  & "TCP identity");
         when Other => null;
      end case;
      Expect_Dead (T, "half/read");
      Timed_Abortive_Close (T, "half/read");
   exception
      when E : others =>
         Fail ("half/read: " & Image (E));
   end;

   --  Case 4: close_notify. A clean end: Last = 0 / Peer_Closed, and
   --  the session is not poisoned by it.
   declare
      T : TLS_Transport;
   begin
      Connect (T);
      Command (T, 'C');
      T.Read (Buf, Last);
      if Last /= 0 then
         Fail ("clean/read: expected Last = 0, got" & Last'Image);
      end if;
      if not T.Is_Connected then
         Fail ("clean/read: Is_Connected False after close_notify");
      end if;
      Timed_Try_Read (T, "clean/read");
      if Status /= Peer_Closed then
         Fail ("clean/read: Try_Read after close_notify gave "
               & Status'Image);
      end if;
      T.Close;
   exception
      when E : others =>
         Fail ("clean/read: " & Image (E));
   end;
   declare
      T         : TLS_Transport;
      Timed_Out : Boolean;
   begin
      Connect (T);
      Command (T, 'C');
      Poll (T, Timed_Out, "clean/try");
      if Timed_Out then
         Fail ("clean/try: close_notify not seen within Patience");
      elsif Status /= Peer_Closed then
         Fail ("clean/try: expected Peer_Closed, got " & Status'Image);
      end if;
      if not T.Is_Connected then
         Fail ("clean/try: Is_Connected False after close_notify");
      end if;
      T.Close;
   exception
      when E : others =>
         Fail ("clean/try: " & Image (E));
   end;

   --  Case 5: FIN without close_notify. Try_Read: TLS_Error on both
   --  backends, poisoned. Read: the backend's documented policy.
   declare
      T         : TLS_Transport;
      Timed_Out : Boolean;
   begin
      Connect (T);
      Command (T, 'F');
      begin
         Poll (T, Timed_Out, "fin/try");
         if Timed_Out then
            Fail ("fin/try: the FIN never surfaced through Try_Read");
         else
            Fail ("fin/try: the FIN surfaced as " & Status'Image);
         end if;
      exception
         when TLS_Error => null;
         when AHT.Transport.Transport_Error =>
            Fail ("fin/try: the FIN surfaced as Transport_Error, not "
                  & "the truncation TLS_Error");
      end;
      Expect_Dead (T, "fin/try");
      Timed_Abortive_Close (T, "fin/try");
   exception
      when E : others =>
         Fail ("fin/try: " & Image (E));
   end;
   declare
      T : TLS_Transport;
   begin
      Connect (T);
      Command (T, 'F');
      case Read_Until_Error (T, "fin/read") is
         when TLS =>
            --  openssl's strict-EOF policy; the error poisons.
            Expect_Dead (T, "fin/read");
         when None =>
            --  mbedtls's clean-EOF policy; a clean end does not.
            if not T.Is_Connected then
               Fail ("fin/read: Is_Connected False after a clean EOF");
            end if;
         when Transport =>
            Fail ("fin/read: the FIN surfaced as Transport_Error");
         when Other => null;
      end case;
      Timed_Abortive_Close (T, "fin/read");
   exception
      when E : others =>
         Fail ("fin/read: " & Image (E));
   end;

   --  Case 6: corrupted authentication tag. Unchanged integrity path.
   declare
      T : TLS_Transport;
   begin
      T.Connect ("127.0.0.1", Corrupt_Port, Insecure => True);
      T.Set_Read_Deadline (Patience);
      case Read_Until_Error (T, "corrupt") is
         when TLS => null;
         when None =>
            Fail ("corrupt: clean EOF instead of an integrity failure");
         when Transport =>
            Fail ("corrupt: Transport_Error instead of TLS_Error");
         when Other => null;
      end case;
      Expect_Dead (T, "corrupt");
      Timed_Abortive_Close (T, "corrupt");
   exception
      when E : others =>
         Fail ("corrupt: " & Image (E));
   end;

   --  Case 7: Would_Block is not a fault. Silence after an echo reads
   --  as Would_Block for Quiet, and the session still echoes after.
   declare
      T    : TLS_Transport;
      Till : Time;
      N    : Natural := 0;
   begin
      Connect (T);
      Echo_Via_Try_Read (T, "quiet/before");
      Till := Clock + Quiet;
      loop
         Timed_Try_Read (T, "quiet");
         if Status /= Would_Block or else Last /= 0 then
            Fail ("quiet: expected Would_Block/0, got "
                  & Status'Image & Last'Image);
            exit;
         end if;
         N := N + 1;
         exit when Clock > Till;
         delay Poll_Gap;
      end loop;
      if N < 2 then
         Fail ("quiet: only" & N'Image & " Would_Block observations");
      end if;
      if not T.Is_Connected then
         Fail ("quiet: Is_Connected False after Would_Block");
      end if;
      Echo_Via_Try_Read (T, "quiet/after");
      Command (T, 'C');
      T.Close;
   exception
      when E : others =>
         Fail ("quiet: " & Image (E));
   end;

   --  Case 8 is Expect_Dead, applied above after every fatal path.

   --  Case 9: repeated reset and abortive cleanup, fd-accounted.
   declare
      FD_Before : Natural := 0;
      FD_After  : Natural := 0;
      Counting  : constant Boolean := Have_Proc;
   begin
      if Counting then
         FD_Before := Count_Entries ("/proc/self/fd");
      end if;
      for I in 1 .. Cycles loop
         declare
            T : TLS_Transport;
            W : constant String := "cycle" & Integer'Image (I);
         begin
            Connect (T);
            Command (T, 'R');
            case Read_Until_Error (T, W) is
               when Transport => null;
               when None =>
                  Fail (W & ": the reset read as a clean EOF");
               when TLS =>
                  Fail (W & ": the reset surfaced as TLS_Error");
               when Other => null;
            end case;
            if T.Is_Connected then
               Fail (W & ": Is_Connected True after the reset");
            end if;
            Timed_Abortive_Close (T, W);
            Timed_Abortive_Close (T, W & " (second)");
            T.Close;
         exception
            when E : others =>
               Fail (W & ": " & Image (E));
         end;
         exit when Failures > 0;
      end loop;
      if Counting then
         FD_After := Count_Entries ("/proc/self/fd");
         if FD_After /= FD_Before then
            Fail ("cycles: fd count" & FD_Before'Image & " before,"
                  & FD_After'Image & " after" & Cycles'Image
                  & " reset/abortive-close cycles");
         end if;
      else
         Put_Line ("test_tls_reset: SKIP fd count (no /proc)");
      end if;
   end;

   if Failures = 0 then
      Put_Line ("test_tls_reset: OK (reset, half record, close_notify, "
                & "FIN, corrupt tag, Would_Block, rejection, cycles)");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_tls_reset:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_TLS_Reset;
