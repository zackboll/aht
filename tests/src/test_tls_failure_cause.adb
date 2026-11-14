--  Copyright (C) 2026 Contributors to AHT
--  SPDX-License-Identifier: Apache-2.0

--  AHT.Transport.TLS.Last_Failure, both backends, against
--  tests/server/server_tls_reset.py (127.0.0.1:8781, and 8782 under a
--  certificate issued to another name), the corrupted-record fixture
--  (8773) and the deaf fixture (8769). Every reset is a real RST from
--  a real socket (SO_LINGER 0); every expectation is on the typed
--  cause, Is_Connected and the status or exception identity of the
--  call, never on an exception message.
--
--  Cases:
--    A. established session, then the reset, seen by Read and by
--       Try_Read: Transport_Error and Network_Reset. No_Failure
--       before it. The cause survives the rejected operations that
--       follow, two Abortive_Close calls and a Close.
--    B. a reset that cuts a record short is Other_Failure: half a
--       record then the reset, and a whole record with half of the
--       next in one send, the whole one read first, then the reset
--    C. close_notify: Last = 0 / Peer_Closed, No_Failure, also after
--       Close. A reset that follows a close_notify is never
--       Network_Reset: Try_Read keeps reporting Peer_Closed, and a
--       further Read either repeats Last = 0 (openssl, No_Failure) or
--       runs into the reset (mbedtls, Other_Failure)
--    D. FIN without close_notify: never Network_Reset. Try_Read
--       raises TLS_Error and reports Other_Failure on both backends;
--       Read keeps its backend policy (TLS_Error and Other_Failure on
--       openssl, Last = 0 and No_Failure on mbedtls)
--    E. corrupted authentication tag: TLS_Error, Other_Failure
--    F. verification failures end Connect with TLS_Error and leave
--       No_Failure and no session: an untrusted chain, and a trusted
--       certificate issued to another name. The control is the same
--       shape with the right name (8781 trusting its own
--       certificate), which connects.
--    G. a read deadline and an abort end the operation, not the
--       session: No_Failure, still connected, still echoing. A write
--       deadline that fires mid-record poisons, and is Other_Failure.
--       A reset discovered by a send, with nothing read, is
--       Other_Failure: only a failed receive carries the proof.
--       A receive that fails with an error other than a reset, on a
--       healthy session at a record boundary, is Other_Failure
--       (Socket_Fault swaps the socket for /dev/null; POSIX only,
--       skipped and reported elsewhere).
--    H. after every fatal case Read, Try_Read, Write, Try_Write and
--       Try_Flush are refused and the cause is what it was
--    I. fifty reset, Abortive_Close, Abortive_Close, Close cycles:
--       Network_Reset each time, and the fd count ends where it
--       started (Linux /proc/self/fd; elsewhere the count is skipped
--       and reported)
--
--  Does not cover:
--    - case B's second premise by observation: that the half record
--      was received with the whole one rests on the fixture sending
--      both in one send, and on the case failing when the
--      record-boundary condition is removed from Fail_Input
--    - unprocessed whole records in the engine's input queue when a
--      reset arrives: it takes the writer feeding between the
--      reader's engine call and its socket read, which traffic cannot
--      force. That condition in Fail_Input rests on its own argument.
--    - a reset during the handshake: Connect fails, there is no
--      session, and Last_Failure stays No_Failure by construction
--    - a blocking Write after Abort_Pending interrupted a Read: it
--      takes the abort left on the write selector, which is the
--      inner TCP's behaviour and not a cause this test classifies

with Ada.Command_Line;
with Ada.Directories;
with Ada.Exceptions;
with Ada.Real_Time; use Ada.Real_Time;
with Ada.Text_IO; use Ada.Text_IO;
with Ada.Unchecked_Deallocation;

with GNAT.Directory_Operations;

with AHT.Bytes;
with AHT.Transport;
with AHT.Transport.TLS;
with AHT.URL;

with Socket_Fault;

procedure Test_TLS_Failure_Cause is

   use AHT.Transport.TLS;

   Reset_Port      : constant AHT.URL.Port_Number := 8781;
   Wrong_Name_Port : constant AHT.URL.Port_Number := 8782;
   Corrupt_Port    : constant AHT.URL.Port_Number := 8773;
   Deaf_Port       : constant AHT.URL.Port_Number := 8769;

   CA_File       : constant String := "tests/server/certs/server.crt";
   Wrong_CA_File : constant String := "tests/server/certs/wrongname.crt";

   Banner : constant String := "RESET-FIXTURE-BANNER";

   Call_Bound : constant Time_Span := Milliseconds (500);
   Patience   : constant Duration := 10.0;
   Poll_Gap   : constant Duration := 0.005;
   Cycles     : constant := 50;

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_tls_failure_cause: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   function Image (E : Ada.Exceptions.Exception_Occurrence) return String
   is (Ada.Exceptions.Exception_Name (E));

   procedure Expect_Cause
     (T : TLS_Transport; Want : Failure_Cause; Where : String) is
   begin
      if T.Last_Failure /= Want then
         Fail (Where & ": Last_Failure is " & T.Last_Failure'Image
               & ", expected " & Want'Image);
      end if;
   end Expect_Cause;

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

   --  Poll Try_Read until it reports something other than Would_Block
   --  or Patience runs out (then Timed_Out). Exceptions propagate.
   procedure Poll (T : in out TLS_Transport; Timed_Out : out Boolean) is
      Give_Up : constant Time := Clock + To_Time_Span (Patience);
   begin
      Timed_Out := False;
      loop
         T.Try_Read (Buf, Last, Status);
         exit when Status /= Would_Block;
         if Clock > Give_Up then
            Timed_Out := True;
            exit;
         end if;
         delay Poll_Gap;
      end loop;
   end Poll;

   --  One echo round trip through the blocking Read: the session is
   --  established, authenticated and usable at this point.
   procedure Echo (T : in out TLS_Transport; Where : String) is
   begin
      Command (T, 'E');
      T.Read (Buf, Last);
      if AHT.Bytes.To_String (Buf (1 .. Last)) /= Banner then
         Fail (Where & ": echo returned" & Last'Image & " byte(s), not "
               & "the banner");
      end if;
   end Echo;

   type Outcome is (Clean_End, Transport, TLS, Other);

   --  Drive a blocking Read to whatever ends the session.
   function Read_To_End
     (T : in out TLS_Transport; Where : String) return Outcome is
   begin
      loop
         T.Read (Buf, Last);
         if Last = 0 then
            return Clean_End;
         end if;
      end loop;
   exception
      when AHT.Transport.Transport_Error => return Transport;
      when TLS_Error => return TLS;
      when E : others =>
         Fail (Where & ": unexpected " & Image (E));
         return Other;
   end Read_To_End;

   --  The same through Try_Read.
   function Poll_To_End
     (T : in out TLS_Transport; Where : String) return Outcome
   is
      Timed_Out : Boolean;
   begin
      loop
         Poll (T, Timed_Out);
         if Timed_Out then
            Fail (Where & ": nothing ended the session within Patience");
            return Other;
         end if;
         if Status = Peer_Closed then
            return Clean_End;
         end if;
      end loop;
   exception
      when AHT.Transport.Transport_Error => return Transport;
      when TLS_Error => return TLS;
      when E : others =>
         Fail (Where & ": unexpected " & Image (E));
         return Other;
   end Poll_To_End;

   procedure Expect_Outcome (Got, Want : Outcome; Where : String) is
   begin
      if Got /= Want and then Got /= Other then
         Fail (Where & ": session ended as " & Got'Image
               & ", expected " & Want'Image);
      end if;
   end Expect_Outcome;

   --  Case H. A dead session refuses every operation, by the entry
   --  guard or the engine's dead flag (either is a rejection), and
   --  none of the refusals changes the cause.
   procedure Expect_Dead
     (T : in out TLS_Transport; Cause : Failure_Cause; Where : String)
   is
      Count   : Natural;
      WS      : Try_Write_Status;
      FS      : Try_Flush_Status;
      Started : Time;

      procedure Refused (Op : String; Returned : Boolean) is
      begin
         if Returned then
            Fail (Where & ": " & Op & " returned on a dead session");
         end if;
         if Clock - Started > Call_Bound then
            Fail (Where & ": " & Op & " waited on a dead session");
         end if;
         Expect_Cause (T, Cause, Where & " after " & Op);
      end Refused;
   begin
      if T.Is_Connected then
         Fail (Where & ": Is_Connected True after the fatal error");
      end if;
      Expect_Cause (T, Cause, Where);

      Started := Clock;
      begin
         T.Read (Buf, Last);
         Refused ("Read", True);
      exception
         when AHT.Transport.Transport_Error | TLS_Error =>
            Refused ("Read", False);
      end;
      Started := Clock;
      begin
         T.Try_Read (Buf, Last, Status);
         Refused ("Try_Read", True);
      exception
         when AHT.Transport.Transport_Error | TLS_Error =>
            Refused ("Try_Read", False);
      end;
      Started := Clock;
      begin
         T.Write (AHT.Bytes.From_String ("E"));
         Refused ("Write", True);
      exception
         when AHT.Transport.Transport_Error | TLS_Error =>
            Refused ("Write", False);
      end;
      Started := Clock;
      begin
         T.Try_Write (AHT.Bytes.From_String ("E"), Count, WS);
         Refused ("Try_Write", True);
      exception
         when AHT.Transport.Transport_Error | TLS_Error =>
            Refused ("Try_Write", False);
      end;
      Started := Clock;
      begin
         T.Try_Flush (FS);
         Refused ("Try_Flush", True);
      exception
         when AHT.Transport.Transport_Error | TLS_Error =>
            Refused ("Try_Flush", False);
      end;
   exception
      when E : others =>
         Fail (Where & ": a refused operation raised " & Image (E));
   end Expect_Dead;

   --  Release twice abortively, then Close: the cause outlives the
   --  session state it was read from.
   procedure Release
     (T : in out TLS_Transport; Cause : Failure_Cause; Where : String)
   is
      Started : constant Time := Clock;
   begin
      T.Abortive_Close;
      Expect_Cause (T, Cause, Where & " after Abortive_Close");
      T.Abortive_Close;
      Expect_Cause (T, Cause, Where & " after a second Abortive_Close");
      T.Close;
      Expect_Cause (T, Cause, Where & " after Close");
      if Clock - Started > Call_Bound then
         Fail (Where & ": releasing the session waited");
      end if;
      if T.Is_Connected then
         Fail (Where & ": Is_Connected after release");
      end if;
   exception
      when E : others =>
         Fail (Where & ": release raised " & Image (E));
   end Release;

   function Count_Entries (Path : String) return Natural is
      use GNAT.Directory_Operations;
      Dir  : Dir_Type;
      Name : String (1 .. 256);
      Got  : Natural;
      N    : Natural := 0;
   begin
      Open (Dir, Path);
      loop
         Read (Dir, Name, Got);
         exit when Got = 0;
         if Name (1 .. Got) /= "." and then Name (1 .. Got) /= ".." then
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

   type Reader is (Via_Read, Via_Try_Read);

   function End_Of
     (T : in out TLS_Transport; How : Reader; Where : String)
      return Outcome
   is (case How is
          when Via_Read     => Read_To_End (T, Where),
          when Via_Try_Read => Poll_To_End (T, Where));

begin
   --  A never-connected object has no failure.
   declare
      T : TLS_Transport;
   begin
      Expect_Cause (T, No_Failure, "fresh");
      T.Abortive_Close;
      Expect_Cause (T, No_Failure, "fresh after Abortive_Close");
   end;

   --  Case A: established session, then the reset.
   for How in Reader loop
      declare
         T : TLS_Transport;
         W : constant String := "A/" & How'Image;
      begin
         Connect (T);
         Echo (T, W);
         Expect_Cause (T, No_Failure, W & " while established");
         Command (T, 'R');
         Expect_Outcome (End_Of (T, How, W), Transport, W);
         Expect_Dead (T, Network_Reset, W);
         Release (T, Network_Reset, W);
      exception
         when E : others =>
            Fail (W & ": " & Image (E));
      end;
   end loop;

   --  Case B: a reset that cuts a record short is not the proven
   --  interruption; part of a record is in the engine, unjudged.
   for How in Reader loop
      declare
         T : TLS_Transport;
         W : constant String := "B/half/" & How'Image;
      begin
         Connect (T);
         Command (T, 'H');
         Expect_Outcome (End_Of (T, How, W), Transport, W);
         Expect_Dead (T, Other_Failure, W);
         Release (T, Other_Failure, W);
      exception
         when E : others =>
            Fail (W & ": " & Image (E));
      end;

      --  The whole record is read first, so the engine is back to
      --  wanting input with half a record already inside it.
      declare
         T : TLS_Transport;
         W : constant String := "B/after-record/" & How'Image;
      begin
         Connect (T);
         Command (T, 'P');
         T.Read (Buf, Last);
         if AHT.Bytes.To_String (Buf (1 .. Last)) /= Banner then
            Fail (W & ": the whole record was not delivered first");
         end if;
         Expect_Cause (T, No_Failure, W & " with half a record held");
         Command (T, 'R');
         Expect_Outcome (End_Of (T, How, W), Transport, W);
         Expect_Dead (T, Other_Failure, W);
         Release (T, Other_Failure, W);
      exception
         when E : others =>
            Fail (W & ": " & Image (E));
      end;
   end loop;

   --  Case C: close_notify is a clean, authenticated end.
   for How in Reader loop
      declare
         T : TLS_Transport;
         W : constant String := "C/" & How'Image;
      begin
         Connect (T);
         Command (T, 'C');
         Expect_Outcome (End_Of (T, How, W), Clean_End, W);
         if not T.Is_Connected then
            Fail (W & ": Is_Connected False after close_notify");
         end if;
         T.Try_Read (Buf, Last, Status);
         if Status /= Peer_Closed then
            Fail (W & ": Try_Read after close_notify gave "
                  & Status'Image);
         end if;
         Expect_Cause (T, No_Failure, W);
         T.Close;
         Expect_Cause (T, No_Failure, W & " after Close");
      exception
         when E : others =>
            Fail (W & ": " & Image (E));
      end;
   end loop;

   --  Case C: close_notify, then a reset. The close was authenticated
   --  and seen first; whatever a later read meets, it is not a proven
   --  interruption of a healthy session.
   declare
      T : TLS_Transport;
      W : constant String := "C/then-reset";
   begin
      Connect (T);
      Command (T, 'N');
      T.Read (Buf, Last);
      if Last /= 0 then
         Fail (W & ": close_notify not delivered first, Last ="
               & Last'Image);
      end if;
      Expect_Cause (T, No_Failure, W & " after close_notify");
      T.Try_Read (Buf, Last, Status);
      if Status /= Peer_Closed then
         Fail (W & ": Try_Read after close_notify gave " & Status'Image);
      end if;
      Expect_Cause (T, No_Failure, W & " after Try_Read");
      begin
         T.Read (Buf, Last);
         if Last /= 0 then
            Fail (W & ": a second Read returned data");
         end if;
         Expect_Cause (T, No_Failure, W & " after a second clean Read");
      exception
         when AHT.Transport.Transport_Error | TLS_Error =>
            Expect_Cause (T, Other_Failure, W & " after the reset");
      end;
      Release (T, T.Last_Failure, W);
   exception
      when E : others =>
         Fail (W & ": " & Image (E));
   end;

   --  Case D: FIN without close_notify. Try_Read fails closed on both
   --  backends; Read keeps the backend's policy. Neither is a reset.
   declare
      T : TLS_Transport;
   begin
      Connect (T);
      Command (T, 'F');
      Expect_Outcome (Poll_To_End (T, "D/try"), TLS, "D/try");
      Expect_Dead (T, Other_Failure, "D/try");
      Release (T, Other_Failure, "D/try");
   exception
      when E : others =>
         Fail ("D/try: " & Image (E));
   end;
   declare
      T : TLS_Transport;
   begin
      Connect (T);
      Command (T, 'F');
      case Read_To_End (T, "D/read") is
         when TLS =>
            Expect_Dead (T, Other_Failure, "D/read");
            Release (T, Other_Failure, "D/read");
         when Clean_End =>
            Expect_Cause (T, No_Failure, "D/read");
            Release (T, No_Failure, "D/read");
         when Transport =>
            Fail ("D/read: the FIN surfaced as Transport_Error");
         when Other =>
            null;
      end case;
   exception
      when E : others =>
         Fail ("D/read: " & Image (E));
   end;

   --  Case E: a record that fails authentication.
   for How in Reader loop
      declare
         T : TLS_Transport;
         W : constant String := "E/" & How'Image;
      begin
         T.Connect ("127.0.0.1", Corrupt_Port, Insecure => True);
         T.Set_Read_Deadline (Patience);
         Expect_Outcome (End_Of (T, How, W), TLS, W);
         Expect_Dead (T, Other_Failure, W);
         Release (T, Other_Failure, W);
      exception
         when E : others =>
            Fail (W & ": " & Image (E));
      end;
   end loop;

   --  Case F: verification failures end Connect; no session, no cause.
   declare
      procedure Rejected
        (Port : AHT.URL.Port_Number; CA : String; Where : String)
      is
         T : TLS_Transport;
      begin
         begin
            T.Connect ("127.0.0.1", Port, Insecure => False,
                       CA_Path => CA, Handshake_Deadline => Patience);
            Fail (Where & ": Connect succeeded");
         exception
            when TLS_Error => null;
            when E : others =>
               Fail (Where & ": Connect raised " & Image (E)
                     & ", expected TLS_Error");
         end;
         if T.Is_Connected then
            Fail (Where & ": Is_Connected after a rejected Connect");
         end if;
         Expect_Cause (T, No_Failure, Where);
         T.Abortive_Close;
         Expect_Cause (T, No_Failure, Where & " after Abortive_Close");
      end Rejected;
   begin
      --  The right name, a chain the client does not trust.
      Rejected (Reset_Port, Wrong_CA_File, "F/untrusted");
      --  A chain the client trusts, issued to another name.
      Rejected (Wrong_Name_Port, Wrong_CA_File, "F/hostname");

      --  Control: trusted and issued to this name.
      declare
         T : TLS_Transport;
      begin
         T.Connect ("127.0.0.1", Reset_Port, Insecure => False,
                    CA_Path => CA_File, Handshake_Deadline => Patience);
         T.Set_Read_Deadline (Patience);
         Echo (T, "F/control");
         Expect_Cause (T, No_Failure, "F/control");
         Command (T, 'C');
         T.Close;
      exception
         when E : others =>
            Fail ("F/control: " & Image (E));
      end;
   end;

   --  Case G: a read deadline ends the operation only.
   declare
      T : TLS_Transport;
   begin
      Connect (T);
      Echo (T, "G/deadline");
      T.Set_Read_Deadline (0.3);
      begin
         T.Read (Buf, Last);
         Fail ("G/deadline: Read returned on a silent peer");
      exception
         when AHT.Transport.Timeout_Error => null;
      end;
      Expect_Cause (T, No_Failure, "G/deadline");
      if not T.Is_Connected then
         Fail ("G/deadline: Is_Connected False after a read deadline");
      end if;
      T.Set_Read_Deadline (Patience);
      Echo (T, "G/deadline after");
      Command (T, 'C');
      T.Close;
      Expect_Cause (T, No_Failure, "G/deadline after Close");
   exception
      when E : others =>
         Fail ("G/deadline: " & Image (E));
   end;

   --  Case G: an abort ends the operation only. One Abort_Pending:
   --  the selector keeps an abort that arrives before the reader
   --  parks, so the single call lands either way, and a second would
   --  be left queued for the echo that follows. Aborted_Error is the
   --  observation; the read deadline is only the backstop.
   declare
      T       : TLS_Transport;
      Aborted : Boolean := False;
   begin
      Connect (T);
      Echo (T, "G/abort");
      declare
         task Aborter;
         task body Aborter is
         begin
            delay 0.2;
            T.Abort_Pending;
         end Aborter;
      begin
         T.Read (Buf, Last);
         Fail ("G/abort: Read returned on a silent peer");
      exception
         when AHT.Transport.Aborted_Error =>
            Aborted := True;
         when E : others =>
            Fail ("G/abort: Read raised " & Image (E));
      end;
      if Aborted then
         Expect_Cause (T, No_Failure, "G/abort");
         if not T.Is_Connected then
            Fail ("G/abort: Is_Connected False after an abort");
         end if;
         --  The session still serves an echo. Through the
         --  nonblocking calls: Abort_Pending aborts both of the inner
         --  TCP's selectors, and the one the reader did not consume
         --  is taken by the next blocking Write.
         declare
            Count     : Natural;
            WS        : Try_Write_Status;
            Timed_Out : Boolean;
         begin
            T.Try_Write (AHT.Bytes.From_String ("E"), Count, WS);
            if WS /= Accepted or else Count /= 1 then
               Fail ("G/abort: Try_Write after the abort gave "
                     & WS'Image & Count'Image);
            end if;
            Poll (T, Timed_Out);
            if Timed_Out
              or else Status /= Data_Ready
              or else AHT.Bytes.To_String (Buf (1 .. Last)) /= Banner
            then
               Fail ("G/abort: no echo after the abort");
            end if;
         end;
         Expect_Cause (T, No_Failure, "G/abort after the echo");
      end if;
      T.Abortive_Close;
      Expect_Cause (T, No_Failure, "G/abort after Abortive_Close");
   exception
      when E : others =>
         Fail ("G/abort: " & Image (E));
   end;

   --  Case G: a write deadline that fires mid-record poisons, and is
   --  not a reset.
   declare
      type Bytes_Access is access AHT.Bytes.Byte_Array;
      procedure Free is new Ada.Unchecked_Deallocation
        (AHT.Bytes.Byte_Array, Bytes_Access);
      Big : Bytes_Access :=
        new AHT.Bytes.Byte_Array'(1 .. 4 * 1024 * 1024 => 65);
      T   : TLS_Transport;
   begin
      T.Connect ("127.0.0.1", Deaf_Port, Insecure => True,
                 Handshake_Deadline => Patience);
      T.Set_Write_Deadline (1.0);
      begin
         T.Write (Big.all);
         Fail ("G/write-deadline: Write returned against a deaf peer");
      exception
         when AHT.Transport.Timeout_Error => null;
      end;
      Free (Big);
      Expect_Dead (T, Other_Failure, "G/write-deadline");
      Release (T, Other_Failure, "G/write-deadline");
   exception
      when E : others =>
         Free (Big);
         Fail ("G/write-deadline: " & Image (E));
   end;

   --  Case G: a reset found by a send, nothing read since. Writes
   --  repeat until the reset has arrived and one fails.
   declare
      T       : TLS_Transport;
      Give_Up : Time;
      Failed  : Boolean := False;
   begin
      Connect (T);
      Echo (T, "G/send-reset");
      Command (T, 'R');
      Give_Up := Clock + To_Time_Span (Patience);
      T.Set_Write_Deadline (Patience);
      while not Failed and then Clock < Give_Up loop
         begin
            T.Write (AHT.Bytes.From_String ("E"));
            delay Poll_Gap;
         exception
            when AHT.Transport.Transport_Error | TLS_Error =>
               Failed := True;
         end;
      end loop;
      if Failed then
         Expect_Dead (T, Other_Failure, "G/send-reset");
      else
         Fail ("G/send-reset: no Write failed within Patience");
      end if;
      Release (T, T.Last_Failure, "G/send-reset");
   exception
      when E : others =>
         Fail ("G/send-reset: " & Image (E));
   end;

   --  Case G: a receive that fails, but not with a reset. Everything
   --  else Network_Reset requires holds here: the session is healthy,
   --  at a record boundary, with nothing unprocessed.
   if Socket_Fault.Supported then
      for How in Reader loop
         declare
            T : TLS_Transport;
            W : constant String := "G/other-receive-error/" & How'Image;
         begin
            Connect (T);
            Echo (T, W);
            if not Socket_Fault.Break_Socket_To (Natural (Reset_Port)) then
               Fail (W & ": could not replace the session's socket");
            else
               Expect_Outcome (End_Of (T, How, W), Transport, W);
               Expect_Dead (T, Other_Failure, W);
            end if;
            Release (T, T.Last_Failure, W);
         exception
            when E : others =>
               Fail (W & ": " & Image (E));
         end;
      end loop;
   else
      Put_Line ("test_tls_failure_cause: SKIP non-reset receive error "
                & "(sockets are not file descriptors here)");
   end if;

   --  Case I: repeated reset and release, fd-accounted.
   declare
      Counting  : constant Boolean := Have_Proc;
      FD_Before : Natural := 0;
      FD_After  : Natural := 0;
   begin
      if Counting then
         FD_Before := Count_Entries ("/proc/self/fd");
      end if;
      for I in 1 .. Cycles loop
         declare
            T : TLS_Transport;
            W : constant String := "I/cycle" & Integer'Image (I);
         begin
            Connect (T);
            Command (T, 'R');
            Expect_Outcome (Read_To_End (T, W), Transport, W);
            Expect_Cause (T, Network_Reset, W);
            Release (T, Network_Reset, W);
         exception
            when E : others =>
               Fail (W & ": " & Image (E));
         end;
         exit when Failures > 0;
      end loop;
      if Counting then
         FD_After := Count_Entries ("/proc/self/fd");
         if FD_After /= FD_Before then
            Fail ("I: fd count" & FD_Before'Image & " before,"
                  & FD_After'Image & " after" & Cycles'Image & " cycles");
         end if;
      else
         Put_Line ("test_tls_failure_cause: SKIP fd count (no /proc)");
      end if;
   end;

   if Failures = 0 then
      Put_Line ("test_tls_failure_cause: OK (reset, cut record, "
                & "close_notify, FIN, corrupt tag, verification, "
                & "deadline, abort, send reset, rejection, cycles)");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_tls_failure_cause:" & Failures'Image
                & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_TLS_Failure_Cause;
