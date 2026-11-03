--  Copyright (C) 2026 Contributors to AHT
--  SPDX-License-Identifier: Apache-2.0

--  Allocation failure inside the TLS output staging code, both
--  backends. Stage_From_Engine and Push_Output grow Staged and copy it
--  for transmission while holding SSL_Lock; a Storage_Error there
--  used to reach a handler that released Drain_Lock and then called
--  Latch_Engine_Dead, which seizes SSL_Lock: a self-deadlock. The
--  corrected handler marks the engine dead in place and releases
--  what it holds, so the failure is fail-closed instead.
--
--  Mechanism: tests/fault/src/s-memory.adb is linked in place of the
--  run-time's System.Memory, so every Ada allocation in the image
--  passes a one-shot gate. The child arms the gate right before one
--  Try_Write on the deaf fixture (8769), targeting the N-th allocation
--  of 16 KiB or more, which selects among the staging steps for one
--  TLS record: the Staged growth, the secondary-stack chunk for the
--  To_Array copy, and (mbedTLS) the Out_Data queue growth inside the
--  engine's send callback. The parent sweeps N upwards until an
--  ordinal no longer fires, running each child under a watchdog so a
--  deadlock is a reported failure, not a hang; with the original
--  handler every under-lock ordinal trips the watchdog.
--
--  Per fired ordinal the child checks: Try_Write raises; the session
--  is no longer connected; Pending_Output returns (SSL_Lock was
--  released); Try_Write and Try_Flush now refuse with Transport_Error;
--  Abortive_Close is prompt and idempotent, with nothing pending; the
--  transport finalizes at scope exit. Drain_Lock has no public
--  observer once the session is dead, so its release is checked at
--  the source, not here.
--
--  Not covered: the remainder update after a partial send. Staged.Set
--  with a slice of its own previous contents never grows the buffer,
--  so that step cannot raise Storage_Error; the handler covers it by
--  construction (Held is True around it) but no injection reaches it.

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Real_Time; use Ada.Real_Time;
with Ada.Strings.Fixed;
with Ada.Text_IO; use Ada.Text_IO;

with GNAT.OS_Lib;

with System.Memory;

with AHT.Bytes;
with AHT.Transport;
with AHT.Transport.TLS;
with AHT.URL;

procedure Test_TLS_Staging_Fault is

   use AHT.Transport.TLS;

   Deaf_Port : constant AHT.URL.Port_Number := 8769;

   Min_Alloc   : constant := 16_000;  --  what the gate counts, in bytes
   Max_Ordinal : constant := 6;       --  sweep bound; the gate stops
                                      --  firing after a record's few
   Watchdog    : constant Duration := 20.0;
   Call_Bound  : constant Time_Span := Milliseconds (500);

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_tls_staging_fault: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   ---------------------------------------------------------------
   --  The gate in s-memory.adb
   ---------------------------------------------------------------

   procedure Arm (Skip : Integer; Min : System.Memory.size_t)
     with Import, Convention => C, External_Name => "aht_fault_alloc_arm";

   procedure Disarm
     with Import, Convention => C, External_Name => "aht_fault_alloc_disarm";

   function Hit_Size return System.Memory.size_t
     with Import, Convention => C,
          External_Name => "aht_fault_alloc_hit_size";

   function Hit_Ordinal return Integer
     with Import, Convention => C,
          External_Name => "aht_fault_alloc_hit_ordinal";

   ---------------------------------------------------------------
   --  Child: one injected failure, then the post-mortem checks
   ---------------------------------------------------------------

   --  Exit status 0 with a final "CHILD OK" or "CHILD NOFIRE" line;
   --  anything else is a failure the parent reports.
   procedure Child (Ordinal : Positive) is
      Tag    : constant String := "child" & Ordinal'Image & ":";
      T      : TLS_Transport;
      Chunk  : constant AHT.Bytes.Byte_Array (1 .. 16_384) :=
        [others => 16#41#];
      Count  : Natural;
      WS     : Try_Write_Status;
      FS     : Try_Flush_Status;
      Raised : Boolean := False;

      procedure Check_Bound (Started : Time; What : String) is
      begin
         if Clock - Started > Call_Bound then
            Fail (Tag & " " & What & " took "
                  & Duration'Image (To_Duration (Clock - Started)) & " s");
         end if;
      end Check_Bound;
   begin
      T.Connect ("127.0.0.1", Deaf_Port, Insecure => True);

      --  The gate self-disarms on its hit; Disarm covers the no-hit
      --  case so nothing later in this process trips it.
      Arm (Skip => Ordinal - 1, Min => Min_Alloc);
      begin
         T.Try_Write (Chunk, Count, WS);
         Disarm;
      exception
         when E : others =>
            Disarm;
            Raised := True;
            Put_Line (Tag & " Try_Write raised "
                      & Ada.Exceptions.Exception_Name (E) & " — "
                      & Ada.Exceptions.Exception_Message (E));
      end;

      if Hit_Ordinal = 0 then
         --  Nothing of that ordinal: the sweep is over. The write
         --  went through normally; just clean up.
         if Raised then
            Fail (Tag & " raised without an injected failure");
         end if;
         T.Abortive_Close;
         Put_Line ("CHILD NOFIRE");
         return;
      end if;

      Put_Line (Tag & " injected Storage_Error on allocation"
                & Hit_Ordinal'Image & " of" & Hit_Size'Image & " bytes");

      if not Raised then
         Fail (Tag & " Try_Write returned " & WS'Image
               & " despite the injected failure");
      end if;

      --  Fail-closed: the session is unusable, and says so without
      --  waiting on anything.
      if T.Is_Connected then
         Fail (Tag & " Is_Connected after the failure");
      end if;
      declare
         Started : constant Time := Clock;
         Pending : constant Natural := T.Pending_Output;
      begin
         Check_Bound (Started, "Pending_Output");
         Put_Line (Tag & " Pending_Output after the failure:"
                   & Pending'Image);
      end;
      begin
         T.Try_Write (Chunk, Count, WS);
         Fail (Tag & " Try_Write after the failure returned " & WS'Image);
      exception
         when AHT.Transport.Transport_Error => null;  --  expected
         when E : others =>
            Fail (Tag & " Try_Write after the failure raised "
                  & Ada.Exceptions.Exception_Name (E));
      end;
      begin
         T.Try_Flush (FS);
         Fail (Tag & " Try_Flush after the failure returned " & FS'Image);
      exception
         when AHT.Transport.Transport_Error => null;  --  expected
         when E : others =>
            Fail (Tag & " Try_Flush after the failure raised "
                  & Ada.Exceptions.Exception_Name (E));
      end;

      for Pass in 1 .. 2 loop
         declare
            Started : constant Time := Clock;
         begin
            T.Abortive_Close;
            Check_Bound (Started, "Abortive_Close" & Pass'Image);
         exception
            when E : others =>
               Fail (Tag & " Abortive_Close" & Pass'Image & " raised "
                     & Ada.Exceptions.Exception_Name (E) & " — "
                     & Ada.Exceptions.Exception_Message (E));
         end;
      end loop;
      if T.Is_Connected then
         Fail (Tag & " Is_Connected after Abortive_Close");
      end if;
      if T.Pending_Output /= 0 then
         Fail (Tag & " Pending_Output after Abortive_Close:"
               & T.Pending_Output'Image);
      end if;

      if Failures = 0 then
         Put_Line ("CHILD OK");
      end if;
   exception
      when E : others =>
         Disarm;
         Fail (Tag & " " & Ada.Exceptions.Exception_Name (E) & " — "
               & Ada.Exceptions.Exception_Message (E));
   end Child;

   ---------------------------------------------------------------
   --  Parent: one child per ordinal, each under the watchdog
   ---------------------------------------------------------------

   --  Runs this program again as a child for Ordinal and relays its
   --  output. Fired is whether the gate hit; a watchdog expiry (the
   --  deadlock this test is about) or a failing child is a failure.
   procedure Run_Child (Ordinal : Positive; Fired : out Boolean) is
      use GNAT.OS_Lib;

      Self : constant String :=
        Normalize_Pathname (Ada.Command_Line.Command_Name);
      Args : constant Argument_List :=
        [1 => new String'("--child"),
         2 => new String'(Ada.Strings.Fixed.Trim
                            (Ordinal'Image, Ada.Strings.Both))];
      Out_FD     : File_Descriptor;
      Out_Name   : String_Access;
      Pid        : Process_Id;
      Done       : Process_Id;
      Success    : Boolean;
      Timed_Out  : Boolean := False;
      Deadline   : constant Time := Clock + To_Time_Span (Watchdog);
      Saw_OK     : Boolean := False;
      Saw_Nofire : Boolean := False;
   begin
      Fired := False;
      Create_Temp_File (Out_FD, Out_Name);
      if Out_FD = Invalid_FD then
         Fail ("could not create the child's output file");
         return;
      end if;
      Pid := Non_Blocking_Spawn
        (Self, Args, Output_File_Descriptor => Out_FD, Err_To_Out => True);
      Close (Out_FD);
      for A of Args loop
         declare
            P : String_Access := A;
         begin
            Free (P);
         end;
      end loop;
      if Pid = Invalid_Pid then
         Fail ("could not spawn " & Self);
         Delete_File (Out_Name.all, Success);
         Free (Out_Name);
         return;
      end if;

      loop
         Non_Blocking_Wait_Process (Done, Success);
         exit when Done = Pid;
         if Clock > Deadline then
            Kill (Pid, Hard_Kill => True);
            Wait_Process (Done, Success);
            Timed_Out := True;
            exit;
         end if;
         delay 0.05;
      end loop;

      declare
         F : File_Type;
      begin
         Open (F, In_File, Out_Name.all);
         while not End_Of_File (F) loop
            declare
               Line : constant String := Get_Line (F);
            begin
               Put_Line ("  | " & Line);
               if Line = "CHILD OK" then
                  Saw_OK := True;
               elsif Line = "CHILD NOFIRE" then
                  Saw_Nofire := True;
               end if;
            end;
         end loop;
         Close (F);
      exception
         when others =>
            Fail ("could not read the child's output");
      end;
      Delete_File (Out_Name.all, Success);
      Free (Out_Name);

      if Timed_Out then
         Fail ("ordinal" & Ordinal'Image & ": child did not finish within"
               & Duration'Image (Watchdog) & " s (deadlock), killed");
      elsif Saw_Nofire then
         null;
      elsif Saw_OK and then Success then
         Fired := True;
      else
         Fail ("ordinal" & Ordinal'Image & ": child failed");
      end if;
   end Run_Child;

   Fired_Count : Natural := 0;
   Fired       : Boolean;

begin
   if Ada.Command_Line.Argument_Count = 2
     and then Ada.Command_Line.Argument (1) = "--child"
   then
      Child (Positive'Value (Ada.Command_Line.Argument (2)));
      Ada.Command_Line.Set_Exit_Status (if Failures = 0 then 0 else 1);
      return;
   end if;

   for Ordinal in 1 .. Max_Ordinal loop
      Put_Line ("test_tls_staging_fault: ordinal" & Ordinal'Image);
      Run_Child (Ordinal, Fired);
      exit when not Fired;
      Fired_Count := Fired_Count + 1;
   end loop;
   if Fired_Count = 0 and then Failures = 0 then
      Fail ("no allocation of" & Integer'Image (Min_Alloc)
            & " bytes or more happened inside Try_Write; nothing injected");
   end if;

   if Failures = 0 then
      Put_Line ("test_tls_staging_fault: OK ("
                & Ada.Strings.Fixed.Trim (Fired_Count'Image, Ada.Strings.Both)
                & " injected failure(s), each fail-closed)");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_tls_staging_fault:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_TLS_Staging_Fault;
