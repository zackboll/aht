--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

package body AHT.TLS_Sync is

   protected body Lock_Type is
      entry Seize when not Locked is
      begin
         Locked := True;
      end Seize;
      procedure Release is
      begin
         Locked := False;
      end Release;
   end Lock_Type;

   protected body Coordinator_Type is

      procedure Try_Claim_Or_Arm (Granted : out Boolean) is
      begin
         if not Feeder_Claimed then
            Feeder_Claimed := True;
            Granted := True;
         else
            Granted := False;
            Armed   := True;
            --  An event that already happened opens the barrier now.
            if Is_EOF or Is_Fatal then
               Fired := True;
            end if;
         end if;
      end Try_Claim_Or_Arm;

      procedure Release_Feeder is
      begin
         Feeder_Claimed := False;
         if Armed then
            Fired := True;
         end if;
      end Release_Feeder;

      entry Await_Wakeup when Fired is
      begin
         Armed := False;
         Fired := False;
      end Await_Wakeup;

      procedure Disarm is
      begin
         Armed := False;
         Fired := False;
      end Disarm;

      procedure Latch_EOF is
      begin
         Is_EOF := True;
         if Armed then
            Fired := True;
         end if;
      end Latch_EOF;

      procedure Latch_Fatal is
      begin
         Is_Fatal := True;
         if Armed then
            Fired := True;
         end if;
      end Latch_Fatal;

      procedure Latch_Reset is
      begin
         if not Is_Fatal then
            Is_Reset := True;
         end if;
         Is_Fatal := True;
         if Armed then
            Fired := True;
         end if;
      end Latch_Reset;

      function EOF return Boolean is (Is_EOF);
      function Fatal return Boolean is (Is_Fatal);
      function Reset return Boolean is (Is_Reset);

      procedure Bump_Abort is
      begin
         Epoch := Epoch + 1;
         if Armed then
            Fired := True;
         end if;
      end Bump_Abort;

      function Abort_Epoch return Epoch_Type is (Epoch);

   end Coordinator_Type;

   procedure Note
     (Tracker : in out Record_Tracker;
      Data    : AHT.Bytes.Byte_Array)
   is
      Pos : Natural := Data'First;
   begin
      while Pos <= Data'Last loop
         if Tracker.Body_Left > 0 then
            declare
               Take : constant Natural :=
                 Natural'Min (Tracker.Body_Left, Data'Last - Pos + 1);
            begin
               Tracker.Body_Left := Tracker.Body_Left - Take;
               Pos := Pos + Take;
            end;
         elsif Tracker.Header_Got = 4 then
            --  The fifth header byte completes the length. A
            --  zero-length record ends here.
            Tracker.Body_Left :=
              Natural (Tracker.Length_Hi) * 256 + Natural (Data (Pos));
            Tracker.Header_Got := 0;
            Pos := Pos + 1;
         else
            if Tracker.Header_Got = 3 then
               Tracker.Length_Hi := Data (Pos);
            end if;
            Tracker.Header_Got := Tracker.Header_Got + 1;
            Pos := Pos + 1;
         end if;
      end loop;
   end Note;

   function At_Boundary (Tracker : Record_Tracker) return Boolean is
     (Tracker.Header_Got = 0 and then Tracker.Body_Left = 0);

end AHT.TLS_Sync;
