--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with Ada.Real_Time; use Ada.Real_Time;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Bytes;
with AHT.TLS_Sync;

package body TLS_Sync_Cases is

   use type AHT.TLS_Sync.Epoch_Type;

   function Run (Label : String) return Natural is
      Failures : Natural := 0;

      procedure Fail (Msg : String) is
      begin
         Put_Line (Label & ": FAIL — " & Msg);
         Failures := Failures + 1;
      end Fail;

      Coord   : AHT.TLS_Sync.Coordinator_Type;
      Granted : Boolean;
   begin
      --  A1: the claim is unique; a second claimant arms instead, and
      --  releasing the claim fires the latch.
      Coord.Try_Claim_Or_Arm (Granted);
      if not Granted then
         Fail ("A1: first claim not granted");
      end if;
      Coord.Try_Claim_Or_Arm (Granted);
      if Granted then
         Fail ("A1: second claim granted while held");
      end if;
      Coord.Release_Feeder;
      select
         Coord.Await_Wakeup;
      else
         Fail ("A1: latch not fired by Release_Feeder");
      end select;

      --  A2: Bump_Abort wakes a parked waiter, and the woken task can
      --  see the epoch changed. The claim is taken BEFORE the waiter
      --  task activates, so the waiter deterministically arms.
      Coord.Try_Claim_Or_Arm (Granted);
      if not Granted then
         Fail ("A2: main could not take the claim");
      end if;
      declare
         Epoch0 : constant AHT.TLS_Sync.Epoch_Type := Coord.Abort_Epoch;
         Woke   : Boolean := False with Volatile;
         Timed  : Boolean := False with Volatile;

         task Waiter;
         task body Waiter is
            G : Boolean;
         begin
            Coord.Try_Claim_Or_Arm (G);   --  main holds it: arms
            if G then
               Coord.Release_Feeder;      --  cannot happen; A2 fails
               Timed := True;
            else
               select
                  Coord.Await_Wakeup;
                  Woke := True;
               or
                  delay 5.0;
                  Coord.Disarm;
                  Timed := True;
               end select;
            end if;
         end Waiter;
      begin
         delay 0.2;                       --  let Waiter park
         Coord.Bump_Abort;
         while not (Woke or Timed) loop   --  join via flags
            delay 0.01;
         end loop;
         if not Woke then
            Fail ("A2: abort did not wake the parked waiter");
         end if;
         if Coord.Abort_Epoch = Epoch0 then
            Fail ("A2: abort epoch unchanged after Bump_Abort");
         end if;
         Coord.Release_Feeder;
      end;

      --  A3: a parked waiter that nobody signals must hit its own
      --  deadline.
      Coord.Try_Claim_Or_Arm (Granted);
      if not Granted then
         Fail ("A3: main could not take the claim");
      end if;
      declare
         Timed : Boolean := False with Volatile;

         task Sleeper;
         task body Sleeper is
            G : Boolean;
         begin
            Coord.Try_Claim_Or_Arm (G);
            if G then
               Coord.Release_Feeder;      --  cannot happen; A3 fails
            else
               select
                  Coord.Await_Wakeup;
               or
                  delay until Clock + To_Time_Span (0.3);
                  Coord.Disarm;
                  Timed := True;
               end select;
            end if;
         end Sleeper;
      begin
         delay 1.0;                       --  past the 0.3 s bound
         if not Timed then
            Fail ("A3: parked waiter did not time out");
         end if;
         Coord.Release_Feeder;
      end;

      --  A4: the wake path the engines depend on: a writer
      --  parked while the reader owns the claim is released by the
      --  reader's Release_Feeder and can then claim the socket itself.
      Coord.Try_Claim_Or_Arm (Granted);
      if not Granted then
         Fail ("A4: main could not take the claim");
      end if;
      declare
         Claimed : Boolean := False with Volatile;
         Failed  : Boolean := False with Volatile;

         task Follower;
         task body Follower is
            G : Boolean;
         begin
            Coord.Try_Claim_Or_Arm (G);
            if G then
               Coord.Release_Feeder;      --  cannot happen; A4 fails
               Failed := True;
            else
               select
                  Coord.Await_Wakeup;
                  Coord.Try_Claim_Or_Arm (G);
                  if G then
                     Claimed := True;
                     Coord.Release_Feeder;
                  else
                     Failed := True;
                  end if;
               or
                  delay 5.0;
                  Coord.Disarm;
                  Failed := True;
               end select;
            end if;
         end Follower;
      begin
         delay 0.2;                       --  let Follower park
         Coord.Release_Feeder;            --  hand the socket over
         while not (Claimed or Failed) loop
            delay 0.01;
         end loop;
         if not Claimed then
            Fail ("A4: waiter woken by Release_Feeder could not claim");
         end if;
      end;

      --  A5: the reset latch records the reset only when it is what
      --  makes the session fatal, and nothing later changes the answer.
      declare
         First, After_Fatal, Never : AHT.TLS_Sync.Coordinator_Type;
      begin
         if First.Reset or else First.Fatal then
            Fail ("A5: a fresh coordinator reports a failure");
         end if;
         First.Latch_Reset;
         if not (First.Reset and then First.Fatal) then
            Fail ("A5: Latch_Reset on a healthy session not recorded");
         end if;
         First.Latch_Fatal;
         First.Latch_EOF;
         if not First.Reset then
            Fail ("A5: a later latch cleared the reset");
         end if;

         After_Fatal.Latch_Fatal;
         After_Fatal.Latch_Reset;
         if After_Fatal.Reset then
            Fail ("A5: Latch_Reset after another failure recorded a "
                  & "reset");
         end if;
         if not After_Fatal.Fatal then
            Fail ("A5: Fatal lost");
         end if;

         Never.Latch_Fatal;
         Never.Latch_EOF;
         Never.Bump_Abort;
         if Never.Reset then
            Fail ("A5: a latch other than Latch_Reset recorded a reset");
         end if;
      end;

      --  A5 (wake): Latch_Reset wakes a parked waiter, as Latch_Fatal
      --  does.
      declare
         Waking : AHT.TLS_Sync.Coordinator_Type;
         G      : Boolean;
      begin
         Waking.Try_Claim_Or_Arm (G);
         Waking.Try_Claim_Or_Arm (G);     --  held: arms
         Waking.Latch_Reset;
         select
            Waking.Await_Wakeup;
         else
            Fail ("A5: latch not fired by Latch_Reset");
         end select;
      end;

      --  A6: the record tracker is at a boundary exactly when no
      --  header and no body is partly received, however the bytes are
      --  split across receives.
      declare
         use AHT.Bytes;
         --  A 3-byte record, an empty record, then a 300-byte one.
         Stream : constant Byte_Array :=
           Byte_Array'(16#17#, 3, 3, 0, 3, 1, 2, 3)
           & Byte_Array'(16#17#, 3, 3, 0, 0)
           & Byte_Array'(16#17#, 3, 3, 1, 44)
           & Byte_Array'(1 .. 300 => 9);
         Ends   : constant array (1 .. 3) of Positive := [8, 13, 318];

         function Is_End (N : Natural) return Boolean is
           (N = 0 or else (for some E of Ends => E = N));

         Whole : AHT.TLS_Sync.Record_Tracker;
      begin
         if not AHT.TLS_Sync.At_Boundary (Whole) then
            Fail ("A6: a fresh tracker is not at a boundary");
         end if;
         AHT.TLS_Sync.Note (Whole, Stream (1 .. 0));
         if not AHT.TLS_Sync.At_Boundary (Whole) then
            Fail ("A6: an empty receive moved the tracker");
         end if;

         --  Byte by byte: every prefix length is checked.
         declare
            T : AHT.TLS_Sync.Record_Tracker;
         begin
            for I in Stream'Range loop
               AHT.TLS_Sync.Note (T, Stream (I .. I));
               if AHT.TLS_Sync.At_Boundary (T) /= Is_End (I) then
                  Fail ("A6: wrong boundary answer after" & I'Image
                        & " byte(s), fed singly");
               end if;
            end loop;
         end;

         --  Every two-piece split of the stream.
         for Cut in 0 .. Stream'Last loop
            declare
               T : AHT.TLS_Sync.Record_Tracker;
            begin
               AHT.TLS_Sync.Note (T, Stream (1 .. Cut));
               if AHT.TLS_Sync.At_Boundary (T) /= Is_End (Cut) then
                  Fail ("A6: wrong boundary answer after a first piece "
                        & "of" & Cut'Image & " byte(s)");
               end if;
               AHT.TLS_Sync.Note (T, Stream (Cut + 1 .. Stream'Last));
               if not AHT.TLS_Sync.At_Boundary (T) then
                  Fail ("A6: not at a boundary after the whole stream, "
                        & "cut at" & Cut'Image);
               end if;
            end;
         end loop;
      end;

      return Failures;
   end Run;

end TLS_Sync_Cases;
