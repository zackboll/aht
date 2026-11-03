--  Copyright (C) 2026 Contributors to AHT
--  SPDX-License-Identifier: Apache-2.0

--  Test-only body for GNAT's System.Memory, the unit behind
--  __gnat_malloc/__gnat_realloc/__gnat_free, written against the
--  interface its spec documents as stable and replaceable. Linked into
--  the fault-injection test alone (tests/fault/fault.gpr; the suite in
--  tests/tests.gpr keeps the runtime's body). malloc/realloc/free
--  behind a one-shot gate: once armed, the first allocation of at
--  least Min_Size bytes after Skip qualifying ones raises
--  Storage_Error, as heap exhaustion would, and the gate disarms
--  itself so the cleanup that follows allocates normally. Only Ada
--  allocations (`new`, secondary-stack chunks) come through here;
--  OpenSSL and mbedTLS call the C allocator directly, so the gate
--  selects among AHT's own allocations. Not task-safe: the test that
--  arms it is single-task, and the native run-times this is built for
--  use zero-cost exceptions, so no abort deferral is needed around
--  the C calls.

with System.CRTL;

package body System.Memory is

   ----------
   -- Gate --
   ----------

   Armed       : Boolean := False;
   Skip        : Natural := 0;   --  qualifying allocations let through
   Min_Size    : size_t  := 0;   --  what qualifies
   Seen        : Natural := 0;   --  qualifying allocations since Arm
   Hit_Size    : size_t  := 0;   --  size of the failed one, 0 if none
   Hit_Ordinal : Natural := 0;   --  its ordinal among qualifying ones

   procedure Arm (Skip_Count : Integer; Min : size_t)
     with Export, Convention => C, External_Name => "aht_fault_alloc_arm";

   procedure Disarm
     with Export, Convention => C, External_Name => "aht_fault_alloc_disarm";

   function Failed_Size return size_t
     with Export, Convention => C,
          External_Name => "aht_fault_alloc_hit_size";

   function Failed_Ordinal return Integer
     with Export, Convention => C,
          External_Name => "aht_fault_alloc_hit_ordinal";

   procedure Arm (Skip_Count : Integer; Min : size_t) is
   begin
      Skip        := Natural'Max (0, Skip_Count);
      Min_Size    := Min;
      Seen        := 0;
      Hit_Size    := 0;
      Hit_Ordinal := 0;
      Armed       := True;
   end Arm;

   procedure Disarm is
   begin
      Armed := False;
   end Disarm;

   function Failed_Size return size_t is (Hit_Size);

   function Failed_Ordinal return Integer is (Hit_Ordinal);

   -----------
   -- Alloc --
   -----------

   function Alloc (Size : size_t) return System.Address is
      Result : System.Address;
   begin
      if Size = size_t'Last then
         raise Storage_Error with "object too large";
      end if;

      if Armed and then Size >= Min_Size then
         Seen := Seen + 1;
         if Seen > Skip then
            Armed       := False;
            Hit_Size    := Size;
            Hit_Ordinal := Seen;
            raise Storage_Error with "heap exhausted (injected)";
         end if;
      end if;

      Result := System.CRTL.malloc (System.CRTL.size_t (Size));

      if Result = System.Null_Address then
         if Size = 0 then
            return Alloc (1);
         end if;
         raise Storage_Error with "heap exhausted";
      end if;

      return Result;
   end Alloc;

   ----------
   -- Free --
   ----------

   procedure Free (Ptr : System.Address) is
   begin
      System.CRTL.free (Ptr);
   end Free;

   -------------
   -- Realloc --
   -------------

   function Realloc
     (Ptr  : System.Address;
      Size : size_t)
      return System.Address
   is
      Result : System.Address;
   begin
      if Size = size_t'Last then
         raise Storage_Error with "object too large";
      end if;

      Result := System.CRTL.realloc (Ptr, System.CRTL.size_t (Size));

      if Result = System.Null_Address then
         raise Storage_Error with "heap exhausted";
      end if;

      return Result;
   end Realloc;

end System.Memory;
