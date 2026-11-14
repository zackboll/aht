--  Copyright (C) 2026 Contributors to AHT
--  SPDX-License-Identifier: Apache-2.0

with Interfaces.C;

with GNAT.OS_Lib;
with GNAT.Sockets; use GNAT.Sockets;

--  System.OS_Constants is an internal GNAT unit, used to ask which
--  OS this binary targets, which no portable unit answers.
pragma Warnings (Off, "*internal GNAT unit*");
pragma Warnings (Off, "*non-portable and version-dependent*");
with System.OS_Constants;
pragma Warnings (On, "*non-portable and version-dependent*");
pragma Warnings (On, "*internal GNAT unit*");

package body Socket_Fault is

   function Supported return Boolean is
      use type System.OS_Constants.OS_Type;
   begin
      return System.OS_Constants.Target_OS /= System.OS_Constants.Windows;
   end Supported;

   function Dup2 (Old_FD, New_FD : Interfaces.C.int) return Interfaces.C.int
     with Import, Convention => C, External_Name => "dup2";

   function Break_Socket_To (Port : Natural) return Boolean is
      use type Interfaces.C.int;
      use type GNAT.OS_Lib.File_Descriptor;

      Highest : constant := 1023;
      Found   : Integer := -1;
      Matches : Natural := 0;
      Null_FD : GNAT.OS_Lib.File_Descriptor;
      OK      : Boolean;
   begin
      if not Supported then
         return False;
      end if;
      for FD in 0 .. Highest loop
         begin
            declare
               Peer : constant Sock_Addr_Type :=
                 Get_Peer_Name (To_Ada (FD));
            begin
               if Peer.Family = Family_Inet
                 and then Peer.Port = Port_Type (Port)
                 and then Peer.Addr = Inet_Addr ("127.0.0.1")
               then
                  Found   := FD;
                  Matches := Matches + 1;
               end if;
            end;
         exception
            when Socket_Error => null;  --  not a connected socket
         end;
      end loop;
      if Matches /= 1 then
         return False;
      end if;

      Null_FD := GNAT.OS_Lib.Open_Read ("/dev/null", GNAT.OS_Lib.Binary);
      if Null_FD = GNAT.OS_Lib.Invalid_FD then
         return False;
      end if;
      OK := Dup2 (Interfaces.C.int (Null_FD), Interfaces.C.int (Found))
              = Interfaces.C.int (Found);
      GNAT.OS_Lib.Close (Null_FD);
      return OK;
   end Break_Socket_To;

end Socket_Fault;
