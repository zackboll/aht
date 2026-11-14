--  Copyright (C) 2026 Contributors to AHT
--  SPDX-License-Identifier: Apache-2.0

--  A receive failure that is not the peer's doing, for tests that
--  must tell a reset from every other socket error. POSIX only.
package Socket_Fault is

   function Supported return Boolean;
   --  False where a socket is not a file descriptor (Windows).

   function Break_Socket_To (Port : Natural) return Boolean;
   --  Finds this process's one connected TCP socket whose peer is
   --  127.0.0.1:Port and puts /dev/null in its place under the same
   --  descriptor number, so the owner's next receive fails with an
   --  error that is not a reset (ENOTSOCK) while the descriptor stays
   --  valid and stays the owner's to close. The connection itself is
   --  closed by the replacement. False, with nothing changed, unless
   --  exactly one such socket exists.

end Socket_Fault;
