(* bcryptFfi.urs -- low-level FFI to the bcrypt library
Copyright (C) 2013  Benjamin Barenblat <benjamin@barenblat.name>

This library is free software: you can redistribute it and/or modify it under
the terms of the GNU Affero General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version.

This library is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.  See the GNU Affero General Public License for more
details.

You should have received a copy of the GNU Affero General Public License along
with this library.  If not, see <http://www.gnu.org/licenses/>. *)

(* In contrast to the 'Bcrypt' module, 'BcryptFfi' is a low-level, non-typesafe
interface to bcrypt.  It is memory-safe, though, and it's provided as an
"escape hatch" when 'Bcrypt's interface is inadequate.

Unlike 'Bcrypt', which is implemented in Ur, 'BcryptFfi' is actually
implemented in C.  This file describes the interface to the bcrypt FFI in Ur.
The file 'bcrypt.h' describes the interface in C. *)

(* Creates a setting with a pseudorandom salt and the default number of rounds.
The salt comes from /dev/urandom, which is not a cryptographically secure
source, but it should be good enough. *)
val randomSetting : transaction string

(* Runs crypt(3) with the bcrypt algorithm. *)
val crypt : string              (* setting *)
            -> string           (* password *)
            -> string
