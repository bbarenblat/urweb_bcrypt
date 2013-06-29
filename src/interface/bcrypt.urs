(* bcrypt.urs -- high-level FFI to the bcrypt library
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

(* In contrast to the 'BcryptFfi' module, 'Bcrypt' is a high-level, typesafe
interface to bcrypt.  You should use 'Bcrypt' instead of 'BcryptFfi' whenever
possible; the former is implemented on top of the latter.

The bcrypt algorithm takes as input a "setting" and a password and produces a
hash.  The "setting" is a data structure describing the version of bcrypt in
use, a tunable parameter defining how slow you would like the hash to be, and
the salt for the hash. *)


(******************************** The setting ********************************)

structure Setting : sig
    type t
    val eq_t : eq t
    val show_t : show t
    val read_t : read t
    val sql_t : sql_injectable t

    (* Creates a setting with a pseudorandom salt and the default number of
    rounds.  The salt comes from /dev/urandom, which is not a cryptographically
    secure source, but it should be good enough. *)
    val random : transaction t

    (* TODO: Write a function to create a setting with pseudorandom salt and a
    specified number of rounds. *)
end


(******************************* The algorithm *******************************)

type hashedString
val eq_hashedString : eq hashedString
val show_hashedString : show hashedString
val read_hashedString : read hashedString
val sql_hashedString : sql_injectable hashedString

(* Extracts the setting from a hashed password. *)
val setting : hashedString -> Setting.t

(* Performs a bcrypt operation. *)
val crypt : Setting.t -> string -> hashedString
