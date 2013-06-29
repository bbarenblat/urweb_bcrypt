(* bcrypt.ur -- high-level FFI to the bcrypt library
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


(********************************** Utility **********************************)

(* Value-level identity *)
fun id [t ::: Type] (x : t) : t = x

(* Converts a boolean to an option.  Useful for chaining a bunch of boolean
assertions into the option monad. *)
fun assert (cond : bool) : option unit = if cond then Some () else None


(*** String processing functions ***)

(* Removes the first 'n' characters from 's' *)
fun drop (n : int) (s : string) : string =
    String.substring s { Start = n, Len = String.length s - n }

(* Extracts the last 'n' characters from 's' *)
fun takeLast (n : int) (s : string) : string =
    String.substring s { Start = String.length s - n, Len = n }

(* Removes the last 'n' characters from 's' *)
fun dropLast (n : int) (s : string) : string =
    String.substring s { Start = 0, Len = String.length s - n }

(* A predicate on characters matching [./A-Za-z0-9], the set of characters used
in bcrypt's weird base64 representation. *)
fun isValidHashCharacter (c : char) : bool =
    Char.isAlnum c || c = #"." || c = #"/"


(******************************** The setting ********************************)

structure Setting = struct
    (* I use smart constructors (primarily 'read') to ensure that this is
    always a valid bcrypt setting. *)
    type t = string

    val eq_t = eq_string

    val show_t = mkShow id

    fun ofString (s : string) : option t =
        (* Ah, what I'd give for a regular expression engine that can simply
        recognize /\$2[axy]?\$[0-9]{2}\$[./A-Za-z0-9]{22}/!  Alas, that is a
        task for another adventurer. *)
        assert (String.lengthGe s 28);
        (* Rip off the $2 or $2a (or $2y or $2n) at the start. *)
        assert (String.sub s 0 = #"$");
        assert (String.sub s 1 = #"2");
        withIdStripped <-
            (let val classIdentifier = String.sub s 2 in
                 if classIdentifier = #"a"
                    || classIdentifier = #"y"
                    || classIdentifier = #"n"
                 then Some (drop 3 s)
                 else if classIdentifier = #"$"
                 then Some (drop 2 s)
                 else None
             end);
        (* Check for a valid number of rounds. *)
        assert (String.sub withIdStripped 0 = #"$");
        assert (Char.isDigit (String.sub withIdStripped 1));
        assert (Char.isDigit (String.sub withIdStripped 2));
        assert (String.sub withIdStripped 3 = #"$");
        (* Check the salt's base64 representation. *)
        let val salt = drop 4 withIdStripped in
            assert (String.length salt = 22);
            assert (String.all isValidHashCharacter salt);
            return s
        end

    fun ofStringError (s : string) : t =
        Option.get (error <xml>{[s]} is an invalid bcrypt setting</xml>)
                   (ofString s)

    val read_t = mkRead ofStringError ofString

    val sql_t = sql_prim

    val random = BcryptFfi.randomSetting
end


(******************************* The algorithm *******************************)

type hashedString = string

val eq_hashedString = eq_string

val show_hashedString = mkShow id

fun setting (s : hashedString) = dropLast 31 s

fun ofString (s : string) : option hashedString =
    (* Once again, a regular expression library would be nice.  In the
    meantime, the last 31 characters must be the hash, and the others must be
    the setting. *)
    assert (String.lengthGe s 59);
    assert (String.all isValidHashCharacter (takeLast 31 s));
    Monad.ignore (@read Setting.read_t (setting s));
    return s

fun ofStringError (s : string) : hashedString =
    Option.get (error <xml>{[s]} is an invalid bcrypt hash</xml>) (ofString s)

val read_hashedString = mkRead ofStringError ofString

val sql_hashedString = sql_prim

val crypt setting password = BcryptFfi.crypt (show setting) password
