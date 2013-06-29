/* bcrypt.h -- low-level FFI to the bcrypt library
 * Copyright (C) 2013  Benjamin Barenblat <benjamin@barenblat.name>
 *
 * This library is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>. */

/* This file describes the interface to the bcrypt FFI in C.  The file
 * 'bcryptFfi.urs' describes the interface in Ur.  As that file, in contrast to
 * this one, is intended for human consumption, all interface description
 * comments reside there. */

#include <urweb/types.h>

uw_Basis_string uw_BcryptFfi_randomSetting(uw_context);

uw_Basis_string uw_BcryptFfi_crypt(uw_context,
                                   uw_Basis_string setting,
                                   uw_Basis_string password);
