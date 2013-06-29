/* bcryptFfi.c -- low-level FFI to the bcrypt library
 * Copyright (C) 2013  Benjamin Barenblat <benjamin@barenblat.name
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
 * You should have received a copy of the GNU Affero General Public License along
 * with this library.  If not, see <http://www.gnu.org/licenses/>. */

#include <stddef.h>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <urweb/urweb.h>

#include "bcrypt/ow-crypt.h"

uw_Basis_string uw_BcryptFfi_randomSetting(uw_context ctx)
{
        // Grab some random bits for the salt.  We need 128 bits, or 16 bytes.
        const int random_fd = open("/dev/urandom", O_RDONLY);
        if (random_fd == -1) {
		uw_error(ctx, FATAL, "unable to open /dev/urandom");
	}
	char salt[16];
	if (read(random_fd, salt, 16) != 16) {
		uw_error(ctx, BOUNDED_RETRY, "/dev/urandom ran dry");
	}
	close(random_fd);

	// Generate the setting.
	uw_Basis_string setting = uw_malloc(ctx, 30);
	if (! crypt_gensalt_rn("$2y$",
			       0, // default number of rounds
			       salt, 16,
			       setting, 30)) {
		uw_error(ctx, FATAL, "unable to generate bcrypt setting");
	}
	return setting;
}

uw_Basis_string uw_BcryptFfi_crypt(uw_context ctx,
                                   uw_Basis_string setting,
                                   uw_Basis_string password)
{
        char *const scratchpad = uw_malloc(ctx, 61);
        uw_Basis_string result = crypt_rn(password,
                                          setting,
                                          scratchpad, 61);
        if (result == NULL) {
                uw_error(ctx, FATAL, "unable to perform bcrypt operation");
        }

        /* At this point, 'result' points somewhere inside 'scratchpad'.
         * 'scratchpad' is allocated on the Ur heap, so we don't have to do
         * anything extra to marshal from C back into Ur. */
        return result;
}
