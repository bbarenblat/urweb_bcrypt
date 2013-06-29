# configure.ac -- autoconf script for urweb_bcrypt
# Copyright (C) 2013  Benjamin Barenblat <benjamin@barenblat.name>
#
# This script is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# This script is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# urweb_bcrypt.  If not, see <http://www.gnu.org/licenses/>.

# Fire up Autoconf.
AC_PREREQ([2.69])
AC_INIT([urweb_bcrypt], [0.0.0], [benjamin@barenblat.name])
AC_USE_SYSTEM_EXTENSIONS

# Fire up Automake.
AM_INIT_AUTOMAKE([-Wall -Werror foreign no-define])
AC_CONFIG_MACRO_DIR([m4])

# Build a C library.
AC_PROG_CC
# Automake 1.12 seems to require this, but automake 1.11 doesn't recognize it.
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
LT_INIT

# bcrypt has some x86 assembly.
AM_PROG_AS

# Dependencies
AC_CHECK_HEADERS([fcntl.h stdlib.h string.h unistd.h])
AC_FUNC_REALLOC
AC_CHECK_FUNCS([memchr memset strdup])

# Generate Makefile, but not bcrypt/Makefile (that already exists).
AC_CONFIG_FILES([Makefile])

# All done.
AC_OUTPUT
