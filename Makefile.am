# Makefile.am -- automake script for urweb_bcrypt
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


ACLOCAL_AMFLAGS = -I m4

# Two things happen when this package gets built and installed:
#   1. The C source gets compiled into a library.
#   2. The C headers and the Ur interface files get stuck in a location where
#      Ur can find them.


################################# 1. Library ##################################

LIBRARY_SOURCE = src/library

lib_LTLIBRARIES = liburweb_bcrypt.la
liburweb_bcrypt_la_SOURCES = \
	$(srcdir)/$(LIBRARY_SOURCE)/bcryptFfi.c \
	$(srcdir)/$(LIBRARY_SOURCE)/bcrypt/crypt_blowfish.c \
	$(srcdir)/$(LIBRARY_SOURCE)/bcrypt/crypt_gensalt.c \
	$(srcdir)/$(LIBRARY_SOURCE)/bcrypt/wrapper.c \
	$(srcdir)/$(LIBRARY_SOURCE)/bcrypt/x86.S


############################# 2. Interface files ##############################

INTERFACE_SOURCE = src/interface

# One file which needs to get generated at build-time is the config.urp
# configuration header, which provides Ur some build-time constants for users
# of the library.  Unfortunately, this can't be done purely with autoconf,
# because autoconf will not expand @includedir@ recursively.  Apparently, the
# supported way to do this is with (shudder) sed....  (For more information,
# see <http://stackoverflow.com/questions/1440873/>.)
all-local: $(builddir)/$(INTERFACE_SOURCE)/config.urp
$(builddir)/$(INTERFACE_SOURCE)/config.urp: $(srcdir)/$(INTERFACE_SOURCE)/config.urp.in
	mkdir -p $(builddir)/$(INTERFACE_SOURCE)
	$(SED) -e 's|[@]includedir@|$(includedir)|g' <"$<" >"$@"

# Installation with libtool only installs the library, so we need to install
# and uninstall the interface files explicitly.
LIBDEST = @libdir@/urweb/ur/bcrypt
INCLUDEDEST = @includedir@/urweb
HEADER = bcrypt.h
install-exec-local:
	mkdir -p $(LIBDEST)
	install -m 0644 $(builddir)/$(INTERFACE_SOURCE)/config.urp $(LIBDEST)/
	install -m 0644 $(srcdir)/$(INTERFACE_SOURCE)/*.urp $(LIBDEST)/
	install -m 0644 $(srcdir)/$(INTERFACE_SOURCE)/*.ur $(LIBDEST)/
	install -m 0644 $(srcdir)/$(INTERFACE_SOURCE)/*.urs $(LIBDEST)/
	mkdir -p $(INCLUDEDEST)
	install -m 0644 $(srcdir)/$(INTERFACE_SOURCE)/$(HEADER) $(INCLUDEDEST)/
uninstall-local:
	$(RM) $(INCLUDEDEST)/bcrypt.h
	rmdir -p --ignore-fail-on-non-empty $(INCLUDEDEST)
	$(RM) $(LIBDEST)/*
	rmdir -p --ignore-fail-on-non-empty $(LIBDEST)
