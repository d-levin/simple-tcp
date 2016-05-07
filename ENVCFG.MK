######################################################################
# environment-specific configuration; this is included by the main
# Makefile for the project.
######################################################################

OSTYPE = $(shell uname)

ifeq ($(strip $(OSTYPE)),SunOS)
ENV=SOLARIS
ARCH = -D_SOLARIS_
else
ifeq ($(strip $(OSTYPE)),Linux)
ENV=LINUX
ARCH = -D_LINUX_
#else
#ifeq ($(findstring Windows,$(strip $(OSTYPE))),Windows)
#ENV=WIN32
else
$(warning supported environments are Solaris and Linux.)
$(warning the reported O/S is $(OSTYPE).)
$(error bailing out)
#endif
endif
endif

ifeq ($(strip $(ENV)),WIN32)
# Win32 settings (MinGW) -- N.B. this project has not been ported to Win32
PTHREADSDIR=/PTHREADS
ENVCFLAGS=-I$(PTHREADSDIR)/Pre-built/include
ENVLIBS=-L$(PTHREADSDIR)/Pre-built/lib -lpthreadGC -lwsock32
KILLALL=utils/killall.csh
else
ifeq ($(strip $(ENV)),LINUX)
# Linux settings
ENVCFLAGS=-ansi -pthread -D_GNU_SOURCE
ENVLIBS=-lnsl -lpthread -lcrypt
KILLALL=killall
else
# Solaris settings
ENVCFLAGS=-ansi -D__EXTENSIONS__
ENVLIBS=-lsocket -lnsl -lm -lpthread
KILLALL=utils/killall.csh
endif	# LINUX
endif	# WIN32

