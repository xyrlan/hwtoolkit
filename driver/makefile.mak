# Build script for rstflt.sys (was diskfilter.sys)
# Run from a "Developer Command Prompt for VS 2022" or "x64 Native Tools Command Prompt"
#
# Usage:
#   nmake /f makefile.mak
#
# Requires:
#   - Visual Studio 2022 Build Tools (C++ workload)
#   - Windows Driver Kit 10 (WDK)
#   - Windows SDK (usually installed with VS)

# --- PATHS (adjust if your WDK is installed elsewhere) ---
WDK_INC = C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0
WDK_LIB = C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0

# --- Compiler & Linker ---
CC = cl.exe
LINK = link.exe

CFLAGS = /nologo /W4 /WX /wd4996 /Ox /GS- /Zl \
         /D _AMD64_ /D _WIN64 /D NTDDI_VERSION=0x0A000007 /D _NT_TARGET_VERSION_WIN10_RS2 \
         /I "$(WDK_INC)\km" \
         /I "$(WDK_INC)\shared" \
         /kernel /Fo"rstflt.obj"

LFLAGS = /nologo /DRIVER /SUBSYSTEM:NATIVE /ENTRY:DriverEntry \
         /NODEFAULTLIB \
         /LIBPATH:"$(WDK_LIB)\km\x64" \
         ntoskrnl.lib hal.lib wdmsec.lib BufferOverflowK.lib \
         /OUT:rstflt.sys

all: rstflt.sys

rstflt.obj: rstflt.c
	$(CC) $(CFLAGS) /c rstflt.c

rstflt.sys: rstflt.obj
	$(LINK) $(LFLAGS) rstflt.obj

clean:
	-del /q rstflt.obj rstflt.sys 2>nul
