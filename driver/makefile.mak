# Build script for rstflt.sys
# Run from a "Developer Command Prompt for VS 2022" or "x64 Native Tools Command Prompt"
#
# Usage:
#   nmake /f makefile.mak            (builds rstflt.sys)
#   nmake /f makefile.mak rstflt.sys
#   nmake /f makefile.mak clean
#
# Requires:
#   - Visual Studio 2022 Build Tools (C++ workload)
#   - Windows Driver Kit 10 (WDK)
#   - Windows SDK (usually installed with VS)

# --- PATHS (adjust if your WDK is installed elsewhere) ---
WDK_INC = C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0
WDK_LIB = C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0

# --- Compiler & Linker ---
CC   = cl.exe
LINK = link.exe

# Shared flags. /Fo is per-target (see rules).
CFLAGS_COMMON = /nologo /W4 /WX /wd4996 /Ox /GS- /Zl \
                /D _AMD64_ /D _WIN64 /D NTDDI_VERSION=0x0A000007 /D _NT_TARGET_VERSION_WIN10_RS2 \
                /I "$(WDK_INC)\km" \
                /I "$(WDK_INC)\shared" \
                /kernel

LFLAGS_COMMON = /nologo /DRIVER /SUBSYSTEM:NATIVE /ENTRY:DriverEntry \
                /NODEFAULTLIB \
                /LIBPATH:"$(WDK_LIB)\km\x64" \
                ntoskrnl.lib hal.lib BufferOverflowK.lib

# rstflt: legacy WDM upper filter (needs wdmsec.lib)
RSTFLT_LIBS = wdmsec.lib

all: rstflt.sys

# ---------------- rstflt ----------------
rstflt.obj: rstflt.c
	$(CC) $(CFLAGS_COMMON) /Fo"rstflt.obj" /c rstflt.c

rstflt.sys: rstflt.obj
	$(LINK) $(LFLAGS_COMMON) $(RSTFLT_LIBS) rstflt.obj /OUT:rstflt.sys

clean:
	-del /q rstflt.obj rstflt.sys 2>nul
