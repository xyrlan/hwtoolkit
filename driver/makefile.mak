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

# --- Signtool (v4.0.7+ requirement) ---
# BOOT_START drivers on WDAC-enforced Windows are rejected by winload
# if the PE has no Authenticode signature — surfaces as Automatic Repair
# with no visible bugcheck. See docs/postmortem-v4-phase5/incident-v407-
# driver-boot-regression.md for the full root-cause writeup.
#
# The self-signed test cert lives in the host user's Cert:\CurrentUser\My
# store; the VM has the matching public cert in Cert:\LocalMachine\Root.
# Both were provisioned by v4.0.2 (see incident-v402-signature-plus-
# filter.md). Recreate via New-SelfSignedCertificate if the cert expired.
SIGNTOOL     = C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe
SIGN_SHA1    = 30310EE7644799431FFF099E1194817E813152B9
SIGN_STORE   = MY
TSA_URL      = http://timestamp.digicert.com

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
                /INTEGRITYCHECK \
                /LIBPATH:"$(WDK_LIB)\km\x64" \
                ntoskrnl.lib hal.lib BufferOverflowK.lib
# /INTEGRITYCHECK (v5.0.3 requirement): MSDN mandates it for any driver
# using PsSetCreateProcessNotifyRoutineEx. Empirically confirmed on
# bare-metal test 2026-09-01: without this flag, the Ps notify
# registration in ArmTrackD returns STATUS_ACCESS_DENIED and Track D
# never auto-detects rubinot processes (silent fail — g_TrackDPs
# Registered stays FALSE). Testsigning does NOT bypass. See v5.0.3
# changelog block in rstflt.c.

# rstflt: legacy WDM upper filter (needs wdmsec.lib)
RSTFLT_LIBS = wdmsec.lib

all: rstflt.sys

# ---------------- rstflt ----------------
rstflt.obj: rstflt.c trackd_inventory.h
	$(CC) $(CFLAGS_COMMON) /Fo"rstflt.obj" /c rstflt.c

rstflt.sys: rstflt.obj
	$(LINK) $(LFLAGS_COMMON) $(RSTFLT_LIBS) rstflt.obj /OUT:rstflt.sys
	@echo [*] Signing rstflt.sys with test cert $(SIGN_SHA1)
	"$(SIGNTOOL)" sign /fd SHA256 /s $(SIGN_STORE) /sha1 $(SIGN_SHA1) /tr $(TSA_URL) /td SHA256 rstflt.sys

clean:
	-del /q rstflt.obj rstflt.sys 2>nul
