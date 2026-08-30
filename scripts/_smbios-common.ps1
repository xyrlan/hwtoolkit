# ============================================================
#  _smbios-common.ps1  -  helpers de ACL da chave mssmbios\Data
#
#  Dot-source no topo de cada script que edita SMBiosData:
#      . "$PSScriptRoot\_smbios-common.ps1"
#      Grant-SmbiosDataWrite
#
#  Depois de Grant-SmbiosDataWrite, HKLM\SYSTEM\CurrentControlSet\
#  Services\mssmbios\Data esta ownable pelo Administrators e aceita
#  Set-ItemProperty / Remove-ItemProperty em SMBiosData.
# ============================================================

$Script:SmbiosDataKeyPath = "SYSTEM\CurrentControlSet\Services\mssmbios\Data"

function Take-SmbiosDataOwnership {
    $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
        $Script:SmbiosDataKeyPath,
        [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
        [System.Security.AccessControl.RegistryRights]::TakeOwnership
    )
    $acl = $regKey.GetAccessControl()
    $admin = [System.Security.Principal.NTAccount]"BUILTIN\Administrators"
    $acl.SetOwner($admin)
    $regKey.SetAccessControl($acl)
    $regKey.Close()
}

function Grant-SmbiosDataWrite {
    Take-SmbiosDataOwnership
    $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
        $Script:SmbiosDataKeyPath,
        [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
        [System.Security.AccessControl.RegistryRights]::ChangePermissions
    )
    $acl = $regKey.GetAccessControl()
    $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
        [System.Security.Principal.NTAccount]"BUILTIN\Administrators",
        "FullControl",
        "Allow"
    )
    $acl.SetAccessRule($rule)
    $regKey.SetAccessControl($acl)
    $regKey.Close()
}
