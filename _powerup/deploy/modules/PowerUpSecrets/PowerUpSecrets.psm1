function Ensure-KeepassModules
{
    if ($null -ne (Get-Module -ListAvailable -Name SecretManagement.KeePass)) { return }

    # NuGet provider is required by Install-Module; install it silently if missing
    if ($null -eq (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue))
    {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser | Out-Null
    }

    # Trust PSGallery so Install-Module runs without any confirmation prompts
    Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted

    Install-Module -Name Microsoft.PowerShell.SecretManagement, SecretManagement.KeePass -Scope CurrentUser -Force

    # Explicitly import so the newly installed modules are available in this session
    Import-Module Microsoft.PowerShell.SecretManagement
    Import-Module SecretManagement.KeePass
}

function Get-KeepassSecret(
    [Parameter(Mandatory)][string]$VaultName,
    [Parameter(Mandatory)][string]$VaultPath,
    [Parameter(Mandatory)][string]$secretName
)
{
    Ensure-KeepassModules

    # Register the vault if it isn't already
    Register-KeepassVault -VaultName $VaultName -VaultPath $VaultPath

    # Then unlock it so we can get the value
    $vaultPassword = Get-VaultPassword
    Unlock-SecretVault -Password $vaultPassword -Name $vaultName

    $secret = Get-Secret -Name $secretName -Vault $vaultName

    # Always unregister the vault once used, as the vault points to a keepass file that
    # might be in a different folder on the next deploy, we can't have the registration hanging around
    Unregister-SecretVault $vaultName
    return $secret
}

function New-KeepassSecret(
    [Parameter(Mandatory)][string]$VaultName,
    [Parameter(Mandatory)][string]$VaultPath,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$Value
)
{
    Ensure-KeepassModules

    # Register the vault if it isn't already
    Register-KeepassVault -VaultName $VaultName -VaultPath $VaultPath

    # Then unlock it so we can set the new value
    $vaultPassword = Get-VaultPassword

    Unlock-SecretVault -Password $vaultPassword -Vault $vaultName

    Set-Secret -Name $name -Secret $Value -Vault $VaultName

    # Always unregister the vault once used, as the vault points to a keepass file that
    # might be in a different folder on the next deploy, we can't have the registration hanging around
    Unregister-SecretVault $vaultName
}

function Register-KeepassVault (
    [Parameter(Mandatory)][string]$VaultName,
    [Parameter(Mandatory)][string]$VaultPath
)
{
    $path = [System.IO.Path]::GetFullPath($VaultPath)

    try
    {
        # If the vaule exists, it might have been left over from a past run in a different folder, therefore unregister it
        Get-SecretVault -Name $VaultName
        Unregister-SecretVault $vaultName
    }
    catch {
        # no-op, we don't care about errors if the vault doesn't exist
    }
    finally
    {
        # Register the valut now we've confirmed it doesn't already exist
        Write-Host "Registering Vault"
        Register-SecretVault -Name $VaultName -ModuleName SecretManagement.KeePass -VaultParameters @{
            Path = $path
            UseMasterPassword = $true
        }
    }
}

function Get-VaultPassword()
{
    if([string]::IsNullOrEmpty($env:KEEPASS_MASTER_PASSWORD))
    {
        throw "KEEPASS_MASTER_PASSWORD environment variable not set, unable to unlock the database"
    }

    $vaultPassword= ConvertTo-SecureString $env:KEEPASS_MASTER_PASSWORD -AsPlainText -Force

    return $vaultPassword
}

Export-ModuleMember -function Get-KeepassSecret, New-KeepassSecret, Register-KeepassVault
