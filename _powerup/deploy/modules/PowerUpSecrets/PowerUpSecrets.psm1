if ($null -eq (Get-Module -ListAvailable -Name SecretManagement.KeePass)) 
{
    Install-Module -Name Microsoft.PowerShell.SecretManagement, SecretManagement.KeePass -Scope CurrentUser -Force
} 

function Get-KeepassSecret(
    [Parameter(Mandatory)][string]$VaultName,
    [Parameter(Mandatory)][string]$VaultPath,
    [Parameter(Mandatory)][string]$secretName
)
{
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