
function invoke-remotetasks($tasks, $serverNames, $deploymentEnvironment, $packageName, $settingsFunction, $remoteexecutiontool = $null)
{
    $servers = get-serversettings $settingsFunction $serverNames

    copy-package $servers $packageName $deploymentEnvironment
    
    foreach ($server in $servers)
    {
        if (!$remoteexecutiontool)
        {
            if ($server.ContainsKey('remote.task.execution.remoteexecutiontool'))
            {
                $remoteexecutiontool = $server['remote.task.execution.remoteexecutiontool'][0]
            }
        }

        if ($remoteexecutiontool -eq 'psremoting')
        {
            invoke-remotetaskwithremoting $tasks $server $deploymentEnvironment $packageName
        }
        else
        {
            invoke-remotetaskwithpsexec $tasks $server $deploymentEnvironment $packageName
        }
    }
}

function invoke-remotetaskswithpsexec($tasks, $serverNames, $deploymentEnvironment, $packageName)
{
    invoke-remotetasks $tasks $serverNames $deploymentEnvironment $packageName psexec
}

function invoke-remotetaskswithremoting($tasks, $serverNames, $deploymentEnvironment, $packageName)
{
    invoke-remotetasks $tasks $serverNames $deploymentEnvironment $packageName psremoting
}


function invoke-remotetaskwithpsexec($tasks, $server, $deploymentEnvironment, $packageName )
{
    $serverName = $server['server.name'][0]
    Write-Output "===== Beginning execution of tasks $tasks on server $serverName ====="

    $fullLocalReleaseWorkingFolder = $server['local.temp.working.folder'][0] + '\' + $packageName
    $batchFile = $fullLocalReleaseWorkingFolder + '\' + 'deploy.bat'

    #See https://docs.microsoft.com/en-us/sysinternals/downloads/psexec for PsExec switches
    if ($server.ContainsKey('username'))
    {
        cmd /c cscript.exe /nologo $PSScriptRoot\cmd.js $PSScriptRoot\psexec.exe \\$serverName /accepteula -u $server['username'][0] -p $server['password'][0] -h -w $fullLocalReleaseWorkingFolder $batchFile $deploymentEnvironment $tasks
    }
    else
    {
        cmd /c cscript.exe /nologo $PSScriptRoot\cmd.js $PSScriptRoot\psexec.exe \\$serverName /accepteula -h -w $fullLocalReleaseWorkingFolder $batchFile $deploymentEnvironment $tasks
    }

    Write-Output "====== Finished execution of tasks $tasks on server $serverName ====="

    if ($lastexitcode -ne 0)
    {
        throw "Remotely executed task(s) failed with return code $lastexitcode"
    }
}

function invoke-remotetaskwithremoting($tasks, $server, $deploymentEnvironment, $packageName )
{
    $serverName = $server['server.name'][0]
    Write-Output "===== Beginning execution of tasks $tasks on server $serverName ====="

    $fullLocalReleaseWorkingFolder = $server['local.temp.working.folder'][0] + '\' + $packageName
    
    $scriptBlock = { 
        param($workingFolder, $env, $tasks) 
        set-location $workingFolder;
        .\_powerup\deploy\core\deploy_with_psake.ps1 -buildFile .\deploy.ps1 -deploymentProfile $env -tasks $tasks
        
        if ($lastexitcode -ne 0)
        {
            throw "Exiting with exit code $lastexitcode"
        }
    }

    if ($server['server.domain.joined'][0] -eq "true")
    {
        Invoke-Command -scriptblock $scriptBlock -computername $serverName -ArgumentList $fullLocalReleaseWorkingFolder, $deploymentEnvironment, $tasks 
    } 
    else
    {
        Import-Module PowerUpSecrets
        $password = Get-KeepassSecret -VaultName $server['secret.vault.name'][0] -VaultPath $server['secret.vault.path'][0] -SecretName $server['secret.password.name'][0]
        $credential = new-object -typename System.Management.Automation.PSCredential -argumentlist $server["username"][0], $password

        $session = New-PSSession -ComputerName $serverName -Credential $credential -UseSSL

        Invoke-Command -scriptblock $scriptBlock -Session $session -ArgumentList $fullLocalReleaseWorkingFolder, $deploymentEnvironment, $tasks 
    }

    Write-Output "========= Finished execution of tasks $tasks on server $serverName ====="
}

function copy-package($servers, $packageName, $deploymentEnvironment)
{
    import-module -disablenamechecking powerupfilesystem

    foreach ($server in $servers)
    {
        if ($server['server.domain.joined'][0] -eq 'true')
        {
            copy-packageDomain $server $packageName
        }
        else
        {
            copy-packageNonDomain $server $packageName $deploymentEnvironment
        }
    }
}

function copy-packageDomain($server, $packageName)
{
    $remoteDir = $server['remote.temp.working.folder'][0]
    $serverName = $server['server.name'][0]
    
    if (!$remoteDir)
    {
        throw "Setting remote.temp.working.folder not set for server $serverName"
    }
        
    $remotePath = $remoteDir + '\' + $packageName
    $currentLocation = get-location

    $packageCopyRequired = $false

    if ($server['username'] -and $server['password'])
    {
        set-windowscredentials -serverName $serverName -remoteDir $remoteDir -userName $server['username'][0] -password $server['password'][0]
    }

    if ((!(Test-Path $remotePath\package.id) -or !(Test-Path $currentLocation\package.id)))
    {
        $packageCopyRequired = $true
    }
    else
    {
        $packageCopyRequired = !((Get-Item $remotePath\package.id).LastWriteTime -eq (Get-Item $currentLocation\package.id).LastWriteTime)
    }
    
    if ($packageCopyRequired)
    {
        Write-Output "Copying deployment package to $remotePath"
        Copy-MirroredDirectory $currentLocation $remotePath
    }
}

function copy-packageNonDomain($server, $packageName, $deploymentEnvironment)
{
    # We are going to copy the files to a remote PSSession with Copy-Item so don't use the UNC path
    $remoteDir = $server['local.temp.working.folder'][0]
    $serverName = $server['server.name'][0]

    if (!$remoteDir)
    {
        throw "Setting local.temp.working.folder not set for server $serverName"
    }

    $remotePath = $remoteDir + '\' + $packageName
    $currentLocation = get-location

    Import-Module PowerUpSecrets
    
    $password = Get-KeepassSecret -VaultName $server['secret.vault.name'][0] -VaultPath $server['secret.vault.path'][0] -SecretName $server['secret.password.name'][0]
    $credential = new-object -typename System.Management.Automation.PSCredential -argumentlist $server["username"][0], $password

    $session = New-PSSession -ComputerName $serverName -Credential $credential -UseSSL
    
    $localLastWriteTime = (Get-Item $currentLocation\package.id).LastWriteTime.ToString("o")
    $localPackageIdFileExists = (Test-Path $currentLocation\package.id)
    $remotePackageIdFileExists = Invoke-Command -Session $session -ScriptBlock {
        param (
            $remotePath, 
            $localLastWriteTime, 
            $localPackageIdFileExists
        ) 
        if (!(Test-Path $remotePath\package.id))
        {
            return $false
        }
        else
        {
            # Conver the localLastWriteTime back to a date time as we passed it as a string
            return (Get-Item $remotePath\package.id).LastWriteTime -eq [DateTime]$localLastWriteTime
        }
    } -ArgumentList $remotePath, $localLastWriteTime, $localPackageIdFileExists

    $packageCopyRequired = !$remotePackageIdFileExists -or !$localPackageIdFileExists
    
    if ($packageCopyRequired)
    {
        # Only copy the zip file as its much faster than copying file-by-file
        # We can't use robocopy here as we may not be able to access the UNC paths for a non-domain PC
        Copy-ToPsSession $currentLocation $remotePath $session '*.zip'

        # Extract the zip into the parent folder (Expand-Archive creates a destination folder by default and we don't want that)
        Write-Host "Extracting artifact on remote server"
        Invoke-Command -Session $session -ScriptBlock { 
            param ( $destinationDirectory ) 
            Get-ChildItem -Path $destinationDirectory -Filter *.zip -File | ForEach-Object {
                $path = [System.IO.Path]::GetFullPath($_.FullName)
                Expand-Archive -Path $path -DestinationPath $destinationDirectory
            }
        } -ArgumentList $remotePath

        # Also copy the templated configuration and package.id files
        # We need to copy the package.id file as otherwise the timestamps from the extraction step wont match
        Copy-Item -ToSession $session -Path '_templatesoutput' -Destination $remotePath -Recurse
        Copy-Item -ToSession $session -Path 'package.id' -Destination $remotePath
    }
}

function set-windowscredentials ($serverName, $remoteDir, $userName, $password)
{
    write-output "Login to $serverName as $userName"
    NET USE $remoteDir /u:$userName $password
}

function get-serverSettings($settingsFunction, $serverNames)
{        
    $servers = @()
    
    foreach ($serverName in $serverNames)
    {
        $serverSettings = &$settingsFunction $serverName
        $servers += $serverSettings
    }

    $servers
}

function enable-psremotingforpowerup
{
    $nlm = [Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]"{DCB00C01-570F-4A9B-8D69-199FDBA5723B}"))
    $connections = $nlm.getnetworkconnections()
    
    $connections | ForEach-Object {
        if ($_.getnetwork().getcategory() -eq 0)
        {
            $_.getnetwork().setcategory(1)
        }
    }

    Enable-PSRemoting -Force 

    $currentPath = get-location
    Copy-Item $currentPath\_powerup\deploy\core\powershell.exe.config -destination C:\Windows\System32\wsmprovhost.exe.config -force
}
                
export-modulemember -function invoke-remotetasks, invoke-remotetaskswithpsexec, invoke-remotetaskswithremoting, enable-psremotingforpowerup
