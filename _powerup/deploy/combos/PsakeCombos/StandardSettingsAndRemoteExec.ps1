function getFileBasedServerSettings($serverName)
{
    getFileBasedSettings $serverName "servers*.*"
}

function getFileBasedDeploymentProfileSettings($deploymentProfile, $overrideSettings)
{
    $verbose = &$getVerboseSettingScriptBlock
    getFileBasedSettings $deploymentProfile $deploymentSettingsFiles $true $overrideSettings $verbose
}

function validateFileBasedDeploymentProfileSettings()
{    
    import-module AffinityId\Id.PowershellExtensions.dll

    Show-SettingsWarnings -filePattern $deploymentSettingsFiles -appendReservedSettings $True
}

function getPackageInformationSettings()
{
    $currentPath = Get-Location
    if (Test-Path "$currentPath\package.id") {
        getFileBasedSettings "PackageInformation" "package.id"
    }
}

function getFileBasedSettings($section, $fileName, $includeEnvironment = $false, $overrideSettings = $null, $verbose = $false)
{
    $currentPath = Get-Location

    import-module AffinityId\Id.PowershellExtensions.dll

    get-parsedsettings -filePattern $fileName -section $section -overrideSettings $overrideSettings -appendReservedSettings $includeEnvironment -directory $currentPath -verbose:$verbose
}

function run($task, $servers, $remoteWorkingSubFolder = $null)
{
    if(!$servers)
    {
        invoke-task $task
    }
    else
    {
        import-module powerupremote
        $currentPath = Get-Location

        if ($remoteWorkingSubFolder -eq $null)
        {
            $remoteWorkingSubFolder = ${package.name}
        }

        invoke-remotetasks $task $servers ${deployment.profile} $remoteWorkingSubFolder $serverSettingsScriptBlock
    }
}

#Convenience function for when you *sometimes* need remote execution
function RunTask {
    param (
        [string]$task,
        [string]$executeRemotely,
        [string]$server
    )

    if(ConvertTo-Bool($executeRemotely)) {
        run $task $server
    } else {
        invoke-task $task
    }
}

task default -depends preprocesspackage, deploy

task validate {
    showSettingsWarnings
}

task preprocesspackage {
    touchPackageIdFile
    & $processTemplatesScriptBlock
}

tasksetup {
    copyDeploymentProfileSpecificFiles
    mergePackageInformation
    mergeSettings
    & $taskSetupExtensionScriptBlock
}

function touchPackageIdFile()
{
    $path = get-location
    if (Test-Path $path\package.id) {
      (Get-Item $path\package.id).LastWriteTime = [datetime]::Now
    }
}

function mergePackageInformation()
{
    import-module powerupsettings
    $packageInformation = getPackageInformationSettings

    if ($packageInformation)
    {
        import-settings $packageInformation
    }
}

function copyDeploymentProfileSpecificFiles()
{
    import-module poweruptemplates
    Merge-ProfileSpecificFiles ${deployment.profile}
}

function mergeSettings()
{
    import-module powerupsettings

    $deploymentProfileSettings = getDeploymentProfileSettings ${deployment.profile} ${deployment.parameters}

    if ($deploymentProfileSettings)
    {
        import-settings $deploymentProfileSettings
    }
}

function processTemplates()
{
    import-module powerupsettings
    import-module poweruptemplates
    
    $currentPath = Get-Location
    $fullFilePath = "$currentPath\$deploymentSettingsFiles"
    
    Write-Output "Processing settings file at $fullFilePath with the following parameter: ${deployment.profile}"
    
    #This is the second time we are reading the settings file. Should probably be using the settings from the merge process.
    $deploymentProfileSettings = getDeploymentProfileSettings ${deployment.profile} ${deployment.parameters}

    if (!$deploymentProfileSettings)
    {
        $deploymentProfileSettings = @{}
    }

    Write-Output "Package settings for this profile are:"
    PrintHashtable $deploymentProfileSettings    

    Write-Output "Substituting and copying templated files"
    merge-templates $deploymentProfileSettings ${deployment.profile} $deploymentTemplateDirectory $deploymentProfileTemplateDirectory $deploymentTemplateOutputDirectory

}

function getDeploymentProfileSettings($deploymentProfile, $overrideSettings)
{
    if (!$overrideSettings)
    {
        $overrideSettings = @{}
    }

    $packageInformation = getPackageInformationSettings

    if ($packageInformation)
    {
        foreach($key in $packageInformation.keys)
        {
            $value = $packageInformation.$key
            if ($value.length -eq 1)
            {
                $overrideSettings.Set_Item($key, $packageInformation.$key[0])
            }
            else
            {
                $overrideSettings.Set_Item($key, $packageInformation.$key)
            }
        }
    }

    return &$deploymentProfileSettingsScriptBlock $deploymentProfile $overrideSettings
}

function showSettingsWarnings()
{
    &$validateDeploymentProfileSettingsScriptBlock
}

function taskSetupDefaultExtension()
{
    # We allow extending the per-task setup, set to an empty function by default
}

function getVerboseSettingDefault()
{
    return $false
}

$getVerboseSettingScriptBlock = $function:getVerboseSettingDefault
$deploymentProfileSettingsScriptBlock = $function:getFileBasedDeploymentProfileSettings
$validateDeploymentProfileSettingsScriptBlock = $function:validateFileBasedDeploymentProfileSettings
$serverSettingsScriptBlock = $function:getFileBasedServerSettings
$processTemplatesScriptBlock = $function:processTemplates
$taskSetupExtensionScriptBlock = $function:taskSetupDefaultExtension
#defaults for settings and template paths - override in the deploy script properties if necessary
$deploymentSettingsFiles = "settings*.*"
$deploymentTemplateDirectory = "_templates"
$deploymentTemplateOutputDirectory = "_templatesoutput"
$deploymentProfileTemplateDirectory = "_profiletemplates"
