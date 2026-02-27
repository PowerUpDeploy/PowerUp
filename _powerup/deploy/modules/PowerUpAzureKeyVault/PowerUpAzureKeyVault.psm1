function Find-CertificateBySubjectName([string]$SubjectName)
{
    $stores = @('Cert:\LocalMachine\My', 'Cert:\CurrentUser\My')

    foreach ($store in $stores)
    {
        $matches = Get-ChildItem $store | Where-Object { $_.Subject -like "*$SubjectName*" -and $_.NotAfter -gt (Get-Date) }

        if ($matches)
        {
            $cert = $matches | Sort-Object NotAfter -Descending | Select-Object -First 1

            if ($matches.Count -gt 1)
            {
                Write-Output "Found $($matches.Count) certificates matching '$SubjectName' in $store, using the one expiring $($cert.NotAfter)"
            }

            if (!$cert.HasPrivateKey)
            {
                throw "Certificate '$SubjectName' found in $store does not have an accessible private key"
            }

            return $cert
        }
    }

    $expired = @()
    foreach ($store in $stores)
    {
        $expired += Get-ChildItem $store | Where-Object { $_.Subject -like "*$SubjectName*" }
    }

    if ($expired)
    {
        throw "Certificate '$SubjectName' was found but has expired (NotAfter: $($expired[0].NotAfter))"
    }

    throw "Certificate with subject '$SubjectName' not found in Cert:\LocalMachine\My or Cert:\CurrentUser\My"
}

function ConvertTo-Base64UrlEncoded([byte[]]$bytes)
{
    return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function New-JwtClientAssertion(
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
    [string]$TenantId,
    [string]$ClientId
)
{
    # Decode thumbprint hex string to bytes (compatible with .NET 4.x)
    $thumbprintHex = $Certificate.Thumbprint
    $thumbprintBytes = for ($i = 0; $i -lt $thumbprintHex.Length; $i += 2)
    {
        [Convert]::ToByte($thumbprintHex.Substring($i, 2), 16)
    }

    $x5t = ConvertTo-Base64UrlEncoded $thumbprintBytes

    $header = ConvertTo-Base64UrlEncoded ([Text.Encoding]::UTF8.GetBytes(
        (ConvertTo-Json @{ alg = "RS256"; typ = "JWT"; x5t = $x5t } -Compress)
    ))

    $now = [DateTimeOffset]::UtcNow
    $nbf = $now.ToUnixTimeSeconds()
    $exp = $now.AddMinutes(10).ToUnixTimeSeconds()

    $claims = ConvertTo-Base64UrlEncoded ([Text.Encoding]::UTF8.GetBytes(
        (ConvertTo-Json @{
            aud = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
            iss = $ClientId
            sub = $ClientId
            jti = [Guid]::NewGuid().ToString()
            nbf = $nbf
            exp = $exp
        } -Compress)
    ))

    $dataToSign = [Text.Encoding]::UTF8.GetBytes("$header.$claims")

    # Use the string overload of SignData for .NET 4.x / RSACryptoServiceProvider compatibility
    $signatureBytes = $Certificate.PrivateKey.SignData($dataToSign, "SHA256")
    $signature = ConvertTo-Base64UrlEncoded $signatureBytes

    return "$header.$claims.$signature"
}

function Get-AzureAccessToken(
    [string]$TenantId,
    [string]$ClientId,
    [string]$ClientAssertion
)
{
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    $tokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

    $body = @{
        grant_type             = "client_credentials"
        client_id              = $ClientId
        client_assertion_type  = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        client_assertion       = $ClientAssertion
        scope                  = "https://vault.azure.net/.default"
    }

    try
    {
        $response = Invoke-RestMethod -Method Post -Uri $tokenUrl -Body $body -ContentType "application/x-www-form-urlencoded"
        return $response.access_token
    }
    catch
    {
        throw "Azure authentication failed for tenant '$TenantId', client '$ClientId'. Inner error: $_"
    }
}

function Invoke-KeyVaultSecretGet(
    [string]$VaultUrl,
    [string]$SecretName,
    [string]$AccessToken
)
{
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    $uri = "$($VaultUrl.TrimEnd('/'))/secrets/$SecretName`?api-version=7.4"
    $headers = @{ Authorization = "Bearer $AccessToken" }

    try
    {
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
        return $response.value
    }
    catch
    {
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode -eq 404)
        {
            throw "Secret '$SecretName' was not found in vault '$VaultUrl'"
        }
        throw "Failed to retrieve secret '$SecretName' from vault '$VaultUrl'. Inner error: $_"
    }
}

function Get-AzureKeyVaultSecret(
    [Parameter(Mandatory)][string]$VaultUrl,
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$ClientId,
    [Parameter(Mandatory)][string]$CertificateSubjectName,
    [Parameter(Mandatory)][string]$SecretName,
    [switch]$AsPlainText
)
{
    Write-Output "Retrieving secret '$SecretName' from Azure KeyVault '$VaultUrl'"

    $cert = Find-CertificateBySubjectName $CertificateSubjectName

    Write-Output "Authenticating to Azure AD using certificate '$($cert.Subject)'"
    $jwt = New-JwtClientAssertion -Certificate $cert -TenantId $TenantId -ClientId $ClientId
    $accessToken = Get-AzureAccessToken -TenantId $TenantId -ClientId $ClientId -ClientAssertion $jwt

    $secretValue = Invoke-KeyVaultSecretGet -VaultUrl $VaultUrl -SecretName $SecretName -AccessToken $accessToken

    if ($AsPlainText)
    {
        return $secretValue
    }

    return ConvertTo-SecureString $secretValue -AsPlainText -Force
}

Export-ModuleMember -Function Get-AzureKeyVaultSecret
