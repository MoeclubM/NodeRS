[CmdletBinding()]
param(
    [string]$Repository = $env:NODERS_ANYTLS_REPOSITORY,
    [string]$Version = $env:NODERS_ANYTLS_VERSION,
    [string]$ArchivePath,
    [string]$InstallDir = "$env:ProgramFiles\NodeRS-AnyTLS",
    [string]$ConfigDir = "$env:ProgramData\NodeRS-AnyTLS",
    [string]$StateDir = "$env:ProgramData\NodeRS-AnyTLS\data",
    [string]$SelfSignedDomain,
    [string]$AcmeDomain,
    [string]$AcmeEmail,
    [string]$AcmeChallengeListen = '0.0.0.0:80',
    [switch]$NoService
)

$ErrorActionPreference = 'Stop'
$DefaultRepository = '__GITHUB_REPOSITORY__'
if ($DefaultRepository -eq '__GITHUB_REPOSITORY__') {
    $DefaultRepository = ''
}
if ([string]::IsNullOrWhiteSpace($Repository)) {
    $Repository = $DefaultRepository
}
if ([string]::IsNullOrWhiteSpace($Version)) {
    $Version = 'latest'
}
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$CertPath = Join-Path $ConfigDir 'cert.pem'
$KeyPath = Join-Path $ConfigDir 'key.pem'

function Get-AssetSuffix {
    switch ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture) {
        'X64' { return 'windows-amd64' }
        default { throw "Unsupported Windows architecture: $([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture)" }
    }
}

function Find-LocalStaging {
    $binary = Join-Path $ScriptDir 'noders-anytls.exe'
    if (Test-Path $binary) {
        return $ScriptDir
    }
    return $null
}

function Resolve-ReleaseTag {
    if ($Version -ne 'latest') {
        return $Version
    }
    if ([string]::IsNullOrWhiteSpace($Repository)) {
        throw 'Repository is required when downloading a release; pass -Repository owner/repo.'
    }
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repository/releases/latest"
    if ([string]::IsNullOrWhiteSpace($release.tag_name)) {
        throw "Unable to detect the latest release tag for $Repository"
    }
    return $release.tag_name
}

function Download-ReleaseArchive {
    param(
        [Parameter(Mandatory)] [string]$Tag,
        [Parameter(Mandatory)] [string]$Suffix
    )
    $archiveName = "noders-anytls-$Tag-$Suffix.zip"
    $archivePath = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString() + '-' + $archiveName)
    $url = "https://github.com/$Repository/releases/download/$Tag/$archiveName"
    Write-Host "Downloading $url"
    Invoke-WebRequest -Uri $url -OutFile $archivePath
    return $archivePath
}

function Expand-StagingArchive {
    param([Parameter(Mandatory)] [string]$Path)
    $extractRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString())
    Expand-Archive -Path $Path -DestinationPath $extractRoot -Force
    $staging = Get-ChildItem $extractRoot -Directory | Select-Object -First 1
    if (-not $staging) {
        throw "Archive $Path does not contain a package directory."
    }
    return $staging.FullName
}

function Ensure-Directories {
    New-Item -ItemType Directory -Force -Path $InstallDir, $ConfigDir, $StateDir | Out-Null
}

function Set-DefaultConfigPaths {
    param([Parameter(Mandatory)] [string]$Path)
    $configText = Get-Content $Path -Raw
    $normalizedCert = $CertPath.Replace('\', '/')
    $normalizedKey = $KeyPath.Replace('\', '/')
    $configText = $configText -replace 'cert_path = "cert.pem"', ('cert_path = "{0}"' -f $normalizedCert)
    $configText = $configText -replace 'key_path = "key.pem"', ('key_path = "{0}"' -f $normalizedKey)
    Set-Content $Path $configText
}

function Set-AcmeOptions {
    param([Parameter(Mandatory)] [string]$Path)
    if ([string]::IsNullOrWhiteSpace($AcmeDomain)) {
        return
    }
    $configText = Get-Content $Path -Raw
    $configText = $configText -replace 'enabled = false', 'enabled = true'
    $configText = $configText -replace 'email = "admin@example.com"', ('email = "{0}"' -f $AcmeEmail)
    $configText = $configText -replace 'domain = "node.example.com"', ('domain = "{0}"' -f $AcmeDomain)
    $configText = $configText -replace 'challenge_listen = "0.0.0.0:80"', ('challenge_listen = "{0}"' -f $AcmeChallengeListen)
    Set-Content $Path $configText
}

function ConvertTo-Pem {
    param(
        [Parameter(Mandatory)] [string]$Label,
        [Parameter(Mandatory)] [byte[]]$Bytes
    )
    $base64 = [Convert]::ToBase64String($Bytes)
    $wrapped = ($base64 -split '(.{1,64})' | Where-Object { $_ }) -join [Environment]::NewLine
    return "-----BEGIN $Label-----`r`n$wrapped`r`n-----END $Label-----`r`n"
}

function New-SelfSignedPem {
    param(
        [Parameter(Mandatory)] [string]$Domain,
        [Parameter(Mandatory)] [string]$CertificatePath,
        [Parameter(Mandatory)] [string]$PrivateKeyPath
    )
    if (-not [string]::IsNullOrWhiteSpace($AcmeDomain)) {
        Write-Host 'ACME is enabled; skipping self-signed certificate generation.'
        return
    }
    if ((Test-Path $CertificatePath) -and (Test-Path $PrivateKeyPath)) {
        Write-Host 'TLS files already exist, skipping self-signed generation.'
        return
    }
    $rsa = [System.Security.Cryptography.RSACng]::new(2048)
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        "CN=$Domain",
        $rsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    $sanBuilder = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
    $sanBuilder.AddDnsName($Domain)
    $request.CertificateExtensions.Add($sanBuilder.Build())
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false, $false, 0, $true)
    )
    $usage = [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature -bor
        [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new($usage, $true)
    )
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]::new($request.PublicKey, $false)
    )
    $certificate = $request.CreateSelfSigned(
        [System.DateTimeOffset]::UtcNow.AddMinutes(-5),
        [System.DateTimeOffset]::UtcNow.AddYears(10)
    )
    $certPem = ConvertTo-Pem -Label 'CERTIFICATE' -Bytes $certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    $keyPem = ConvertTo-Pem -Label 'PRIVATE KEY' -Bytes $rsa.Key.Export([System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob)
    Set-Content -Path $CertificatePath -Value $certPem -NoNewline
    Set-Content -Path $PrivateKeyPath -Value $keyPem -NoNewline
}

function Test-IsAdmin {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($current)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Install-ServiceDefinition {
    param([Parameter(Mandatory)] [string]$BinaryPath)
    if ($NoService) {
        return
    }
    if (-not (Test-IsAdmin)) {
        Write-Host 'Skipping service installation because the script is not running as Administrator.'
        return
    }
    $serviceName = 'NodeRS-AnyTLS'
    $configPath = Join-Path $ConfigDir 'config.toml'
    $binPath = ('"{0}" "{1}"' -f $BinaryPath, $configPath)
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        sc.exe config $serviceName start= auto binPath= $binPath | Out-Null
    }
    else {
        New-Service -Name $serviceName -BinaryPathName $binPath -DisplayName $serviceName -StartupType Automatic | Out-Null
    }
    Start-Service -Name $serviceName -ErrorAction SilentlyContinue
}

$stagingDir = Find-LocalStaging
if (-not $stagingDir) {
    if ($ArchivePath) {
        $stagingDir = Expand-StagingArchive -Path $ArchivePath
    }
    else {
        $suffix = Get-AssetSuffix
        $tag = Resolve-ReleaseTag
        $downloaded = Download-ReleaseArchive -Tag $tag -Suffix $suffix
        $stagingDir = Expand-StagingArchive -Path $downloaded
    }
}

$binaryPath = Join-Path $stagingDir 'noders-anytls.exe'
if (-not (Test-Path $binaryPath)) {
    throw "Release staging directory does not contain noders-anytls.exe: $stagingDir"
}
Ensure-Directories
Copy-Item $binaryPath (Join-Path $InstallDir 'noders-anytls.exe') -Force
$configPath = Join-Path $ConfigDir 'config.toml'
if (-not (Test-Path $configPath)) {
    Copy-Item (Join-Path $stagingDir 'config.example.toml') $configPath -Force
    Set-DefaultConfigPaths -Path $configPath
}
Set-AcmeOptions -Path $configPath
if (-not [string]::IsNullOrWhiteSpace($SelfSignedDomain)) {
    New-SelfSignedPem -Domain $SelfSignedDomain -CertificatePath $CertPath -PrivateKeyPath $KeyPath
}
Install-ServiceDefinition -BinaryPath (Join-Path $InstallDir 'noders-anytls.exe')

Write-Host 'Installed NodeRS-AnyTLS'
Write-Host "  Binary: $(Join-Path $InstallDir 'noders-anytls.exe')"
Write-Host "  Config: $configPath"
Write-Host "  State:  $StateDir"
Write-Host "  Cert:   $CertPath"
Write-Host "  Key:    $KeyPath"
if (-not [string]::IsNullOrWhiteSpace($AcmeDomain)) {
    Write-Host "  ACME:   enabled for $AcmeDomain via HTTP-01 on $AcmeChallengeListen"
}
