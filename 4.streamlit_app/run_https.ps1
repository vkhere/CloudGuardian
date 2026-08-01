<#
    run_https.ps1
    =============
    Starts the CloudGuardian Console over HTTPS using the self-signed wildcard
    certificate in .\certs.

    Why a launcher instead of putting the paths in config.toml?
        If the SSL settings live in .streamlit\config.toml, the app refuses to
        start whenever the certificate files are missing. Keeping them as
        command-line flags means plain HTTP still works out of the box, and
        HTTPS is opt-in by running this script.

    Usage:
        .\run_https.ps1
        .\run_https.ps1 -Port 8443
#>

param(
    [int]$Port = 8501,
    [string]$CertDir = "certs"
)

$ErrorActionPreference = "Stop"

$crt = Join-Path $CertDir "cloudguardian.crt"
$key = Join-Path $CertDir "cloudguardian.key"

if (-not (Test-Path $crt) -or -not (Test-Path $key)) {
    Write-Host "No certificate found in '$CertDir'. Generating one now..." -ForegroundColor Yellow
    python tools\make_certs.py
    if (-not (Test-Path $crt)) {
        Write-Host "Certificate generation failed. Run 'python tools\make_certs.py' manually." -ForegroundColor Red
        exit 1
    }
}

Write-Host ""
Write-Host "Starting CloudGuardian Console over HTTPS" -ForegroundColor Cyan
Write-Host "  certificate : $crt"
Write-Host "  URL         : https://console.cloudguardian.local:$Port"
Write-Host "  fallback    : https://localhost:$Port"
Write-Host ""
Write-Host "If the browser warns the certificate is untrusted, you have not yet"
Write-Host "imported it into the Trusted Root store - see the setup guide, HTTPS chapter."
Write-Host ""

python -m streamlit run app.py `
    --server.port $Port `
    --server.address 0.0.0.0 `
    --server.sslCertFile $crt `
    --server.sslKeyFile $key
