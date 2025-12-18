#This Script will dump all the all issued certificates, including expired ones. And then Parse them into CSV. Amount of time it takes for this op to complete is depends on number of certs you've in your CA. You can also make changes to exclude or apply condition to pull the data accordingly. Feel free to improvise.
# CONFIG
$CA        = "Srv1.demo.local\SubCA"
$WorkDir   = "C:\Users\Administrator\Temp\ADCS_Export"
$OutputCsv = "C:\Users\Administrator\Temp\IssuedCertificates_Full.csv"

New-Item -Path $WorkDir -ItemType Directory -Force | Out-Null

Write-Host "Getting issued Request IDs from CA..." -ForegroundColor Yellow

# 1) Get all issued RequestIDs (Disposition=20)
$tempIdsCsv = Join-Path $WorkDir "reqids.csv"
certutil -config $CA -view -restrict "Disposition=20" -out "Request ID" csv > $tempIdsCsv

$requestIds = Import-Csv $tempIdsCsv | ForEach-Object {
    $_.'Request ID'
} | Where-Object { $_ -match '^\d+$' } | Sort-Object -Unique

Write-Host "Found $($requestIds.Count) issued RequestIDs" -ForegroundColor Green

# 2) Export, decode and collect data
$all = @()

foreach ($id in $requestIds) {
    Write-Host "Processing RequestID $id..." -NoNewline
    $cerPath = Join-Path $WorkDir "Req_$id.cer"

    # Export cert for this RequestID
    $null = certreq -retrieve -config $CA $id $cerPath 2>$null

    if (-not (Test-Path $cerPath)) {
        Write-Host " no .cer exported (skipping)" -ForegroundColor DarkYellow
        continue
    }

    try {
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cerPath)

        # SANs (all types, one column)
        $sans = ""
        $sanExt = $cert.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.17" }
        if ($sanExt) {
            try {
                $sanObj = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
                $sanObj.InitializeDecode(1, [Convert]::ToBase64String($sanExt.RawData))
                $sans = ($sanObj.AlternativeNames |
                         ForEach-Object { "$($_.FriendlyName):$($_.strValue)" }) -join "|"
                [void][Runtime.InteropServices.Marshal]::ReleaseComObject($sanObj)
            } catch {
                $sans = $sanExt.Format(0) -replace "`r?`n","|"
            }
        }

        # Subject DN components
        $subject = $cert.Subject
        $cn      = if ($subject -match 'CN=([^,]+)') { $matches[1] } else { "" }
        $org     = if ($subject -match 'O=([^,]+)')  { $matches[1] } else { "" }
        $ou      = if ($subject -match 'OU=([^,]+)') { $matches[1] } else { "" }
        $state   = if ($subject -match 'ST=([^,]+)') { $matches[1] } else { "" }
        $city    = if ($subject -match 'L=([^,]+)')  { $matches[1] } else { "" }
        $country = if ($subject -match 'C=([^,]+)')  { $matches[1] } else { "" }

        # Extensions
        $skiExt = $cert.Extensions["2.5.29.14"]       # SKI
        $akiExt = $cert.Extensions["2.5.29.35"]       # AKI
        $ekuExt = $cert.Extensions["2.5.29.37"]       # EKU

        $row = [PSCustomObject]@{
            RequestID     = $id
            FilePath      = $cerPath
            SerialNumber  = $cert.GetSerialNumberString()
            Thumbprint    = $cert.Thumbprint
            NotBefore     = $cert.NotBefore
            NotAfter      = $cert.NotAfter
            CommonName    = $cn
            Organization  = $org
            OU            = $ou
            State         = $state
            City          = $city
            Country       = $country
            Subject       = $subject
            SKI           = if ($skiExt) { $skiExt.Format(0) } else { "" }
            AKI           = if ($akiExt) { $akiExt.Format(0) } else { "" }
            EKUs          = if ($ekuExt) { $ekuExt.Format(0) -replace "`r?`n","|" } else { "" }
            SANs          = $sans
        }

        $all += $row
        Write-Host " OK" -ForegroundColor Green
    } catch {
        Write-Host " error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# 3) Post‑process SANs: pipe → comma in same cell and strip leading ':'
foreach ($r in $all) {
    $sanValue = $r.'SANs'
    if (-not [string]::IsNullOrWhiteSpace($sanValue)) {
        $parts =
            $sanValue -split '\|' |
            Where-Object { $_ -and $_.Trim() } |
            ForEach-Object {
                if ($_ -like ':*') { $_.Substring(1) } else { $_ }
            }

        if ($parts.Count -gt 0) {
            $r.'SANs' = ($parts -join ', ')
        }
    }
}

# 4) Export consolidated CSV
$all | Export-Csv -Path $OutputCsv -NoTypeInformation
Write-Host "`nExported $($all.Count) certificates to $OutputCsv" -ForegroundColor Cyan
