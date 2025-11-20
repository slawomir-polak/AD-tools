Import-Module WebAdministration

# ====================================================================
# DANE SERWERA
# ====================================================================

$Hostname = $env:COMPUTERNAME
$IPs = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike "169.254.*" -and $_.IPAddress -ne "127.0.0.1" } |
        Select-Object -ExpandProperty IPAddress)

$Date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$DateFile = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"

# wybieramy pierwszy adres IP (typowo główny)
$PrimaryIP = $IPs | Select-Object -First 1
$PrimaryIP_Safe = $PrimaryIP -replace "\.", "-"

$ReportFile = "$PrimaryIP_Safe`_IIS_AUDYT_$DateFile.html"

# Bufor HTML
$Report = @()

# funkcja pomocnicza
function Add-Section($title, $content) {
    return "<h2>$title</h2><pre>$content</pre>"
}

# ====================================================================
# Zbieranie danych do raportu
# ====================================================================

$Report += "<h1>Raport audytu IIS</h1>"
$Report += "<b>Host:</b> $Hostname<br>"
$Report += "<b>Adresy IP:</b> $($IPs -join ', ')<br>"
$Report += "<b>Data:</b> $Date<br><hr>"


# 1 — Metody HTTP
$methods = (Get-WebConfigurationProperty -Filter "/system.webServer/security/requestFiltering/verbs/add" -Name "verb" -PSPath 'IIS:\') |
           Select-Object -ExpandProperty Value
$Report += Add-Section "1. Dozwolone metody HTTP" ($methods -join "`n")


# 2 — Uwierzytelnianie
$auth = Get-WebConfiguration -Filter "/system.webServer/security/authentication/*" -PSPath "IIS:\" |
        Select-Object name, enabled | Out-String
$Report += Add-Section "2. Uwierzytelnianie" $auth

$authRules = Get-WebConfiguration -Filter "/system.webServer/security/authorization/*" -PSPath "IIS:\" | Out-String
$Report += Add-Section "2b. Reguły autoryzacji" $authRules


# 3 — Directory Browsing
$dirBrowse = (Get-WebConfigurationProperty -Filter "/system.webServer/directoryBrowse" -Name enabled -PSPath 'IIS:\').Value
$Report += Add-Section "3. Directory Browsing" $dirBrowse


# 4 — Wirtualne hosty
$bindings = (Get-ChildItem IIS:\Sites | Select-Object Name, State, Bindings | Out-String)
$Report += Add-Section "4. Wirtualne hosty (Bindings)" $bindings


# 5 — Custom Errors
$errors = Get-WebConfiguration -Filter "/system.webServer/httpErrors/error" -PSPath 'IIS:\' |
          Select-Object statusCode, path, responseMode | Out-String
$Report += Add-Section "5. Obsługa błędów (Custom Errors)" $errors


# 6 — Server Header
$serverHeader = Get-WebConfigurationProperty -Filter "/system.webServer/httpProtocol/customHeaders/add[@name='Server']" -Name "value" -PSPath 'IIS:\'
$removeHeader = Get-WebConfigurationProperty -PSPath 'IIS:\' -Filter /system.webServer/security/requestFiltering -Name removeServerHeader
$Report += Add-Section "6. Server Header" ("Server: $serverHeader`nRemoveServerHeader: $removeHeader")


# 7 — Moduły
$modules = (Get-WebGlobalModule | Select-Object Name, Image | Out-String)
$Report += Add-Section "7. Moduły IIS" $modules


# 8 — Nagłówki bezpieczeństwa
$headers = "X-Frame-Options","X-Content-Type-Options","Strict-Transport-Security","Content-Security-Policy","X-XSS-Protection"
$out = ""
foreach ($h in $headers) {
    $val = Get-WebConfigurationProperty -PSPath 'IIS:\' -Filter "/system.webServer/httpProtocol/customHeaders/add[@name='$h']" -Name value
    $out += "$h : $val`n"
}
$Report += Add-Section "8. Nagłówki bezpieczeństwa" $out


# 9 — Logowanie
$logging = Get-WebConfigurationProperty -Filter "/system.applicationHost/sites/siteDefaults/logFile" -Name * -PSPath 'IIS:\' | Out-String
$Report += Add-Section "9. Konfiguracja logowania" $logging


# 10 — TLS/HTTPS
$regBase = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
$protocols = (Get-ChildItem $regBase | ForEach-Object {
    $_.Name.Replace("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\","")
}) -join "`n"

$cipherSuites = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\CipherSuites" -ErrorAction SilentlyContinue | Out-String)

$httpsBindings = (Get-ChildItem IIS:\Sites | ForEach-Object {
    $_.Bindings.Collection | Where-Object {$_.protocol -eq "https"} |
    Select-Object BindingInformation, CertificateStoreName, CertificateHash
} | Out-String)

$Report += Add-Section "10. Protokoły TLS/SSL" $protocols
$Report += Add-Section "10b. Cipher Suites" $cipherSuites
$Report += Add-Section "10c. Certyfikaty / HTTPS Bindings" $httpsBindings


# 11 — Wersja IIS
$iisVersion = (Get-ItemProperty "HKLM:\Software\Microsoft\InetStp").VersionString
$Report += Add-Section "11. Wersja IIS" "IIS Version: $iisVersion`nSprawdź CVE: Nessus / OpenVAS / Qualys"


# ====================================================================
# Zapis raportu
# ====================================================================

$HTML = @"
<html>
<head>
<title>Raport IIS</title>
<style>
body { font-family: Consolas; background: #f7f7f7; padding: 20px; }
pre { background: #fff; padding: 10px; border: 1px solid #ccc; }
h1,h2 { font-family: Arial; }
</style>
</head>
<body>
$($Report -join "`n")
</body>
</html>
"@

$HTML | Out-File -FilePath $ReportFile -Encoding UTF8

Write-Host "`nRaport zapisano jako: $ReportFile" -ForegroundColor Green
