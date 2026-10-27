# capture-evidence.ps1
#
# Reproduces every HTTP request quoted in the Lab 1 report and stores the raw
# response in docs/evidence/*.txt.
#
# Windows PowerShell 5.1 mangles double quotes when passing JSON to native
# executables, so request bodies are written to small temp files and sent with
# `curl --data-binary @file`. The one-liner equivalent (as it would be typed in
# Bash) is recorded inside each evidence file.
#
# Prerequisites: `npm run seed` and `npm start` in another terminal.
# Usage:        powershell -ExecutionPolicy Bypass -File scripts\capture-evidence.ps1

$ErrorActionPreference = 'Stop'
$base = 'http://127.0.0.1:3000'
$out  = Join-Path $PSScriptRoot '..\docs\evidence'
New-Item -ItemType Directory -Force -Path $out | Out-Null
$tmp  = Join-Path $env:TEMP ('lab1-evidence-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

function Save([string]$name, [string]$command, [string]$response) {
    $text = "COMMAND (Bash):`n$command`n`nACTUAL RESPONSE:`n$response"
    [IO.File]::WriteAllText((Join-Path $out $name), $text, (New-Object Text.UTF8Encoding $false))
    Write-Host "  saved $name"
}

function Body([string]$name, [string]$json) {
    $p = Join-Path $tmp "$name.json"
    [IO.File]::WriteAllText($p, $json, (New-Object Text.UTF8Encoding $false))
    return $p
}

Write-Host '1. health'
Save '01-health.txt' "curl -s $base/health" (& curl.exe -s "$base/health" | Out-String)

Write-Host '2. protected endpoint without a token'
Save '02-anonymous-401.txt' "curl -s -i $base/api/data" (& curl.exe -s -i "$base/api/data" | Out-String)

Write-Host '3. successful login'
$loginBody = Body 'login' '{"username":"alice","password":"Alice-Str0ng!Pass"}'
$login = & curl.exe -s -X POST "$base/auth/login" -H 'Content-Type: application/json' --data-binary "@$loginBody" | Out-String
Save '03-login-success.txt' @'
curl -s -X POST http://127.0.0.1:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"Alice-Str0ng!Pass"}'
'@ $login

$token = ($login | ConvertFrom-Json).token
Write-Host "  token acquired: $($token.Substring(0, 24))..."

Write-Host '4. wrong password'
$wrongBody = Body 'wrong' '{"username":"alice","password":"Wrong-Password-123"}'
Save '04-login-wrong-password.txt' @'
curl -s -i -X POST http://127.0.0.1:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"Wrong-Password-123"}'
'@ (& curl.exe -s -i -X POST "$base/auth/login" -H 'Content-Type: application/json' --data-binary "@$wrongBody" | Out-String)

Write-Host '5. authenticated data request'
Save '05-authenticated-data.txt' "curl -s $base/api/data -H `"Authorization: Bearer `$TOKEN`"" (& curl.exe -s "$base/api/data" -H "Authorization: Bearer $token" | Out-String)

Write-Host '6. SQL injection attempt (authentication bypass)'
# Build the body with ConvertTo-Json: PowerShell 5.1 mangles single quotes inside
# JSON string literals, and a malformed body would produce a 400 parse error
# instead of the validation/authentication error we want to demonstrate.
$sqliJson = @{ username = "' OR 1=1--"; password = 'whatever123' } | ConvertTo-Json -Compress
$sqliBody = Body 'sqli' $sqliJson
Save '06-sqli-login.txt' @'
# username is the injection payload: ' OR 1=1--
curl -s -i -X POST http://127.0.0.1:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"'\'' OR 1=1--","password":"whatever123"}'
'@ (& curl.exe -s -i -X POST "$base/auth/login" -H 'Content-Type: application/json' --data-binary "@$sqliBody" | Out-String)

Write-Host '7. XSS payload is stored but escaped on output'
$xssBody = Body 'xss' '{"title":"xss-demo","content":"<script>alert(document.cookie)</script>"}'
Save '07-xss-escaping.txt' @'
curl -s -X POST http://127.0.0.1:3000/api/posts \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"title":"xss-demo","content":"<script>alert(document.cookie)</script>"}'
'@ (& curl.exe -s -X POST "$base/api/posts" -H "Authorization: Bearer $token" -H 'Content-Type: application/json' --data-binary "@$xssBody" | Out-String)

Write-Host '8. IDOR: bob tries to delete alice''s note'
$bobBody = Body 'bob' '{"username":"bob","password":"Bob-Str0ng!Pass42"}'
$bob = (& curl.exe -s -X POST "$base/auth/login" -H 'Content-Type: application/json' --data-binary "@$bobBody" | Out-String | ConvertFrom-Json).token
Save '08-idor-delete.txt' @'
# note 1 belongs to alice; bob presents his own valid token
curl -s -i -X DELETE http://127.0.0.1:3000/api/posts/1 \
  -H "Authorization: Bearer $BOB_TOKEN"
'@ (& curl.exe -s -i -X DELETE "$base/api/posts/1" -H "Authorization: Bearer $bob" | Out-String)

Write-Host '9. tampered signature'
$parts = $token.Split('.')
$tampered = "$($parts[0]).$($parts[1]).AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
Save '09-tampered-token.txt' @'
# same token, last signature byte changed
curl -s -i http://127.0.0.1:3000/api/data -H "Authorization: Bearer $TAMPERED"
'@ (& curl.exe -s -i "$base/api/data" -H "Authorization: Bearer $tampered" | Out-String)

Write-Host '10. security headers'
Save '10-security-headers.txt' "curl -s -D - -o /dev/null $base/health" (& curl.exe -s -D - -o NUL "$base/health" | Out-String)

Write-Host '11. decoded JWT claims'
$padded = $parts[1].Replace('-', '+').Replace('_', '/')
switch ($padded.Length % 4) { 2 { $padded += '==' } 3 { $padded += '=' } }
$claims = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($padded))
Save '11-jwt-claims.json' "# payload section of the issued token, base64url-decoded`n# header: $($parts[0])" $claims

Remove-Item -Recurse -Force $tmp
Write-Host "`nDone - evidence written to $(Resolve-Path $out)"
