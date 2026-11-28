#requires -Version 5.1
<#
  本机 Trae 登录态 → GitHub Secret 的定时同步（Windows 计划任务调用）。
  作用：Trae 的 refreshToken 一被本机客户端轮换，云端静态 Secret 就作废（code=1001）。
       这个脚本只在「本机 token 真的变了」时才推送，避免把云端自己轮换出来的新 token 顶掉。
  依赖：tools/push_secret.js（node + libsodium-wrappers）、python、
        %USERPROFILE%\.workbuddy\trae-checkin\pat.dpapi（DPAPI 当前用户加密）

  初始化（只需一次，PAT 从环境变量读，不落明文）：
     set GITHUB_TOKEN=github_pat_xxx
     powershell -ExecutionPolicy Bypass -File tools\sync-secret.ps1 -Init
#>
param([switch]$Init)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security

$root = Split-Path -Parent $PSScriptRoot
$cfgDir = Join-Path $env:USERPROFILE '.workbuddy\trae-checkin'
$patFile = Join-Path $cfgDir 'pat.dpapi'
$logDir = Join-Path $env:LOCALAPPDATA 'TraeCheckin'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$logFile = Join-Path $logDir 'sync.log'

if ($Init) {
    $patInit = $env:GITHUB_TOKEN
    if (-not $patInit) { Write-Host '[x] 请先设置环境变量 GITHUB_TOKEN'; exit 1 }
    New-Item -ItemType Directory -Force -Path $cfgDir | Out-Null
    $bytes = [Text.Encoding]::UTF8.GetBytes($patInit)
    $enc = [Security.Cryptography.ProtectedData]::Protect($bytes, $null, 'CurrentUser')
    [IO.File]::WriteAllBytes($patFile, $enc)
    Write-Host ('[+] 已写入 ' + $patFile)
    exit 0
}

function Write-Log([string]$msg) {
    $line = '{0} {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $msg
    Add-Content -Path $logFile -Value $line -Encoding utf8
}

if (-not (Test-Path $patFile)) {
    $patTxt = Join-Path $cfgDir 'pat.txt'
    if (Test-Path $patTxt) {
        $pat = (Get-Content $patTxt -Raw).Trim()
        if (-not $pat) { Write-Log 'skip: pat.txt 为空'; exit 0 }
        Set-Location $root
        try {
            $env:GITHUB_TOKEN = $pat
            $out = & node 'tools\push_secret.js' --secret auto 2>&1
            Write-Log (($out | Out-String).Trim())
        } catch { Write-Log ('error: ' + $_.Exception.Message) }
        finally { Remove-Item Env:\GITHUB_TOKEN -ErrorAction SilentlyContinue }
        exit 0
    }
    Write-Log 'skip: pat.dpapi / pat.txt 都不存在（未配置自动同步）'
    exit 0
}

try {
    $enc = [IO.File]::ReadAllBytes($patFile)
    $bytes = [Security.Cryptography.ProtectedData]::Unprotect($enc, $null, 'CurrentUser')
    $pat = [Text.Encoding]::UTF8.GetString($bytes)
} catch {
    Write-Log ('error: 解密 pat 失败 ' + $_.Exception.Message)
    exit 1
}

if (-not $pat) {
    Write-Log 'skip: pat 解密为空'
    exit 0
}

try {
    $env:GITHUB_TOKEN = $pat
    Set-Location $root
    $out = & node 'tools\push_secret.js' --secret auto 2>&1
    Write-Log (($out | Out-String).Trim())
} catch {
    Write-Log ('error: ' + $_.Exception.Message)
} finally {
    Remove-Item Env:\GITHUB_TOKEN -ErrorAction SilentlyContinue
}
