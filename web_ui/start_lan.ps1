# start_lan.ps1
# 启动 Agent Skill Security Portal 的「局域网公开模式」：
#   - ASG_PUBLIC_MODE=1  → 关掉模式二/模式三的动态执行 + 删除按钮
#   - 自动放行 Windows 防火墙 TCP 8765（同 WiFi/同子网的人就能访问）
#   - 打印每个网卡的 IPv4，告诉你该把哪个地址发给别人
#
# 用法：在仓库根目录 PowerShell 里：
#   .\web_ui\start_lan.ps1
#
# 停止：Ctrl+C。防火墙规则会保留，下次启动不用再放行；要撤销见脚本末尾命令。

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$AppPath  = Join-Path $RepoRoot "web_ui\app.py"
$Port     = 8765
$RuleName = "ASG Portal $Port (Public Mode)"

if (-not (Test-Path $AppPath)) {
    Write-Host "找不到 $AppPath，请确认你在仓库根目录运行。" -ForegroundColor Red
    exit 1
}

# 1. 防火墙规则（幂等：已存在就跳过）
$existing = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
if ($null -eq $existing) {
    Write-Host "[1/3] 添加防火墙入站规则 TCP $Port ..." -ForegroundColor Cyan
    New-NetFirewallRule -DisplayName $RuleName `
        -Direction Inbound -Protocol TCP -LocalPort $Port `
        -Action Allow -Profile Private,Domain | Out-Null
    Write-Host "      规则已添加（仅 Private/Domain 网络生效，不放公网）" -ForegroundColor Green
} else {
    Write-Host "[1/3] 防火墙规则已存在，跳过" -ForegroundColor DarkGray
}

# 2. 显示 LAN IP
Write-Host "[2/3] 把下面任一地址发给同网段的人："  -ForegroundColor Cyan
$ips = Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.PrefixOrigin -ne "WellKnown" -and $_.IPAddress -ne "127.0.0.1" }
foreach ($ip in $ips) {
    Write-Host ("      http://{0}:{1}    ({2})" -f $ip.IPAddress, $Port, $ip.InterfaceAlias) -ForegroundColor Yellow
}

# 3. 启动服务
Write-Host "[3/3] 启动 web_ui/app.py（ASG_PUBLIC_MODE=1）" -ForegroundColor Cyan
Write-Host "      按 Ctrl+C 退出"                          -ForegroundColor DarkGray
$env:ASG_PUBLIC_MODE = "1"
try {
    & python $AppPath
} finally {
    Remove-Item Env:\ASG_PUBLIC_MODE -ErrorAction SilentlyContinue
}

# 撤销防火墙规则（按需手工执行）：
#   Remove-NetFirewallRule -DisplayName "ASG Portal 8765 (Public Mode)"
