<#
.SYNOPSIS
  Watch for connections to a specific IP (or prefix) and log which process makes
  them. Use to identify what an unexplained behavioral-C2 alert really was.

.EXAMPLE
  .\scripts\watch_ip.ps1 -Ip 84.247.97.15
  .\scripts\watch_ip.ps1 -Ip 84.247. -Seconds 600    # prefix match, 10 min
#>
param(
  [Parameter(Mandatory = $true)][string]$Ip,
  [int]$Seconds = 1800,   # how long to watch
  [int]$PollMs = 1000
)
Write-Host "Watching for connections to '$Ip' for $Seconds s (Ctrl+C to stop)..."
$seen = @{}
$end = (Get-Date).AddSeconds($Seconds)
while ((Get-Date) -lt $end) {
  foreach ($c in (Get-NetTCPConnection -ErrorAction SilentlyContinue |
                  Where-Object { $_.RemoteAddress -like "$Ip*" })) {
    $key = "$($c.RemoteAddress):$($c.RemotePort):$($c.OwningProcess)"
    if (-not $seen.ContainsKey($key)) {
      $seen[$key] = $true
      $p = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
      $path = try { $p.Path } catch { "" }
      Write-Host ("[{0}] {1} -> {2}:{3}  PROCESS={4} (pid {5})  {6}" -f `
        (Get-Date -Format HH:mm:ss), $c.LocalPort, $c.RemoteAddress, `
        $c.RemotePort, $p.ProcessName, $c.OwningProcess, $path)
    }
  }
  Start-Sleep -Milliseconds $PollMs
}
Write-Host "Done watching."
