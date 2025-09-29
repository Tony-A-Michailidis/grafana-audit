<#
.SYNOPSIS
  Grafana audit snapshot script.

.DESCRIPTION
  Collects health, version, datasources, folders, dashboard index, sample dashboards,
  Prometheus alerts/rules (through datasource proxy), basic load metrics, and a small Loki sample.

.PARAMETER Base
  Base Grafana URL including subpath (/grafana). Adjust $Base in the param section for other deployments.

.PARAMETER Token
  Grafana service account or API key. Can also use GRAFANA_TOKEN env var.

.NOTES
Run with:  
.\grafana-audit.ps1 -Base https://dev.edh-cde.unclass.dfo-mpo.gc.ca/grafana -Token <insert Grafana service account generated token that has admin privs> -LokiUID <the loki UID> 
Get the service account token from the Grafana admin panel by creating a service account with admin privileges.
Get the lokiUID: kubectl exec -n monitoring deploy/grafana -- curl -s -H "Authorization: Bearer <admin-token>" http://<host>/grafana/api/datasources | ConvertFrom-Json | Where-Object {$_.type -eq "loki"} | Select-Object name, uid, id
#>

param(
  [string]$Base = "https://dev.edh-cde.unclass.dfo-mpo.gc.ca/grafana",  #adjust as necessary, could be in the params but too much to type if you do this over and over again. 
  [string]$Token = $env:GRAFANA_TOKEN,  
  [string]$OutDir = "grafana-audit",
  [string]$PromUID = "promds",
  [string]$LokiUID = $env:lokiUID, 
  [int]$DashboardSample = 15
)

if (-not $Token) {
  Write-Error "No token provided (param -Token or env:GRAFANA_TOKEN)."
  exit 1
}

if (-not $ LokiUID) { 
  Write-Error "No LokiUID provided (param -Token or env:LokiUID)."
  exit 1
}

Write-Host "Using Grafana base: $Base"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$Headers = @{ Authorization = "Bearer $Token" }

function Save-Json {
  param(
    [string]$Name,
    [Parameter(Mandatory)][object]$Data
  )
  $path = Join-Path $OutDir $Name
  try {
    ($Data | ConvertTo-Json -Depth 14) | Out-File $path -Encoding UTF8
    Write-Host ("Wrote {0}" -f $path)
  } catch {
    Write-Warning ("Failed to write {0}: {1}" -f $Name, $_.Exception.Message)
  }
}

function Invoke-GrafanaGet {
  param(
    [string]$Path,
    [switch]$Raw
  )
  $url = "$Base$Path"
  try {
    $r = Invoke-RestMethod -Uri $url -Headers $Headers -Method Get -ErrorAction Stop
    if ($Raw) { return $r } else { return $r }
  } catch {
    Write-Warning "GET $Path failed: $($_.Exception.Message)"
    return $null
  }
}

function Invoke-PromQuery {
  param(
    [string]$Query
  )
  $enc = [System.Uri]::EscapeDataString($Query)
  $path = "/api/datasources/uid/$PromUID/resources/api/v1/query?query=$enc"
  return Invoke-GrafanaGet -Path $path
}

# 1. Health & version
$health   = Invoke-GrafanaGet "/api/health"
$frontend = Invoke-GrafanaGet "/api/frontend/settings"
Save-Json "01_health.json" $health
if ($frontend -and $frontend.buildInfo) {
  Save-Json "02_frontend_buildInfo.json" $frontend.buildInfo
}

# 2. Datasources
$datasources = Invoke-GrafanaGet "/api/datasources"
if ($datasources) {
  # Redact secure fields
  foreach ($d in $datasources) {
    if ($d.secureJsonFields) {
      $d.secureJsonFields = ($d.secureJsonFields | Get-Member -MemberType NoteProperty | ForEach-Object { $_.Name })
    }
  }
  Save-Json "03_datasources_index.json" $datasources
}

# 3. Folders
$folders = Invoke-GrafanaGet "/api/folders"
if ($folders) {
  Save-Json "04_folders.json" $folders
}

# 4. Dashboard index
$dashIndex = Invoke-GrafanaGet "/api/search?type=dash-db&limit=5000"
if ($dashIndex) {
  Save-Json "05_dashboards_index.json" $dashIndex
}

# 5. Dashboards
$sample = @()
if ($dashIndex) {
  $dashIndex | Select-Object -First $DashboardSample | ForEach-Object {
    $uid = $_.uid
    $dash = Invoke-GrafanaGet "/api/dashboards/uid/$uid"
    if ($dash -and $dash.dashboard) {
      $sample += [pscustomobject]@{
        uid    = $uid
        title  = $dash.dashboard.title
        panels = ($dash.dashboard.panels | Measure-Object).Count
        tags   = ($dash.dashboard.tags -join ",")
        folder = $_.folderTitle
      }
    }
  }
  Save-Json "06_dashboards_sample_summary.json" $sample
}

# 6. Unified Grafana alerting (if enabled)
$unifiedAlerts = Invoke-GrafanaGet "/api/alertmanager/grafana/config/api/v1/alerts"
if ($unifiedAlerts) {
  Save-Json "07_grafana_unified_alerts.json" $unifiedAlerts
}

# 7. Prometheus alerts & rules (through proxy)
$promAlerts = Invoke-GrafanaGet "/api/datasources/uid/$PromUID/resources/api/v1/alerts"
if ($promAlerts) {
  Save-Json "08_prometheus_alerts.json" $promAlerts
}
$promRules  = Invoke-GrafanaGet "/api/datasources/uid/$PromUID/resources/api/v1/rules"
if ($promRules) {
  Save-Json "09_prometheus_rules.json" $promRules
}

# 8. Prometheus load snapshot
$queries = @{
  headSeries = 'sum(prometheus_tsdb_head_series)'
  sampleIn   = 'sum(rate(prometheus_tsdb_head_samples_appended_total[5m]))'
  apiP95     = 'histogram_quantile(0.95, sum(rate(apiserver_request_duration_seconds_bucket{verb!~"WATCH|WATCHLIST"}[5m])) by (le,verb))'
}

$loadResults = @{}
foreach ($k in $queries.Keys) {
  $resp = Invoke-PromQuery -Query $queries[$k]
  if ($resp -and $resp.data) {
    $loadResults[$k] = $resp.data.result
  } else {
    $loadResults[$k] = "ERROR"
  }
}
Save-Json "10_prometheus_load_snapshot.json" $loadResults

# 9. Loki sampling (auto-fallback paths)
$lokiOk = $false
if ($LokiUID) {
  $now = [int][double]::Parse((Get-Date -UFormat %s))
  $start = $now - 300
  $logQuery = '{level="error"}'
  $enc = [System.Uri]::EscapeDataString($logQuery)

  $candidatePaths = @(
    "/api/datasources/uid/$LokiUID/proxy/loki/api/v1/query_range?query=$enc&start=${start}000000000&end=${now}000000000&limit=50",
    "/api/datasources/proxy/$($datasources | Where-Object {$_.type -eq 'loki'} | Select-Object -First 1 -ExpandProperty id)/loki/api/v1/query_range?query=$enc&start=${start}000000000&end=${now}000000000&limit=50",
    "/api/datasources/uid/$LokiUID/resources/loki/api/v1/query_range?query=$enc&start=${start}000000000&end=${now}000000000&limit=50" # last (legacy attempt)
  )

  foreach ($p in $candidatePaths) {
    $resp = Invoke-GrafanaGet $p
    if ($resp) {
      Save-Json "11_loki_error_sample.json" $resp
      $lokiOk = $true
      break
    }
  }

  if (-not $lokiOk) {
    Write-Warning "All Loki proxy path attempts failed (checked proxy & resources styles)."
  }
} else {
  Write-Host "No Loki UID provided; skipping Loki sample."
}

# 10. Summary
$summary = [pscustomobject]@{
  timestamp            = (Get-Date).ToString("o")
  grafanaVersion       = if ($frontend) { $frontend.buildInfo.version } else { "UNKNOWN" }
  datasourceCount      = if ($datasources) { $datasources.Count } else { 0 }
  dashboardCount       = if ($dashIndex) { $dashIndex.Count } else { 0 }
  sampledDashboards    = $sample.Count
  prometheusHeadSeries = ($loadResults.headSeries | ConvertTo-Json -Depth 3)
  promAlertsCount      = if ($promAlerts -and $promAlerts.data) { ($promAlerts.data.alerts | Measure-Object).Count } else { 0 }
  unifiedAlertsPresent = [bool]$unifiedAlerts
  lokiSampleSuccess    = $lokiOk
}
Save-Json "00_summary.json" $summary

Write-Host "`n--- Completed audit. Output folder: $OutDir ---"
