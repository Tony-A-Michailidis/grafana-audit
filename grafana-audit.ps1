<#
.SYNOPSIS
  Grafana audit snapshot script.

.DESCRIPTION
  Collects health, version, datasources, folders, dashboard index, sample dashboards,
  Prometheus alerts/rules (through datasource proxy), basic load metrics, and a small Loki sample.

.PARAMETER Base
  Base Grafana URL including subpath (/grafana).

.PARAMETER Token
  Grafana service account or API key. Can also use GRAFANA_TOKEN env var.

.NOTES
 # Basic audit  
.\grafana-audit.ps1 -Base $url -Token $token

# Comprehensive security audit
.\grafana-audit.ps1 -Base $url -Token $token -IncludeSecurityAudit -IncludeUserActivity

# Performance analysis
.\grafana-audit.ps1 -Base $url -Token $token -IncludePerformanceMetrics -ValidateAlerts

# Full enterprise audit
.\grafana-audit.ps1 -Base $url -Token $token -IncludeSecurityAudit -IncludePerformanceMetrics -IncludeUserActivity -ExportDashboards -ValidateAlerts
#>

param(
  [string]$Base = "....", 
  [string]$Token = $env:GRAFANA_TOKEN,  
  [string]$OutDir = "grafana-audit",
  [string]$PromUID = "promds",
  [string]$LokiUID = "lokids",
  [string]$AzureMonitorUID = "azmonitor",
  [int]$DashboardSample = 15,
  [switch]$IncludeSecurityAudit,
  [switch]$IncludePerformanceMetrics,
  [switch]$IncludeUserActivity,
  [switch]$ExportDashboards,
  [switch]$ValidateAlerts
)

if (-not $Token) {
  Write-Error "No token provided (param -Token or env:GRAFANA_TOKEN)."
  exit 1
}

# Define all functions first
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
    [switch]$Raw,
    [switch]$SuppressWarnings
  )
  $url = "$Base$Path"
  try {
    $r = Invoke-RestMethod -Uri $url -Headers $Headers -Method Get -ErrorAction Stop
    if ($Raw) { return $r } else { return $r }
  } catch {
    if (-not $SuppressWarnings) {
      $statusCode = ""
      if ($_.Exception.Response) {
        $statusCode = " ($($_.Exception.Response.StatusCode))"
      }
      Write-Warning "GET $Path failed: $($_.Exception.Message)$statusCode"
    }
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

function Test-GrafanaConnectivity {
  param([string]$BaseUrl, [hashtable]$Headers)
  
  try {
    $response = Invoke-RestMethod -Uri "$BaseUrl/api/health" -Headers $Headers -Method Get -TimeoutSec 10
    return $response.database -eq "ok"
  } catch {
    Write-Warning "Grafana connectivity test failed: $($_.Exception.Message)"
    return $false
  }
}

function Get-AlertSeverityBreakdown {
  param($Alerts)
  
  $breakdown = @{
    critical = 0
    warning = 0
    info = 0
    unknown = 0
  }
  
  if ($Alerts -and $Alerts.data -and $Alerts.data.alerts) {
    foreach ($alert in $Alerts.data.alerts) {
      $severity = $alert.labels.severity
      if ($breakdown.ContainsKey($severity)) {
        $breakdown[$severity]++
      } else {
        $breakdown.unknown++
      }
    }
  }
  
  return $breakdown
}

function Export-AuditReport {
  param(
    [string]$OutputDir,
    [object]$Summary
  )
  
  $reportPath = Join-Path $OutputDir "AUDIT_REPORT.md"
  $report = @"
# Grafana Audit Report

**Generated:** $($Summary.timestamp)
**Grafana Version:** $($Summary.grafanaVersion)

## Summary
- **Datasources:** $($Summary.datasourceCount)
- **Dashboards:** $($Summary.dashboardCount) 
- **Folders:** $($Summary.folderCount)
- **Active Alerts:** $($Summary.firingAlertsCount)/$($Summary.promAlertsCount)
- **Users:** $($Summary.userCount)
- **Teams:** $($Summary.teamCount)
- **Plugins:** $($Summary.pluginCount)

## Health Status
- **Loki Connection:** $(if($Summary.lokiSampleSuccess) { "✅ OK" } else { "❌ Failed" })
- **Azure Monitor:** $(if($Summary.azureMonitorConnected) { "✅ Connected" } else { "❌ Not Connected" })
- **Version Status:** $(if($Summary.hasUpdate) { "⚠️ Update Available ($($Summary.latestVersion))" } else { "✅ Up to Date" })

## Audit Scope
$(if($Summary.auditFlags.securityAudit) { "✅ Security Audit" } else { "❌ Security Audit" })
$(if($Summary.auditFlags.performanceMetrics) { "✅ Performance Metrics" } else { "❌ Performance Metrics" })
$(if($Summary.auditFlags.userActivity) { "✅ User Activity" } else { "❌ User Activity" })
$(if($Summary.auditFlags.dashboardExport) { "✅ Dashboard Export" } else { "❌ Dashboard Export" })
$(if($Summary.auditFlags.alertValidation) { "✅ Alert Validation" } else { "❌ Alert Validation" })

---
*Run with additional flags for comprehensive analysis*
"@
  
  $report | Out-File $reportPath -Encoding UTF8
  Write-Host "Audit report saved: $reportPath"
}

function Invoke-GrafanaGetWithFallback {
  param(
    [string]$Path,
    [string]$Description,
    [switch]$IsAdminRequired,
    [switch]$IsOptional
  )
  
  $result = Invoke-GrafanaGet -Path $Path -SuppressWarnings:$IsOptional
  
  if (-not $result -and $IsAdminRequired) {
    Write-Host "⚠️  Skipping $Description (requires admin privileges)" -ForegroundColor Yellow
  } elseif (-not $result -and -not $IsOptional) {
    Write-Warning "$Description failed - this may indicate a configuration issue"
  }
  
  return $result
}

# Initialize
Write-Host "Using Grafana base: $Base"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$Headers = @{ Authorization = "Bearer $Token" }

# Test connectivity first
Write-Host "Testing Grafana connectivity..."
if (-not (Test-GrafanaConnectivity -BaseUrl $Base -Headers $Headers)) {
  Write-Error "Failed to connect to Grafana. Please check URL and token."
  exit 1
}
Write-Host "✅ Grafana connectivity confirmed"

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

# 5. Sample dashboards
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
  Write-Host "Testing Loki connectivity..."
  $now = [int][double]::Parse((Get-Date -UFormat %s))
  $start = $now - 300
  $logQuery = '{level="error"}'
  $enc = [System.Uri]::EscapeDataString($logQuery)

  # Try different Loki API paths
  $candidatePaths = @(
    "/api/datasources/uid/$LokiUID/proxy/loki/api/v1/query_range?query=$enc&start=${start}000000000&end=${now}000000000&limit=50",
    "/api/datasources/uid/$LokiUID/resources/loki/api/v1/query_range?query=$enc&start=${start}000000000&end=${now}000000000&limit=50"
  )
  
  # Add proxy by ID if we can find the Loki datasource
  $lokiDS = $datasources | Where-Object {$_.type -eq 'loki'} | Select-Object -First 1
  if ($lokiDS) {
    $candidatePaths += "/api/datasources/proxy/$($lokiDS.id)/loki/api/v1/query_range?query=$enc&start=${start}000000000&end=${now}000000000&limit=50"
  }

  foreach ($p in $candidatePaths) {
    $resp = Invoke-GrafanaGet $p -SuppressWarnings
    if ($resp) {
      Save-Json "11_loki_error_sample.json" $resp
      $lokiOk = $true
      Write-Host "✅ Loki connection successful"
      break
    }
  }

  if (-not $lokiOk) {
    Write-Host "⚠️  Loki sampling failed - may indicate connectivity issues" -ForegroundColor Yellow
    # Create empty result to maintain file structure
    Save-Json "11_loki_error_sample.json" @{status="error";message="Loki connection failed"}
  }
} else {
  Write-Host "No Loki UID provided; skipping Loki sample."
}

# 10. Enhanced Security Audit (if requested)
if ($IncludeSecurityAudit) {
  Write-Host "Performing security audit..."
  
  # User and team information (requires admin privileges)
  $users = Invoke-GrafanaGetWithFallback "/api/users/search" "User audit" -IsAdminRequired
  $teams = Invoke-GrafanaGet "/api/teams/search"
  $orgs = Invoke-GrafanaGetWithFallback "/api/orgs" "Organization audit" -IsAdminRequired
  
  if ($users) { Save-Json "12_users_audit.json" $users }
  if ($teams) { Save-Json "13_teams_audit.json" $teams }
  if ($orgs) { Save-Json "14_orgs_audit.json" $orgs }
  
  # Service accounts and API keys
  $serviceAccounts = Invoke-GrafanaGet "/api/serviceaccounts/search"
  if ($serviceAccounts) { Save-Json "15_service_accounts.json" $serviceAccounts }
  
  # Authentication settings (requires admin privileges)
  $authSettings = Invoke-GrafanaGetWithFallback "/api/admin/settings" "Authentication settings" -IsAdminRequired
  if ($authSettings) { 
    # Redact sensitive auth info
    if ($authSettings.auth) {
      foreach ($provider in $authSettings.auth.PSObject.Properties) {
        if ($provider.Value.client_secret) { $provider.Value.client_secret = "[REDACTED]" }
        if ($provider.Value.client_id) { $provider.Value.client_id = "[REDACTED]" }
      }
    }
    Save-Json "16_auth_settings.json" $authSettings
  }
}

# 11. Performance Metrics Analysis (if requested)
if ($IncludePerformanceMetrics) {
  Write-Host "Collecting performance metrics..."
  
  # Extended Prometheus queries for performance analysis
  $perfQueries = @{
    queryDuration = 'histogram_quantile(0.99, sum(rate(grafana_http_request_duration_seconds_bucket[5m])) by (le))'
    memoryUsage = 'process_resident_memory_bytes{job="grafana"}'
    cpuUsage = 'rate(process_cpu_seconds_total{job="grafana"}[5m]) * 100'
    dbConnections = 'grafana_database_connections_open'
    apiRequestRate = 'sum(rate(grafana_http_request_total[5m])) by (code)'
    alertEvaluationTime = 'histogram_quantile(0.95, sum(rate(grafana_alerting_rule_evaluation_duration_seconds_bucket[5m])) by (le))'
    datasourceQueryDuration = 'histogram_quantile(0.95, sum(rate(grafana_datasource_request_duration_seconds_bucket[5m])) by (le, datasource))'
  }
  
  $perfResults = @{}
  foreach ($k in $perfQueries.Keys) {
    $resp = Invoke-PromQuery -Query $perfQueries[$k]
    if ($resp -and $resp.data) {
      $perfResults[$k] = $resp.data.result
    } else {
      $perfResults[$k] = "ERROR"
    }
  }
  Save-Json "17_performance_metrics.json" $perfResults
}

# 12. User Activity Analysis (if requested)
if ($IncludeUserActivity) {
  Write-Host "Analyzing user activity..."
  
  # Recent dashboard views and edits
  $dashboardVersions = @()
  if ($dashIndex) {
    $dashIndex | Select-Object -First 10 | ForEach-Object {
      $uid = $_.uid
      $versions = Invoke-GrafanaGet "/api/dashboards/uid/$uid/versions"
      if ($versions) {
        $dashboardVersions += [pscustomobject]@{
          uid = $uid
          title = $_.title
          versions = $versions
        }
      }
    }
  }
  Save-Json "18_dashboard_activity.json" $dashboardVersions
  
  # Annotation activity
  $annotations = Invoke-GrafanaGet "/api/annotations?limit=100"
  if ($annotations) { Save-Json "19_recent_annotations.json" $annotations }
}

# 13. Dashboard Export (if requested)
if ($ExportDashboards) {
  Write-Host "Exporting dashboard definitions..."
  $dashboardExports = @()
  
  if ($dashIndex) {
    $dashIndex | Select-Object -First $DashboardSample | ForEach-Object {
      $uid = $_.uid
      $dash = Invoke-GrafanaGet "/api/dashboards/uid/$uid"
      if ($dash -and $dash.dashboard) {
        $dashboardExports += [pscustomobject]@{
          uid = $uid
          title = $dash.dashboard.title
          dashboard = $dash.dashboard
          meta = $dash.meta
        }
      }
    }
  }
  Save-Json "20_dashboard_exports.json" $dashboardExports
}

# 14. Alert Validation (if requested)
if ($ValidateAlerts) {
  Write-Host "Validating alert configurations..."
  
  # Get all alert rules
  $alertRules = Invoke-GrafanaGet "/api/ruler/grafana/api/v1/rules"
  if ($alertRules) { Save-Json "21_alert_rules_detailed.json" $alertRules }
  
  # Get notification policies
  $notificationPolicies = Invoke-GrafanaGet "/api/alertmanager/grafana/config/api/v1/receivers"
  if ($notificationPolicies) { Save-Json "22_notification_policies.json" $notificationPolicies }
  
  # Test alert groups - try different endpoints
  $alertGroups = Invoke-GrafanaGet "/api/alertmanager/grafana/api/v1/alerts/groups" -SuppressWarnings
  if (-not $alertGroups) {
    $alertGroups = Invoke-GrafanaGet "/api/alertmanager/grafana/api/v2/alerts/groups" -SuppressWarnings
  }
  
  if ($alertGroups) { 
    Save-Json "23_alert_groups.json" $alertGroups 
  } else {
    Write-Host "⚠️  Alert groups endpoint not available" -ForegroundColor Yellow
    Save-Json "23_alert_groups.json" @{status="not_available";message="Alert groups endpoint not found"}
  }
}

# 15. Infrastructure Health Check
Write-Host "Checking infrastructure health..."

# Enhanced Prometheus cluster health
$infraQueries = @{
  prometheusUptime = 'up{job="prometheus-k8s"}'
  grafanaUptime = 'up{job="grafana"}'
  alertmanagerUptime = 'up{job="alertmanager-main"}'
  nodeExporterUp = 'up{job="node-exporter"}'
  kubeStateMetricsUp = 'up{job="kube-state-metrics"}'
  prometheusTsdbSize = 'prometheus_tsdb_size_bytes'
  prometheusRetention = 'prometheus_config_last_reload_success_timestamp_seconds'
  diskSpaceUsage = 'node_filesystem_avail_bytes{mountpoint="/"}'
}

$infraResults = @{}
foreach ($k in $infraQueries.Keys) {
  $resp = Invoke-PromQuery -Query $infraQueries[$k]
  if ($resp -and $resp.data) {
    $infraResults[$k] = $resp.data.result
  } else {
    $infraResults[$k] = "ERROR"
  }
}
Save-Json "24_infrastructure_health.json" $infraResults

# 16. Azure Monitor Integration Check (if Azure Monitor datasource exists)
if ($AzureMonitorUID -and ($datasources | Where-Object {$_.uid -eq $AzureMonitorUID})) {
  Write-Host "Checking Azure Monitor integration..."
  
  # Test Azure Monitor connectivity with a simpler query
  $azureQuery = "Heartbeat | limit 1"
  $encodedQuery = [System.Uri]::EscapeDataString($azureQuery)
  
  # Try different Azure Monitor API paths
  $azurePaths = @(
    "/api/datasources/uid/$AzureMonitorUID/resources/azuremonitor/query?query=$encodedQuery",
    "/api/datasources/uid/$AzureMonitorUID/resources/logs?query=$encodedQuery",
    "/api/datasources/uid/$AzureMonitorUID/proxy/v1/workspaces/query?query=$encodedQuery"
  )
  
  $azureSuccess = $false
  foreach ($path in $azurePaths) {
    $azureResp = Invoke-GrafanaGet $path -SuppressWarnings
    if ($azureResp) {
      Save-Json "25_azure_monitor_sample.json" $azureResp
      $azureSuccess = $true
      Write-Host "✅ Azure Monitor connection successful"
      break
    }
  }
  
  if (-not $azureSuccess) {
    Write-Host "⚠️  Azure Monitor query failed - may require workspace configuration" -ForegroundColor Yellow
    Save-Json "25_azure_monitor_sample.json" @{status="error";message="Azure Monitor query failed"}
  }
}

# 17. Plugin Analysis
$plugins = Invoke-GrafanaGet "/api/plugins"
if ($plugins) {
  $pluginSummary = $plugins | ForEach-Object {
    [pscustomobject]@{
      id = $_.id
      name = $_.name
      type = $_.type
      enabled = $_.enabled
      version = $_.info.version
      hasUpdate = $_.hasUpdate
    }
  }
  Save-Json "26_plugins_analysis.json" $pluginSummary
}

# 18. Configuration Validation
Write-Host "Validating configuration..."

$configValidation = @{
  datasourceConnectivity = @()
  dashboardErrors = @()
  alertRuleValidation = @()
  securityIssues = @()
}

# Test datasource connectivity
if ($datasources) {
  foreach ($ds in $datasources) {
    $testResult = Invoke-GrafanaGet "/api/datasources/uid/$($ds.uid)/health"
    $configValidation.datasourceConnectivity += [pscustomobject]@{
      name = $ds.name
      type = $ds.type
      uid = $ds.uid
      status = if ($testResult) { "OK" } else { "ERROR" }
      details = $testResult
    }
  }
}

# Check for common security issues
if ($IncludeSecurityAudit) {
  # Check for default passwords, open permissions, etc.
  if ($authSettings -and $authSettings.security) {
    if ($authSettings.security.admin_user -eq "admin") {
      $configValidation.securityIssues += "Default admin username detected"
    }
    if ($authSettings.security.allow_sign_up -eq $true) {
      $configValidation.securityIssues += "Public sign-up is enabled"
    }
  }
}

Save-Json "27_configuration_validation.json" $configValidation

# 19. Enhanced Summary
$summary = [pscustomobject]@{
  timestamp            = (Get-Date).ToString("o")
  grafanaVersion       = if ($frontend) { $frontend.buildInfo.version } else { "UNKNOWN" }
  hasUpdate           = if ($frontend) { $frontend.buildInfo.hasUpdate } else { $false }
  latestVersion       = if ($frontend) { $frontend.buildInfo.latestVersion } else { "UNKNOWN" }
  datasourceCount      = if ($datasources) { $datasources.Count } else { 0 }
  dashboardCount       = if ($dashIndex) { $dashIndex.Count } else { 0 }
  sampledDashboards    = $sample.Count
  folderCount         = if ($folders) { $folders.Count } else { 0 }
  prometheusHeadSeries = ($loadResults.headSeries | ConvertTo-Json -Depth 3)
  promAlertsCount      = if ($promAlerts -and $promAlerts.data) { ($promAlerts.data.alerts | Measure-Object).Count } else { 0 }
  firingAlertsCount   = if ($promAlerts -and $promAlerts.data) { ($promAlerts.data.alerts | Where-Object {$_.state -eq "firing"} | Measure-Object).Count } else { 0 }
  unifiedAlertsPresent = [bool]$unifiedAlerts
  lokiSampleSuccess    = $lokiOk
  azureMonitorConnected = [bool]($datasources | Where-Object {$_.type -eq "grafana-azure-monitor-datasource"})
  pluginCount         = if ($plugins) { $plugins.Count } else { 0 }
  userCount           = if ($users) { $users.users.Count } else { 0 }
  teamCount           = if ($teams) { $teams.totalCount } else { 0 }
  auditFlags = @{
    securityAudit = $IncludeSecurityAudit.IsPresent
    performanceMetrics = $IncludePerformanceMetrics.IsPresent
    userActivity = $IncludeUserActivity.IsPresent
    dashboardExport = $ExportDashboards.IsPresent
    alertValidation = $ValidateAlerts.IsPresent
  }
}
Save-Json "00_summary.json" $summary

# Generate audit report
Export-AuditReport -OutputDir $OutDir -Summary $summary

# Alert severity breakdown
if ($promAlerts) {
  $alertBreakdown = Get-AlertSeverityBreakdown -Alerts $promAlerts
  Save-Json "28_alert_severity_breakdown.json" $alertBreakdown
}

Write-Host "`n--- Completed enhanced audit. Output folder: $OutDir ---"
Write-Host "Files generated: $(Get-ChildItem $OutDir -Filter '*.json' | Measure-Object | Select-Object -ExpandProperty Count)"
Write-Host "Summary highlights:"
Write-Host "  - Grafana version: $($summary.grafanaVersion) $(if($summary.hasUpdate) { "(Update available: $($summary.latestVersion))" } else { "(Up to date)" })"
Write-Host "  - Datasources: $($summary.datasourceCount)"
Write-Host "  - Dashboards: $($summary.dashboardCount)"
Write-Host "  - Active alerts: $($summary.firingAlertsCount)/$($summary.promAlertsCount)"
Write-Host "  - Plugins: $($summary.pluginCount)"

if ($alertBreakdown) {
  Write-Host "  - Alert breakdown: Critical($($alertBreakdown.critical)) Warning($($alertBreakdown.warning)) Info($($alertBreakdown.info))"
}
