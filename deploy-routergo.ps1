param(
    [string]$KubeConfigPath = "C:\Users\qmish\.kube\fb\config"
)

$ErrorActionPreference = "Stop"
$env:KUBECONFIG = $KubeConfigPath

function Invoke-Kubectl {
    param([string[]]$ArgsLine)
    & kubectl @ArgsLine
    if ($LASTEXITCODE -ne 0) {
        throw "kubectl command failed: kubectl $($ArgsLine -join ' ')"
    }
}

Write-Host "Applying base manifest..."
Invoke-Kubectl @("apply", "-f", ".\k8s-routergo.yaml")

Write-Host "Applying ops manifest..."
Invoke-Kubectl @("apply", "-f", ".\k8s-routergo-ops.yaml")

Write-Host "Applying ingress manifest..."
Invoke-Kubectl @("apply", "-f", ".\k8s-routergo-ingress.yaml")

Write-Host "Restarting deployment..."
Invoke-Kubectl @("-n", "routergo", "rollout", "restart", "deployment/routergo")

Write-Host "Waiting rollout..."
& kubectl -n routergo rollout status deployment/routergo --timeout=240s
if ($LASTEXITCODE -ne 0) {
    Write-Warning "rollout status timed out, checking deployment availability and cleaning stale pods..."
    $ready = (& kubectl -n routergo get deploy routergo -o jsonpath='{.status.availableReplicas}')
    if (-not $ready) {
        $ready = "0"
    }
    if ([int]$ready -lt 1) {
        throw "Deployment routergo is not available after rollout timeout."
    }
    & kubectl -n routergo delete pod --field-selector=status.phase=Unknown --force --grace-period=0
}

Write-Host "Current objects:"
Invoke-Kubectl @("-n", "routergo", "get", "deploy", "routergo")
Invoke-Kubectl @("-n", "routergo", "get", "svc", "routergo")
Invoke-Kubectl @("-n", "routergo", "get", "hpa", "routergo-hpa")
Invoke-Kubectl @("-n", "routergo", "get", "pdb", "routergo-pdb")
Invoke-Kubectl @("-n", "routergo", "get", "ingress", "routergo")

$nodePort = (& kubectl -n routergo get svc routergo -o jsonpath='{.spec.ports[0].nodePort}')
if ($nodePort) {
    Write-Host "NodePort access: http://<node-ip>:$nodePort/dashboard"
}
