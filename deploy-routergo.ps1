param(
    [string]$KubeConfigPath = "C:\Users\qmish\.kube\fb\config"
)

$ErrorActionPreference = "Stop"
$env:KUBECONFIG = $KubeConfigPath

Write-Host "Applying base manifest..."
kubectl apply -f ".\k8s-routergo.yaml"

Write-Host "Applying ops manifest..."
kubectl apply -f ".\k8s-routergo-ops.yaml"

Write-Host "Restarting deployment..."
kubectl -n routergo rollout restart deployment/routergo

Write-Host "Waiting rollout..."
kubectl -n routergo rollout status deployment/routergo --timeout=240s

Write-Host "Current objects:"
kubectl -n routergo get deploy routergo
kubectl -n routergo get svc routergo
kubectl -n routergo get hpa routergo-hpa
kubectl -n routergo get pdb routergo-pdb
