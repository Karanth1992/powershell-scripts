# ADOpsKit.psm1
# Dot-source all private helpers first
$Private = Get-ChildItem -Path "$PSScriptRoot\Private" -Filter '*.ps1' -ErrorAction SilentlyContinue
foreach ($file in $Private) { . $file.FullName }

# Dot-source all public functions
$Public = Get-ChildItem -Path "$PSScriptRoot\Public" -Filter '*.ps1' -ErrorAction SilentlyContinue
foreach ($file in $Public) { . $file.FullName }
