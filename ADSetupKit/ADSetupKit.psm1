$Private = Get-ChildItem -Path "$PSScriptRoot\Private" -Filter '*.ps1' -ErrorAction SilentlyContinue
foreach ($file in $Private) { . $file.FullName }
$Public = Get-ChildItem -Path "$PSScriptRoot\Public" -Filter '*.ps1' -ErrorAction SilentlyContinue
foreach ($file in $Public) { . $file.FullName }
