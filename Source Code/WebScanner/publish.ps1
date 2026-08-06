# PowerShell script to publish self-contained single-file exe for Windows x64
param(
    [string]$configuration = "Release",
    [string]$runtime = "win-x64"
)

Write-Output "Publishing project as self-contained single-file ($runtime, $configuration)..."

dotnet publish WebScanner.csproj -c $configuration -r $runtime --self-contained true -p:PublishSingleFile=true -p:IncludeAllContentForSelfExtract=true -o ./publish

if ($LASTEXITCODE -ne 0) {
    Write-Error "dotnet publish failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}

Write-Output "Publish complete. Output folder: $(Resolve-Path ./publish)"