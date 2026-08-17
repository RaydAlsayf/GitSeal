param([string]$Output = "dist")
$ErrorActionPreference = "Stop"
$controlledNames = @(
  "GO111MODULE", "GOENV", "GOFLAGS", "GONOPROXY", "GONOSUMDB",
  "GOPRIVATE", "GOPROXY", "GOSUMDB", "GOTOOLCHAIN", "GOWORK",
  "GOAMD64", "GOARM64", "CGO_ENABLED", "GOOS", "GOARCH", "GODEBUG",
  "GOROOT", "GOEXPERIMENT", "GOFIPS140",
  "SOURCE_DATE_EPOCH", "TZ"
)
$poisonedGitNames = @(
  "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR",
  "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
  "GIT_CONFIG", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_NOSYSTEM",
  "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS", "GIT_IMPLICIT_WORK_TREE",
  "GIT_GRAFT_FILE", "GIT_NO_REPLACE_OBJECTS", "GIT_REPLACE_REF_BASE",
  "GIT_PREFIX", "GIT_SHALLOW_FILE", "GIT_NAMESPACE", "GIT_REFERENCE_BACKEND",
  "GIT_DEFAULT_HASH", "GIT_DEFAULT_REF_FORMAT", "GIT_INDEX_VERSION",
  "GIT_LITERAL_PATHSPECS", "GIT_GLOB_PATHSPECS", "GIT_NOGLOB_PATHSPECS",
  "GIT_ICASE_PATHSPECS", "GIT_ATTR_SOURCE", "GIT_ATTR_NOSYSTEM",
  "GIT_ATTR_GLOBAL", "GIT_ATTR_SYSTEM", "GIT_QUARANTINE_PATH", "GIT_NO_LAZY_FETCH",
  "GIT_EXEC_PATH", "GIT_CEILING_DIRECTORIES", "GIT_DISCOVERY_ACROSS_FILESYSTEM"
)
$dynamicGitNames = @(Get-ChildItem Env: | Where-Object {
  $_.Name -match '^GIT_CONFIG_(KEY|VALUE)_[^=]+$'
} | ForEach-Object { $_.Name })
$poisonedGitNames += $dynamicGitNames
foreach ($name in $poisonedGitNames) {
  if (-not [string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable($name))) {
    throw "ambiguous Git authority environment is forbidden for review builds: $name"
  }
}
$savedEnvironment = @{}
foreach ($name in ($controlledNames + $poisonedGitNames)) {
  $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name)
}
foreach ($name in $poisonedGitNames) {
  Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
}
$env:GIT_CONFIG_GLOBAL = "NUL"
$env:GIT_CONFIG_SYSTEM = "NUL"
$env:GIT_CONFIG_NOSYSTEM = "1"
$env:GIT_ATTR_NOSYSTEM = "1"
$env:GIT_NO_LAZY_FETCH = "1"

$env:GO111MODULE = "on"
$env:GODEBUG = ""
$env:GOENV = "off"
$env:GOFLAGS = "-mod=readonly"
$env:GONOPROXY = ""
$env:GONOSUMDB = ""
$env:GOPRIVATE = ""
$env:GOPROXY = "off"
$env:GOSUMDB = "sum.golang.org"
$env:GOTOOLCHAIN = "local"
$env:GOWORK = "off"
$env:GOAMD64 = "v1"
$env:GOARM64 = "v8.0"
$env:CGO_ENABLED = "0"
$env:TZ = "UTC"
Remove-Item -LiteralPath Env:GOROOT, Env:GOEXPERIMENT, Env:GOFIPS140 -ErrorAction SilentlyContinue

$git = (Get-Command git -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
$go = (Get-Command go -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source

$root = (& $git --no-pager --no-optional-locks --no-replace-objects -c core.fsmonitor=false rev-parse --show-toplevel).Trim()
if ($LASTEXITCODE -ne 0 -or -not $root) { throw "repository root is unavailable" }
Push-Location -LiteralPath $root

$targets = @("linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64", "windows/amd64", "windows/arm64")
try {
  $revision = (& $git --no-pager --no-optional-locks --no-replace-objects -c core.fsmonitor=false rev-parse --verify "HEAD^{commit}").Trim()
  if ($LASTEXITCODE -ne 0 -or -not $revision) { throw "source revision is unavailable" }

  $status = & $git --no-pager --no-optional-locks --no-replace-objects -c core.fsmonitor=false status --porcelain=v1 --untracked-files=all --ignored=matching
  if ($LASTEXITCODE -ne 0) { throw "source status is unavailable" }
  if ($status) { throw "source tree has modified, untracked, or ignored files; refusing build" }

  $goVersion = (& $go env GOVERSION).Trim()
  if ($LASTEXITCODE -ne 0 -or $goVersion -ne "go1.26.6") { throw "the exact Go 1.26.6 toolchain is required" }

  $module = (& $go mod edit -json | ConvertFrom-Json)
  if ($LASTEXITCODE -ne 0) { throw "go.mod could not be inspected" }
  if ($null -ne $module.Replace) { throw "module replacements are forbidden in a release build" }

  & $go mod verify
  if ($LASTEXITCODE -ne 0) { throw "module verification failed" }
  & $go list -mod=readonly -deps ./cmd/gitseal | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "the offline production dependency graph is incomplete" }

  $env:SOURCE_DATE_EPOCH = (& $git --no-pager --no-optional-locks --no-replace-objects -c core.fsmonitor=false show -s --format=%ct $revision).Trim()
  if ($LASTEXITCODE -ne 0 -or -not $env:SOURCE_DATE_EPOCH) { throw "source epoch is unavailable" }

  if (Test-Path -LiteralPath $Output) { throw "output path already exists: $Output" }
  New-Item -ItemType Directory -Path $Output | Out-Null

  foreach ($target in $targets) {
    $parts = $target.Split("/")
    $env:GOOS = $parts[0]
    $env:GOARCH = $parts[1]
    $env:CGO_ENABLED = "0"
    $suffix = if ($env:GOOS -eq "windows") { ".exe" } else { "" }
    $destination = Join-Path $Output "gitseal_$($env:GOOS)_$($env:GOARCH)$suffix"
    & $go build -mod=readonly -trimpath -buildvcs=false -ldflags "-buildid= -X github.com/raydalsayf/gitseal/internal/cli.SourceRevision=$revision" -o $destination ./cmd/gitseal
    if ($LASTEXITCODE -ne 0) { throw "build failed for $target" }
  }

  Copy-Item -LiteralPath @("LICENSE", "THIRD_PARTY_NOTICES.md") -Destination $Output
  $artifactNames = @(
    "LICENSE", "THIRD_PARTY_NOTICES.md",
    "gitseal_darwin_amd64", "gitseal_darwin_arm64",
    "gitseal_linux_amd64", "gitseal_linux_arm64",
    "gitseal_windows_amd64.exe", "gitseal_windows_arm64.exe"
  )
  $lines = $artifactNames | ForEach-Object {
    $artifact = Get-Item -LiteralPath (Join-Path $Output $_)
    $sum = (Get-FileHash -Algorithm SHA256 -LiteralPath $artifact.FullName).Hash.ToLowerInvariant()
    "$sum  $($artifact.Name)"
  }
  $ascii = New-Object System.Text.ASCIIEncoding
  [System.IO.File]::WriteAllText((Join-Path $Output "SHA256SUMS"), (($lines -join "`n") + "`n"), $ascii)
} finally {
  Pop-Location
  foreach ($name in ($controlledNames + $poisonedGitNames)) {
    $value = $savedEnvironment[$name]
    if ($null -eq $value) {
      Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
    } else {
      [Environment]::SetEnvironmentVariable($name, $value)
    }
  }
}
