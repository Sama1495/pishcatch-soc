# Download the public corpora used by the evaluation. Does not crawl message links.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
if (-not (Test-Path (Join-Path $Root "scripts"))) {
    $Root = Split-Path -Parent $PSScriptRoot
}
$Dest = Join-Path $Root "data\corpora"
New-Item -ItemType Directory -Force -Path $Dest | Out-Null

$Files = @(
    @{ Url = "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2"; Name = "easy_ham.tar.bz2"; Extract = $true },
    @{ Url = "https://spamassassin.apache.org/old/publiccorpus/20030228_hard_ham.tar.bz2"; Name = "hard_ham.tar.bz2"; Extract = $true },
    @{ Url = "https://monkey.org/~jose/phishing/phishing-2023"; Name = "nazario-phishing-2023.mbox"; Extract = $false },
    @{ Url = "https://monkey.org/~jose/phishing/LICENSE.txt"; Name = "nazario-LICENSE.txt"; Extract = $false },
    @{ Url = "https://monkey.org/~jose/phishing/README.txt"; Name = "nazario-README.txt"; Extract = $false }
)

foreach ($item in $Files) {
    $target = Join-Path $Dest $item.Name
    if ((Test-Path $target) -and ((Get-Item $target).Length -gt 0)) {
        Write-Host "keep $($item.Name)"
    } else {
        Write-Host "get $($item.Url)"
        Invoke-WebRequest -Uri $item.Url -OutFile $target -UseBasicParsing
    }
    if ($item.Extract) {
        $folder = if ($item.Name -like "*easy_ham*") { "easy_ham" } else { "hard_ham" }
        $extracted = Join-Path $Dest $folder
        if ((Test-Path $extracted) -and (Get-ChildItem $extracted -ErrorAction SilentlyContinue)) {
            Write-Host "keep extracted $folder"
        } else {
            Write-Host "extract $($item.Name)"
            tar -xjf $target -C $Dest
        }
    }
}

Write-Host "ready under $Dest"
Write-Host "These files are gitignored. Do not fetch URLs found inside the mail."
