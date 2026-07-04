param(
    [Parameter(Mandatory = $true)]
    [string]$ImagePath
)

$ErrorActionPreference = "Stop"
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

Add-Type -AssemblyName System.Runtime.WindowsRuntime

$asTaskMethod = @(
    [System.WindowsRuntimeSystemExtensions].GetMethods() |
        Where-Object {
            $_.Name -eq "AsTask" -and
            $_.IsGenericMethod -and
            $_.GetParameters().Count -eq 1
        }
)[0]

function Wait-WinRtResult {
    param($Operation, [Type]$ResultType)
    $method = $asTaskMethod.MakeGenericMethod($ResultType)
    $task = $method.Invoke($null, @($Operation))
    if (-not $task.Wait(15000)) {
        throw "Windows OCR operation timed out"
    }
    return $task.Result
}

$storageFileType = [Windows.Storage.StorageFile, Windows.Storage, ContentType = WindowsRuntime]
$streamType = [Windows.Storage.Streams.IRandomAccessStream, Windows.Storage.Streams, ContentType = WindowsRuntime]
$decoderType = [Windows.Graphics.Imaging.BitmapDecoder, Windows.Graphics.Imaging, ContentType = WindowsRuntime]
$bitmapType = [Windows.Graphics.Imaging.SoftwareBitmap, Windows.Graphics.Imaging, ContentType = WindowsRuntime]
$ocrEngineType = [Windows.Media.Ocr.OcrEngine, Windows.Foundation, ContentType = WindowsRuntime]
$ocrResultType = [Windows.Media.Ocr.OcrResult, Windows.Foundation, ContentType = WindowsRuntime]

$file = Wait-WinRtResult ($storageFileType::GetFileFromPathAsync((Resolve-Path -LiteralPath $ImagePath).Path)) $storageFileType
$stream = Wait-WinRtResult ($file.OpenAsync([Windows.Storage.FileAccessMode]::Read)) $streamType
$decoder = Wait-WinRtResult ($decoderType::CreateAsync($stream)) $decoderType
$bitmap = Wait-WinRtResult ($decoder.GetSoftwareBitmapAsync()) $bitmapType
$engine = $ocrEngineType::TryCreateFromUserProfileLanguages()
if ($null -eq $engine) {
    throw "No Windows OCR language is available for the current user profile"
}
$result = Wait-WinRtResult ($engine.RecognizeAsync($bitmap)) $ocrResultType

$lines = @()
foreach ($line in $result.Lines) {
    $words = @()
    foreach ($word in $line.Words) {
        $rect = $word.BoundingRect
        $words += [ordered]@{
            text = $word.Text
            region = @([double]$rect.X, [double]$rect.Y, [double]$rect.Width, [double]$rect.Height)
        }
    }
    $lines += [ordered]@{
        text = $line.Text
        words = $words
    }
}

[ordered]@{
    available = $true
    backend = "windows-media-ocr"
    language = $engine.RecognizerLanguage.LanguageTag
    text = $result.Text
    lines = $lines
} | ConvertTo-Json -Depth 8 -Compress
