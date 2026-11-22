# Carpeta principal donde se guardarán los APKs
$carpetaPrincipal = ".\apks"

# Crear la carpeta principal si no existe
if (-not (Test-Path $carpetaPrincipal)) {
    New-Item -ItemType Directory -Path $carpetaPrincipal | Out-Null
}

# Obtener la lista de paquetes de terceros (-3)
Write-Host "Obteniendo lista de aplicaciones..." -ForegroundColor Cyan
$paquetes = adb shell pm list packages -3 | ForEach-Object {
    ($_ -replace "^package:", "").Trim()
} | Where-Object { $_ -ne "" }

if ($paquetes.Count -eq 0) {
    Write-Host "No se encontraron aplicaciones de terceros o no hay ningún emulador conectado." -ForegroundColor Red
    exit
}

Write-Host "Se encontraron $($paquetes.Count) aplicaciones. Iniciando extracción...`n" -ForegroundColor Green

foreach ($pkg in $paquetes) {
    Write-Host "Extrayendo: $pkg" -ForegroundColor Yellow
    
    # Crear subcarpeta con el nombre del paquete (ej. .\apks\com.duolingo)
    $carpetaApp = Join-Path $carpetaPrincipal $pkg
    if (-not (Test-Path $carpetaApp)) {
        New-Item -ItemType Directory -Path $carpetaApp | Out-Null
    }

    # Obtener todas las rutas de los .apk de la aplicación (base + splits)
    $rutasApk = adb shell pm path $pkg | ForEach-Object {
        ($_ -replace "^package:", "").Trim()
    } | Where-Object { $_ -ne "" }

    # Descargar cada archivo .apk en su respectiva subcarpeta
    foreach ($ruta in $rutasApk) {
        adb pull "$ruta" "$carpetaApp\"
    }
}

Write-Host "`n¡Extracción completada! Los archivos están en $carpetaPrincipal" -ForegroundColor Green