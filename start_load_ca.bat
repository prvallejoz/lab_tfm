@echo on
:: ============================================================================
:: SCRIPT DE ARRANQUE Y CONFIGURACION MITM DIRECTO - ANDROID 13 (API 33)
:: ============================================================================

:: --- VARIABLES DE CONFIGURACION (Ingresa aqui el nombre exacto de tu archivo y AVD) ---
set "AVD_NAME=Lab_TFM_API33"
set "EMULATOR_PATH=C:\Users\prval\AppData\Local\Android\Sdk\emulator\emulator.exe"
set "CERT_FILENAME=9a5ba575.0"
set "PROXY_IP=192.168.0.96:8080"

set "CERT_PATH=%~dp0%CERT_FILENAME%"

echo.
echo === [FASE 1/5] VERIFICANDO EXISTENCIA DEL CERTIFICADO LOCAL ===
if not exist "%CERT_PATH%" (
    echo [ERROR] No se encontro "%CERT_PATH%". Verifica el nombre en CERT_FILENAME.
    pause
    exit /b 1
)
echo [INFO] Archivo encontrado: %CERT_PATH%

echo.
echo === [FASE 2/5] INICIANDO EMULADOR ANDROID 13 EN MODO ESCRIBIBLE ===
start "Emulador_API33" "%EMULATOR_PATH%" -avd %AVD_NAME% -writable-system

echo.
echo === [FASE 3/5] ESPERANDO CONEXION ADB Y ARRANQUE DEL SISTEMA ===
adb start-server
adb wait-for-device
timeout /t 30 /nobreak

echo.
echo === [FASE 4/5] VERIFICANDO ESTADO DE OVERLAYFS E INYECTANDO CERTIFICADO ===
adb root
timeout /t 3 /nobreak

:: Comprueba si el certificado ya esta instalado en /system/etc/security/cacerts/
adb shell "ls /system/etc/security/cacerts/%CERT_FILENAME%" >nul 2>&1
if %errorlevel% equ 0 (
    echo [INFO] El certificado %CERT_FILENAME% ya existe en /system. Saltando inyeccion...
    goto CONFIG_PROXY
)

:: Monta /system en lectura/escritura y gestiona el reinicio de overlayfs si es primer arranque
echo [INFO] Ejecutando adb remount...
adb remount > "%TEMP%\remount_out.txt" 2>&1
type "%TEMP%\remount_out.txt"

findstr /I /C:"reboot your device" "%TEMP%\remount_out.txt" >nul 2>&1
if %errorlevel% equ 0 (
    echo [INFO] Primer arranque limpio detectado: reiniciando para activar overlayfs...
    adb reboot
    adb wait-for-device
    timeout /t 25 /nobreak
    adb root
    timeout /t 3 /nobreak
    adb remount
)

echo [INFO] Transfiriendo %CERT_FILENAME% y aplicando permisos / SELinux...
adb push "%CERT_PATH%" /system/etc/security/cacerts/
adb shell "chown root:root /system/etc/security/cacerts/%CERT_FILENAME%"
adb shell "chmod 644 /system/etc/security/cacerts/%CERT_FILENAME%"
adb shell "chcon u:object_r:system_file:s0 /system/etc/security/cacerts/%CERT_FILENAME%"

echo [INFO] Reiniciando emulador para cargar el nuevo certificado del sistema...
adb reboot
adb wait-for-device
timeout /t 25 /nobreak
adb root
timeout /t 2 /nobreak

:CONFIG_PROXY
echo.
echo === [FASE 5/5] CONFIGURANDO PROXY GLOBAL Y VERIFICANDO ===
adb shell settings put global http_proxy %PROXY_IP%

echo.
echo --- VERIFICACION FINAL ---
adb shell "head -n 1 /system/etc/security/cacerts/%CERT_FILENAME%"
adb shell "ls -laZ /system/etc/security/cacerts/%CERT_FILENAME%"
adb shell settings get global http_proxy

echo.
echo === LABORATORIO ANDROID 13 LISTO ===
pause