@echo on
:: ============================================================================
:: SCRIPT DE ARRANQUE Y CONFIGURACION MITM - ANDROID 13 (API 33) - WINDOWS CMD
:: ============================================================================

:: --- VARIABLES DE CONFIGURACION (Ajusta si tu AVD tiene otro nombre) ---
set "AVD_NAME=TFM"
set "EMULATOR_PATH=C:\Users\prval\AppData\Local\Android\Sdk\emulator\emulator.exe"
set "CERT_FILE=%~dp09a5ba575.0"
set "PROXY_IP=192.168.0.96:8080"

echo.
echo === [FASE 1/4] INICIANDO EMULADOR ANDROID 13 EN MODO ESCRIBIBLE ===
start "Emulador_API33" "%EMULATOR_PATH%" -avd %AVD_NAME% -writable-system

echo.
echo === [FASE 2/4] ESPERANDO CONEXION ADB Y ARRANQUE DEL SISTEMA ===
adb start-server
adb wait-for-device
timeout /t 30 /nobreak

echo.
echo === [FASE 3/4] VERIFICANDO ESTADO DEL CERTIFICADO CA DE BURP SUITE ===
adb root
timeout /t 3 /nobreak

:: Comprueba si el certificado ya existe en /system/etc/security/cacerts/
adb shell "ls /system/etc/security/cacerts/9a5ba575.0" >nul 2>&1
if %errorlevel% equ 0 (
    echo [INFO] El certificado 9a5ba575.0 ya esta instalado de forma permanente.
    goto CONFIG_PROXY
)

echo [INFO] Certificado no detectado. Iniciando instalacion permanente en /system...
adb remount
adb push "%CERT_FILE%" /system/etc/security/cacerts/
adb shell "chown root:root /system/etc/security/cacerts/9a5ba575.0"
adb shell "chmod 644 /system/etc/security/cacerts/9a5ba575.0"
adb shell "chcon u:object_r:system_file:s0 /system/etc/security/cacerts/9a5ba575.0"

echo [INFO] Reiniciando emulador para cargar el nuevo certificado del sistema...
adb reboot
adb wait-for-device
timeout /t 25 /nobreak
adb root
timeout /t 2 /nobreak

:CONFIG_PROXY
echo.
echo === [FASE 4/4] CONFIGURANDO PROXY GLOBAL Y VERIFICANDO ENTORNO ===
adb shell settings put global http_proxy %PROXY_IP%

echo.
echo --- VERIFICACION FINAL ---
adb shell "ls -laZ /system/etc/security/cacerts/9a5ba575.0"
adb shell settings get global http_proxy

echo.
echo === LABORATORIO ANDROID 13 LISTO PARA CAPTURA EN BURP SUITE ===
pause