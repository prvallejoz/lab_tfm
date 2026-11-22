@echo on
:: ============================================================================
:: SCRIPT DE ARRANQUE DE SNAPSHOT BASE LIMPIO - ANDROID 13 (API 33)
:: ============================================================================

:: --- VARIABLES DE CONFIGURACION ---
set "AVD_NAME=Lab_TFM_API33"
set "SNAPSHOT_NAME=snapshot_base_limpio"
set "EMULATOR_PATH=C:\Users\prval\AppData\Local\Android\Sdk\emulator\emulator.exe"
set "CERT_FILENAME=9a5ba575.0"
set "PROXY_IP=192.168.0.96:8080"

echo.
echo === [FASE 1/3] INICIANDO EMULADOR DESDE SNAPSHOT BASE LIMPIO (%SNAPSHOT_NAME%) ===
:: -writable-system mantiene la capa donde esta el certificado CA
:: -snapshot restaura el estado limpio y -no-snapshot-save evita sobrescribirlo al cerrar
start "Emulador_Limpio" "%EMULATOR_PATH%" -avd %AVD_NAME% -writable-system -snapshot %SNAPSHOT_NAME% -no-snapshot-save

echo.
echo === [FASE 2/3] ESPERANDO CONEXION ADB Y ESTABILIZACION DEL SISTEMA ===
adb start-server
adb wait-for-device
timeout /t 15 /nobreak

echo.
echo === [FASE 3/3] VERIFICANDO CERTIFICADO DE SISTEMA Y CONFIGURANDO PROXY ===
adb root
timeout /t 2 /nobreak
adb shell settings put global http_proxy %PROXY_IP%

echo.
echo --- VERIFICACION FINAL DEL ENTORNO LIMPIO ---
adb shell "ls -laZ /system/etc/security/cacerts/%CERT_FILENAME%"
adb shell settings get global http_proxy

echo.
echo === EMULADOR EN SNAPSHOT BASE LIMPIO LISTO PARA PRUEBAS ===
pause