@echo on
:: ============================================================================
:: SCRIPT DE INYECCION MITM EN ANDROID 15 (MODULO APEX) - MODO DETALLADO
:: ============================================================================

echo.
echo === [FASE 1/4] INICIANDO EMULADOR CON PERMISOS DE ESCRITURA ===
start "" "C:\Users\prval\AppData\Local\Android\Sdk\emulator\emulator.exe" -avd Lab_TFM -writable-system -no-snapshot-load

echo.
echo === [FASE 2/4] ESPERANDO CONEXION ADB Y ARRANQUE DEL SISTEMA ===
adb wait-for-device
timeout /t 35 /nobreak

echo.
echo === [FASE 3/4] ESCALANDO A ROOT Y MONTANDO MEMORIA TMPFS EN APEX ===
adb root
timeout /t 3 /nobreak

adb push 9a5ba575.0 /data/local/tmp/
adb shell "mkdir -p /data/local/tmp/certs"
adb shell "cp /apex/com.android.conscrypt/cacerts/* /data/local/tmp/certs/"
adb shell "mount -t tmpfs tmpfs /apex/com.android.conscrypt/cacerts"
adb shell "cp /data/local/tmp/certs/* /apex/com.android.conscrypt/cacerts/"
adb shell "cp /data/local/tmp/9a5ba575.0 /apex/com.android.conscrypt/cacerts/"
adb shell "chown root:root /apex/com.android.conscrypt/cacerts/*"
adb shell "chmod 644 /apex/com.android.conscrypt/cacerts/*"
adb shell "chcon u:object_r:system_file:s0 /apex/com.android.conscrypt/cacerts/*"

echo.
echo === [VERIFICACION] COMPROBANDO ARCHIVO INYECTADO EN EL CONTENEDOR ===
adb shell "ls -laZ /apex/com.android.conscrypt/cacerts/9a5ba575.0"

echo.
echo === [FASE 4/4] REINICIANDO SERVICIOS INTERNOS (SOFT REBOOT) ===
adb shell stop
adb shell start

echo.
echo === PROCESO FINALIZADO. REVISA LAS SALIDAS SUPERIORES ===
pause