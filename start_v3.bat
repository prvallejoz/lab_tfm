@echo off
:: ============================================================================
:: SCRIPT DE INYECCION MITM Y PROXY GLOBAL EN ANDROID 15 (MODULO APEX)
:: ============================================================================

echo.
echo === [FASE 1/5] INICIANDO EMULADOR EN MODO ESCRIBIBLE Y ARRANQUE LIMPIO ===
start "Emulador_AVD" "C:\Users\prval\AppData\Local\Android\Sdk\emulator\emulator.exe" -avd Lab_TFM -writable-system -no-snapshot-load

echo.
echo === [FASE 2/5] ESPERANDO CONEXION ADB Y ARRANQUE COMPLETO DEL SISTEMA ===
adb start-server
adb wait-for-device
timeout /t 35 /nobreak

echo.
echo === [FASE 3/5] ESCALANDO A ROOT Y PREPARANDO CERTIFICADO EN /data/local/tmp ===
adb root
timeout /t 3 /nobreak

adb push "%~dp09a5ba575.0" /data/local/tmp/
adb shell "mkdir -p /data/local/tmp/certs"
adb shell "cp /apex/com.android.conscrypt/cacerts/* /data/local/tmp/certs/"

echo.
echo === [FASE 4/5] MONTANDO TMPFS EN PID 1 (INIT) Y PROPAGANDO A ZYGOTE ===
adb shell sh -c 'nsenter --mount=/proc/1/ns/mnt -- mount -t tmpfs tmpfs /apex/com.android.conscrypt/cacerts && cp /data/local/tmp/certs/* /apex/com.android.conscrypt/cacerts/ && cp /data/local/tmp/9a5ba575.0 /apex/com.android.conscrypt/cacerts/ && chown root:root /apex/com.android.conscrypt/cacerts/* && chmod 644 /apex/com.android.conscrypt/cacerts/* && chcon u:object_r:system_file:s0 /apex/com.android.conscrypt/cacerts/*'

adb shell sh -c 'for p in $(pidof system_server zygote zygote64); do nsenter --mount=/proc/$p/ns/mnt -- mount --bind /apex/com.android.conscrypt/cacerts /apex/com.android.conscrypt/cacerts 2>/dev/null; done'

echo.
echo === [FASE 5/5] CONFIGURANDO PROXY GLOBAL HACIA BURP SUITE ===
adb shell settings put global http_proxy 192.168.0.96:8080

echo.
echo === [VERIFICACION] COMPROBANDO CERTIFICADO Y PROXY ACTIVO ===
adb shell "ls -laZ /apex/com.android.conscrypt/cacerts/9a5ba575.0"
adb shell settings get global http_proxy

echo.
echo === ENTORNO LISTO PARA INTERCEPCION ===
pause