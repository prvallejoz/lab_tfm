@echo off
echo === [1/3] INICIANDO EMULADOR ANDROID 13 (API 33) ===
start "Emulador_API33" "C:\Users\prval\AppData\Local\Android\Sdk\emulator\emulator.exe" -avd TFM -writable-system

echo === [2/3] ESPERANDO CONEXION ADB ===
adb start-server
adb wait-for-device
timeout /t 20 /nobreak > NUL

echo === [3/3] VERIFICANDO CERTIFICADO Y PROXY GLOBAL ===
adb shell settings put global http_proxy 192.168.0.96:8080
adb shell "ls -la /system/etc/security/cacerts/9a5ba575.0"
adb shell settings get global http_proxy

echo === LABORATORIO API 33 LISTO ===
pause