@echo off
echo [1/4] Iniciando el emulador con sistema escribible...
start "" "C:\Users\prval\AppData\Local\Android\Sdk\emulator\emulator.exe" -avd Lab-TFM -writable-system -gpu swiftshader_indirect

echo [2/4] Esperando a que el sistema Android cargue...
adb wait-for-device
timeout /t 25 /nobreak > NUL

echo [3/4] Escalando privilegios e inyectando CA en modulo APEX...
adb root
timeout /t 3 /nobreak > NUL
adb push 9a5ba575.0 /data/local/tmp/
adb shell "mkdir -p /data/local/tmp/certs"
adb shell "cp /apex/com.android.conscrypt/cacerts/* /data/local/tmp/certs/"
adb shell "mount -t tmpfs tmpfs /apex/com.android.conscrypt/cacerts"
adb shell "cp /data/local/tmp/certs/* /apex/com.android.conscrypt/cacerts/"
adb shell "cp /data/local/tmp/9a5ba575.0 /apex/com.android.conscrypt/cacerts/"
adb shell "chown root:root /apex/com.android.conscrypt/cacerts/*"
adb shell "chmod 644 /apex/com.android.conscrypt/cacerts/*"
adb shell "chcon u:object_r:system_file:s0 /apex/com.android.conscrypt/cacerts/*"

echo [4/4] Aplicando cambios mediante Soft Reboot...
adb shell stop
adb shell start

echo Entorno listo para intercepcion.
pause