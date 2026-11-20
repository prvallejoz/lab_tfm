@echo off
echo Iniciando el emulador...

:: MODIFICA ESTA LINEA con tu usuario y nombre de emulador
start "" "C:\Users\prval\AppData\Local\Android\Sdk\emulator\emulator.exe" -avd Lab_TFM -writable-system -gpu swiftshader_indirect

echo Esperando a que el emulador encienda (esto puede tomar un minuto)...
adb wait-for-device
:: Damos 25 segundos adicionales para que el sistema interno termine de cargar
timeout /t 25 /nobreak > NUL

echo Inyectando certificado en el modulo APEX...
adb push 9a5ba575.0 /data/local/tmp/
adb root
timeout /t 3 /nobreak > NUL
adb shell "mkdir -p /data/local/tmp/certs"
adb shell "cp /apex/com.android.conscrypt/cacerts/* /data/local/tmp/certs/"
adb shell "mount -t tmpfs tmpfs /apex/com.android.conscrypt/cacerts"
adb shell "cp /data/local/tmp/certs/* /apex/com.android.conscrypt/cacerts/"
adb shell "cp /data/local/tmp/9a5ba575.0 /apex/com.android.conscrypt/cacerts/"
adb shell "chown root:root /apex/com.android.conscrypt/cacerts/*"
adb shell "chmod 644 /apex/com.android.conscrypt/cacerts/*"
adb shell "chcon u:object_r:system_file:s0 /apex/com.android.conscrypt/cacerts/*"

echo === [FASE 4/4] PROPAGANDO CERTIFICADO EN CALIENTE A ZYGOTE (SIN REINICIO) ===
adb shell "for pid in $(pidof zygote zygote64); do nsenter --mount=/proc/$pid/ns/mnt -- mount --bind /apex/com.android.conscrypt/cacerts /apex/com.android.conscrypt/cacerts; done"

adb shell "ls -laZ /apex/com.android.conscrypt/cacerts/9a5ba575.0"

echo === ENTORNO LISTO SIN BLOQUEOS ===

::echo Reiniciando servicios de Android...
::adb shell stop
::adb shell start

echo Inyeccion completada exitosamente.
pause