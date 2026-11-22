package com.example.aplicacioncontrolada

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import android.widget.Button
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import com.facebook.appevents.AppEventsLogger
import com.google.android.gms.ads.AdRequest
import com.google.android.gms.ads.AdView
import com.google.android.gms.ads.MobileAds
import com.google.firebase.analytics.FirebaseAnalytics

class MainActivity : AppCompatActivity() {

    private lateinit var firebaseAnalytics: FirebaseAnalytics
    private lateinit var fbLogger: AppEventsLogger
    private lateinit var adView: AdView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // Inicialización automática de los 3 SDKs al arrancar (Startup)
        firebaseAnalytics = FirebaseAnalytics.getInstance(this)
        fbLogger = AppEventsLogger.newLogger(this)
        MobileAds.initialize(this) {}

        adView = findViewById(R.id.adView)

        // Acción 1: Solicitud manual de permiso sensible
        findViewById<Button>(R.id.btnPermisoUbicacion).setOnClickListener {
            if (ActivityCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION)
                != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(
                    this,
                    arrayOf(Manifest.permission.ACCESS_FINE_LOCATION),
                    1001
                )
            } else {
                Toast.makeText(this, "Permiso de ubicación ya concedido", Toast.LENGTH_SHORT).show()
            }
        }

        // Acción 2: Envío explícito de telemetría a Firebase y Facebook
        findViewById<Button>(R.id.btnEventoAnalitico).setOnClickListener {
            val bundle = Bundle().apply {
                putString("escenario_tfm", "SC_001")
                putString("tipo_prueba", "controlada")
            }
            firebaseAnalytics.logEvent("evento_controlado_tfm", bundle)
            fbLogger.logEvent("fb_evento_controlado_tfm", bundle)
            fbLogger.flush()
            Toast.makeText(this, "Eventos analíticos enviados", Toast.LENGTH_SHORT).show()
        }

        // Acción 3: Petición de banner publicitario a AdMob
        findViewById<Button>(R.id.btnCargarBanner).setOnClickListener {
            val adRequest = AdRequest.Builder().build()
            adView.loadAd(adRequest)
            Toast.makeText(this, "Solicitando banner AdMob...", Toast.LENGTH_SHORT).show()
        }
    }
}