import base64
import csv
import re
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import urllib.parse
import xml.etree.ElementTree as ET

# Catálogo base de dominios conocidos según los SDKs delimitados en el TFM
DOMINIOS_CONOCIDOS = {
    "Google Analytics for Firebase": [
        "app-measurement.com",
        "firebaselogging.googleapis.com",
        "firebaseremoteconfig.googleapis.com",
        "firebaseinstallations.googleapis.com",
    ],
    "Facebook SDK (Meta)": [
        "graph.facebook.com",
        "connect.facebook.net",
        "ep1.facebook.com",
        "an.facebook.com",
    ],
    "Google AdMob": [
        "googleads.g.doubleclick.net",
        "pagead2.googlesyndication.com",
        "adservice.google.com",
        "tpc.googlesyndication.com",
    ],
    "Google AdSense": [
            "pagead2.googleadservices.com",           
        ],
}

# Patrones de búsqueda para parámetros sensibles y telemetría
PATRONES_SENSIBLES = {
    "AAID/UUID": re.compile(
        r"(?:advertiser_id|gaid|aaid|adid|resettable_device_id|app_instance_id|uuid)[\"':=\s]+([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{32})",
        re.IGNORECASE,
    ),
    "Ubicacion": re.compile(
        r"(?:lat|latitude|lon|lng|longitude|gps)[\"':=\s]+(-?\d{1,3}\.\d+)",
        re.IGNORECASE,
    ),
    "Dispositivo/OS": re.compile(
        r"(?:device_model|model|os_version|sdk_version|carrier|bundle_id)[\"':=\s]+([^&\",}\s]+)",
        re.IGNORECASE,
    ),
    "Evento_TFM": re.compile(
        r"(?:event_name|_o|_n|escenario_tfm|evento_controlado_tfm|fb_evento_controlado_tfm)[\"':=\s]+([^&\",}\s]+)",
        re.IGNORECASE,
    ),
}


def clasificar_dominio(host):
    host = host.lower().strip()
    for sdk, dominios in DOMINIOS_CONOCIDOS.items():
        for dom in dominios:
            if host == dom or host.endswith("." + dom):
                return sdk, dom
    return "No clasificado / Tercero desconocido", "-"


def decodificar_peticion(elemento_request):
    if elemento_request is None or not elemento_request.text:
        return ""
    contenido = elemento_request.text
    if elemento_request.attrib.get("base64") == "true":
        try:
            contenido = base64.b64decode(contenido).decode(
                "utf-8", errors="replace"
            )
        except Exception:
            pass
    # Decodificar caracteres URL (%22, %3A, %2C, etc.) para facilitar lectura
    return urllib.parse.unquote(contenido)


def extraer_parametros(texto_completo):
    hallazgos = []
    for categoria, patron in PATRONES_SENSIBLES.items():
        coincidencias = patron.findall(texto_completo)
        if coincidencias:
            valores_unicos = sorted(list(set(coincidencias)))
            # Limitar longitud si hay demasiados valores repetidos
            muestra = ", ".join(valores_unicos[:4])
            hallazgos.append(f"{categoria}: [{muestra}]")
    return " | ".join(hallazgos) if hallazgos else "Sin parámetros clave visibles (o binario/protobuf)"


class ComparadorDominiosTFM:

    def __init__(self, root):
        self.root = root
        self.root.title(
            "Comparador de Dominios y Parámetros SDK - Laboratorio TFM"
        )
        self.root.geometry("1050x620")

        # Panel superior de botones
        frame_top = tk.Frame(root, pady=10)
        frame_top.pack(fill=tk.X, padx=10)

        tk.Button(
            frame_top,
            text="1. Cargar XML de Burp Suite (Detallado)",
            command=self.cargar_xml_burp,
            bg="#e1f5fe",
        ).pack(side=tk.LEFT, padx=5)
        tk.Button(
            frame_top,
            text="2. Cargar TXT de Dominios (Solo Hosts)",
            command=self.cargar_txt,
            bg="#e8f5e9",
        ).pack(side=tk.LEFT, padx=5)
        tk.Button(
            frame_top,
            text="Exportar Matriz Evidencias (CSV)",
            command=self.exportar_csv,
            bg="#fff9c4",
        ).pack(side=tk.RIGHT, padx=5)

        # Área de resultados
        self.texto_salida = scrolledtext.ScrolledText(
            root, wrap=tk.WORD, font=("Consolas", 9)
        )
        self.texto_salida.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.resultados = []
        self.mostrar_catalogo()

    def mostrar_catalogo(self):
        self.texto_salida.insert(
            tk.END, "=== CATÁLOGO DE REFERENCIA CONFIGURADO (TFM) ===\n"
        )
        for sdk, doms in DOMINIOS_CONOCIDOS.items():
            self.texto_salida.insert(tk.END, f"\n[*] {sdk}:\n")
            for d in doms:
                self.texto_salida.insert(tk.END, f"    - {d}\n")
        self.texto_salida.insert(
            tk.END,
            "\n----------------------------------------------------------------------------------\n",
        )
        self.texto_salida.insert(
            tk.END,
            "Cargue un archivo XML exportado de Burp Suite para extraer timestamps, SDKs y parámetros.\n\n",
        )

    def cargar_xml_burp(self):
        ruta = filedialog.askopenfilename(
            filetypes=[("Archivos XML de Burp", "*.xml")]
        )
        if not ruta:
            return
        try:
            tree = ET.parse(ruta)
            root = tree.getroot()
            self.resultados.clear()
            self.texto_salida.delete(1.0, tk.END)

            items = root.findall("item")
            self.texto_salida.insert(
                tk.END,
                f"=== ANÁLISIS DE TRÁFICO BURP SUITE ({len(items)} peticiones procesadas) ===\n\n",
            )

            contador_ev = 1
            for item in items:
                host_el = item.find("host")
                if host_el is None or not host_el.text:
                    continue

                host = host_el.text.strip()
                timestamp = (
                    item.find("time").text.strip()
                    if item.find("time") is not None and item.find("time").text
                    else "Sin fecha"
                )
                metodo = (
                    item.find("method").text.strip()
                    if item.find("method") is not None
                    and item.find("method").text
                    else "-"
                )
                path = (
                    item.find("path").text.strip()
                    if item.find("path") is not None and item.find("path").text
                    else "/"
                )

                raw_request = decodificar_peticion(item.find("request"))
                texto_inspeccion = (
                    f"{urllib.parse.unquote(path)}\n{raw_request}"
                )
                parametros_detectados = extraer_parametros(texto_inspeccion)

                sdk_atribuido, dominio_base = clasificar_dominio(host)
                ev_id = f"EV-DYN-{contador_ev:03d}"
                estado = (
                    "COINCIDENCIA SDK"
                    if dominio_base != "-"
                    else "OTRO / RUIDO"
                )

                self.resultados.append([
                    ev_id,
                    timestamp,
                    host,
                    sdk_atribuido,
                    dominio_base,
                    estado,
                    f"{metodo} {path[:60]}",
                    parametros_detectados,
                ])

                bloque = (
                    f"[{ev_id}] {timestamp} | {host} -> {sdk_atribuido}\n"
                    f"    Petición   : {metodo} {path[:85]}\n"
                    f"    Parámetros : {parametros_detectados}\n"
                    f"{'-'*90}\n"
                )
                self.texto_salida.insert(tk.END, bloque)
                contador_ev += 1

        except Exception as e:
            messagebox.showerror(
                "Error", f"No se pudo procesar el XML de Burp Suite:\n{e}"
            )

    def cargar_txt(self):
        ruta = filedialog.askopenfilename(
            filetypes=[("Archivos de texto", "*.txt")]
        )
        if not ruta:
            return
        try:
            with open(ruta, "r", encoding="utf-8") as f:
                hosts = sorted(
                    list(set([line.strip() for line in f if line.strip()]))
                )

            self.resultados.clear()
            self.texto_salida.delete(1.0, tk.END)
            self.texto_salida.insert(
                tk.END,
                f"=== ANÁLISIS DE LISTA TXT ({len(hosts)} hosts únicos) ===\n\n",
            )

            contador_ev = 1
            for host in hosts:
                sdk_atribuido, dominio_base = clasificar_dominio(host)
                ev_id = f"EV-DYN-{contador_ev:03d}"
                estado = (
                    "COINCIDENCIA SDK"
                    if dominio_base != "-"
                    else "OTRO / RUIDO"
                )

                self.resultados.append([
                    ev_id,
                    "N/A (TXT)",
                    host,
                    sdk_atribuido,
                    dominio_base,
                    estado,
                    "N/A",
                    "N/A",
                ])
                self.texto_salida.insert(
                    tk.END,
                    f"[{ev_id}] Host: {host:<38} | Atribución: {sdk_atribuido}\n",
                )
                contador_ev += 1
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo leer el archivo:\n{e}")

    def exportar_csv(self):
        if not self.resultados:
            messagebox.showwarning(
                "Sin datos", "Primero cargue un archivo de tráfico para analizar."
            )
            return
        ruta = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV", "*.csv")]
        )
        if not ruta:
            return
        with open(ruta, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "EV-ID",
                "Timestamp",
                "Host_Capturado",
                "SDK_Atribuido",
                "Dominio_Patron",
                "Clasificacion",
                "Endpoint_Metodo",
                "Parametros_Sensibles_Detectados",
            ])
            writer.writerows(self.resultados)
        messagebox.showinfo(
            "Exportado",
            f"Matriz de evidencias guardada correctamente en:\n{ruta}",
        )


if __name__ == "__main__":
    root = tk.Tk()
    app = ComparadorDominiosTFM(root)
    root.mainloop()