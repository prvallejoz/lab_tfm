import base64
import csv
import gzip
import re
import struct
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import urllib.parse
import xml.etree.ElementTree as ET
import zlib

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
        "pagead2.googleadservices.com",
        "adservice.google.com",
        "tpc.googlesyndication.com",
    ],
}

# Patrones endurecidos para evitar falsos positivos con bytes binarios
PATRONES_SENSIBLES = {
    "AAID/UUID": re.compile(
        r"(?:advertiser_id|gaid|aaid|adid|resettable_device_id|app_instance_id|uuid)"
        r"[\"':=\s]+([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{32})",
        re.IGNORECASE,
    ),
    "Ubicacion": re.compile(
        r"(?:lat|latitude|lon|lng|longitude|gps)[\"':=\s]+(-?\d{1,3}\.\d{3,})",
        re.IGNORECASE,
    ),
    "Dispositivo/OS": re.compile(
        r"(?:device_model|submodel|model|os_version|sdk_version|carrier|bundle_id)"
        r"[\"':=\s]+([a-zA-Z0-9._\-]{2,40})",
        re.IGNORECASE,
    ),
    "Evento_TFM": re.compile(
        r"(?:event_name|_eventName|escenario_tfm|evento_controlado_tfm|fb_evento_controlado_tfm)"
        r"[\"':=\s]+([a-zA-Z0-9._\-]{3,50})",
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


# ============================================================================
# DECODIFICADOR DE GZIP, PROTOBUF (SIN ESQUEMA) Y BINARIOS A TEXTO PLANO
# ============================================================================

def _leer_varint(data, pos):
    """Lee un entero varint de Protobuf desde data[pos]."""
    resultado = 0
    shift = 0
    while pos < len(data):
        byte = data[pos]
        pos += 1
        resultado |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return resultado, pos
        shift += 7
        if shift > 63:
            raise ValueError("Varint demasiado largo")
    raise ValueError("Fin inesperado leyendo varint")


def _es_texto_legible(raw_bytes):
    """Determina si una secuencia de bytes es texto UTF-8 imprimible."""
    if not raw_bytes:
        return False
    try:
        texto = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return False
    imprimibles = sum(1 for c in texto if c.isprintable() or c in "\r\n\t")
    return (imprimibles / len(texto)) >= 0.85


def decodificar_protobuf(data, profundidad=0, max_profundidad=6):
    """
    Intenta decodificar bytes en formato Protobuf (wire format) sin archivo .proto.
    Retorna (exito: bool, lineas: list[str]).
    """
    if not data or profundidad > max_profundidad:
        return False, []

    pos = 0
    longitud = len(data)
    lineas = []
    indent = "  " * profundidad

    try:
        while pos < longitud:
            tag, pos = _leer_varint(data, pos)
            field_num = tag >> 3
            wire_type = tag & 0x07

            if field_num == 0 or field_num > 536870911:
                return False, []

            if wire_type == 0:  # Varint
                val, pos = _leer_varint(data, pos)
                lineas.append(f"{indent}Campo {field_num} (varint): {val}")

            elif wire_type == 1:  # 64-bit
                if pos + 8 > longitud:
                    return False, []
                val_int = struct.unpack("<Q", data[pos:pos + 8])[0]
                val_dbl = struct.unpack("<d", data[pos:pos + 8])[0]
                pos += 8
                lineas.append(f"{indent}Campo {field_num} (64-bit): {val_int} (double: {val_dbl:.4g})")

            elif wire_type == 2:  # Length-delimited (string, bytes o mensaje anidado)
                tam, pos = _leer_varint(data, pos)
                if tam < 0 or pos + tam > longitud:
                    return False, []
                subdata = data[pos:pos + tam]
                pos += tam

                # 1) Intentar primero como mensaje Protobuf anidado si no es texto puro
                if len(subdata) >= 2 and not _es_texto_legible(subdata):
                    es_pb, sublineas = decodificar_protobuf(subdata, profundidad + 1, max_profundidad)
                    if es_pb and sublineas:
                        lineas.append(f"{indent}Campo {field_num} (mensaje) {{")
                        lineas.extend(sublineas)
                        lineas.append(f"{indent}}}")
                        continue

                # 2) Si es texto UTF-8 legible
                if _es_texto_legible(subdata):
                    texto_limpio = subdata.decode("utf-8", errors="replace").strip()
                    lineas.append(f'{indent}Campo {field_num} (str): "{texto_limpio}"')
                else:
                    # 3) Intentar como sub-protobuf aunque sea corto, o mostrar hex
                    es_pb, sublineas = decodificar_protobuf(subdata, profundidad + 1, max_profundidad)
                    if es_pb and sublineas:
                        lineas.append(f"{indent}Campo {field_num} (mensaje) {{")
                        lineas.extend(sublineas)
                        lineas.append(f"{indent}}}")
                    else:
                        muestra_hex = subdata[:24].hex()
                        sufijo = "..." if len(subdata) > 24 else ""
                        lineas.append(f"{indent}Campo {field_num} (bytes[{len(subdata)}]): 0x{muestra_hex}{sufijo}")

            elif wire_type == 5:  # 32-bit
                if pos + 4 > longitud:
                    return False, []
                val_int = struct.unpack("<I", data[pos:pos + 4])[0]
                val_flt = struct.unpack("<f", data[pos:pos + 4])[0]
                pos += 4
                lineas.append(f"{indent}Campo {field_num} (32-bit): {val_int} (float: {val_flt:.4g})")

            else:
                # Wire types 3, 4 (obsoletos) o inválidos (6, 7)
                return False, []

        return len(lineas) > 0, lineas
    except Exception:
        return False, []


def extraer_strings_legibles(raw_bytes, min_len=4):
    """Extrae cadenas ASCII/UTF-8 imprimibles de cualquier payload binario."""
    cadenas = re.findall(rb"[ -~]{" + str(min_len).encode() + rb",}", raw_bytes)
    return [c.decode("ascii", errors="ignore").strip() for c in cadenas if c.strip()]


def descomprimir_si_aplica(headers_str, body_bytes):
    """Descomprime el cuerpo HTTP si usa GZIP o Deflate."""
    if not body_bytes:
        return body_bytes, False

    es_gzip_header = "content-encoding: gzip" in headers_str.lower()
    es_gzip_magic = body_bytes[:2] == b"\x1f\x8b"

    if es_gzip_header or es_gzip_magic:
        try:
            return gzip.decompress(body_bytes), True
        except Exception:
            try:
                return zlib.decompress(body_bytes, 16 + zlib.MAX_WBITS), True
            except Exception:
                pass

    if "content-encoding: deflate" in headers_str.lower():
        try:
            return zlib.decompress(body_bytes), True
        except Exception:
            try:
                return zlib.decompress(body_bytes, -zlib.MAX_WBITS), True
            except Exception:
                pass

    return body_bytes, False


def decodificar_elemento_http(elemento_xml):
    """
    Decodifica un elemento <request> o <response> del XML de Burp Suite.
    Retorna un diccionario con cabeceras, tipo de formato y cuerpo en texto plano.
    """
    resultado = {
        "headers": "",
        "texto_plano": "",
        "formato": "Vacío",
    }
    if elemento_xml is None or not elemento_xml.text:
        return resultado

    contenido = elemento_xml.text
    if elemento_xml.attrib.get("base64") == "true":
        try:
            raw_bytes = base64.b64decode(contenido)
        except Exception:
            raw_bytes = contenido.encode("latin-1", errors="replace")
    else:
        raw_bytes = contenido.encode("latin-1", errors="replace")

    # Separar cabeceras HTTP del cuerpo
    if b"\r\n\r\n" in raw_bytes:
        headers_bytes, body_bytes = raw_bytes.split(b"\r\n\r\n", 1)
    elif b"\n\n" in raw_bytes:
        headers_bytes, body_bytes = raw_bytes.split(b"\n\n", 1)
    else:
        headers_bytes, body_bytes = raw_bytes, b""

    headers_str = headers_bytes.decode("utf-8", errors="replace")
    resultado["headers"] = headers_str

    if not body_bytes:
        resultado["formato"] = "Sin cuerpo (solo cabeceras)"
        return resultado

    # Descomprimir GZIP/Deflate si corresponde
    body_bytes, fue_comprimido = descomprimir_si_aplica(headers_str, body_bytes)
    etiqueta_comp = "GZIP + " if fue_comprimido else ""

    es_protobuf_header = any(
        ct in headers_str.lower()
        for ct in ("application/x-protobuf", "application/protobuf", "application/octet-stream")
    )

    # 1) Si el cuerpo ya es texto plano legible (JSON, form-urlencoded, XML, etc.)
    if not es_protobuf_header and _es_texto_legible(body_bytes):
        texto = urllib.parse.unquote(body_bytes.decode("utf-8", errors="replace"))
        resultado["texto_plano"] = texto
        resultado["formato"] = f"{etiqueta_comp}Texto plano / JSON"
        return resultado

    # 2) Intentar decodificación Protobuf (schemaless)
    es_pb, lineas_pb = decodificar_protobuf(body_bytes)
    if es_pb:
        resultado["texto_plano"] = "\n".join(lineas_pb)
        resultado["formato"] = f"{etiqueta_comp}Protobuf decodificado"
        return resultado

    # 3) Respaldo: extraer cadenas legibles de binario genérico
    cadenas = extraer_strings_legibles(body_bytes)
    if cadenas:
        resultado["texto_plano"] = "\n".join(cadenas)
        resultado["formato"] = f"{etiqueta_comp}Binario (strings extraídos)"
    else:
        resultado["texto_plano"] = f"[Binario no legible - {len(body_bytes)} bytes]"
        resultado["formato"] = f"{etiqueta_comp}Binario opaco"

    return resultado


def extraer_parametros(texto_completo):
    hallazgos = []
    for categoria, patron in PATRONES_SENSIBLES.items():
        coincidencias = patron.findall(texto_completo)
        if coincidencias:
            valores_unicos = sorted(list(set(coincidencias)))
            muestra = ", ".join(valores_unicos[:5])
            hallazgos.append(f"{categoria}: [{muestra}]")
    return " | ".join(hallazgos) if hallazgos else "Sin parámetros clave visibles"


# ============================================================================
# INTERFAZ GRÁFICA (TKINTER)
# ============================================================================

class ComparadorDominiosTFM:

    def __init__(self, root):
        self.root = root
        self.root.title("Comparador de Dominios y Decodificador Protobuf - Laboratorio TFM")
        self.root.geometry("1120x680")

        frame_top = tk.Frame(root, pady=10)
        frame_top.pack(fill=tk.X, padx=10)

        tk.Button(
            frame_top,
            text="1. Cargar XML de Burp Suite (con Decodificador)",
            command=self.cargar_xml_burp,
            bg="#e1f5fe",
        ).pack(side=tk.LEFT, padx=5)
        tk.Button(
            frame_top,
            text="2. Cargar TXT de Dominios",
            command=self.cargar_txt,
            bg="#e8f5e9",
        ).pack(side=tk.LEFT, padx=5)
        tk.Button(
            frame_top,
            text="Exportar Payloads Decodificados (TXT)",
            command=self.exportar_payloads_txt,
            bg="#f3e5f5",
        ).pack(side=tk.RIGHT, padx=5)
        tk.Button(
            frame_top,
            text="Exportar Matriz Evidencias (CSV)",
            command=self.exportar_csv,
            bg="#fff9c4",
        ).pack(side=tk.RIGHT, padx=5)

        self.texto_salida = scrolledtext.ScrolledText(
            root, wrap=tk.WORD, font=("Consolas", 9)
        )
        self.texto_salida.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.resultados = []
        self.payloads_detallados = []
        self.mostrar_catalogo()

    def mostrar_catalogo(self):
        self.texto_salida.insert(tk.END, "=== CATÁLOGO DE REFERENCIA CONFIGURADO (TFM) ===\n")
        for sdk, doms in DOMINIOS_CONOCIDOS.items():
            self.texto_salida.insert(tk.END, f"\n[*] {sdk}:\n")
            for d in doms:
                self.texto_salida.insert(tk.END, f"    - {d}\n")
        self.texto_salida.insert(
            tk.END,
            "\n----------------------------------------------------------------------------------\n"
            "Cargue un archivo XML de Burp Suite para correlacionar dominios y decodificar\n"
            "cuerpos comprimidos (GZIP) o binarios (Protocol Buffers) en texto plano.\n\n",
        )

    def cargar_xml_burp(self):
        ruta = filedialog.askopenfilename(filetypes=[("Archivos XML de Burp", "*.xml")])
        if not ruta:
            return
        try:
            tree = ET.parse(ruta)
            root = tree.getroot()
            self.resultados.clear()
            self.payloads_detallados.clear()
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
                    if item.find("method") is not None and item.find("method").text
                    else "-"
                )
                path = (
                    item.find("path").text.strip()
                    if item.find("path") is not None and item.find("path").text
                    else "/"
                )

                req_dec = decodificar_elemento_http(item.find("request"))
                res_dec = decodificar_elemento_http(item.find("response"))

                texto_inspeccion = (
                    f"{urllib.parse.unquote(path)}\n"
                    f"{req_dec['headers']}\n"
                    f"{req_dec['texto_plano']}"
                )
                parametros_detectados = extraer_parametros(texto_inspeccion)

                sdk_atribuido, dominio_base = clasificar_dominio(host)
                ev_id = f"EV-DYN-{contador_ev:03d}"
                estado = "COINCIDENCIA SDK" if dominio_base != "-" else "OTRO / RUIDO"

                # Resumen corto del payload decodificado para la columna CSV
                resumen_payload = req_dec["texto_plano"].replace("\n", " | ")[:200] if req_dec["texto_plano"] else "-"

                self.resultados.append([
                    ev_id,
                    timestamp,
                    host,
                    sdk_atribuido,
                    dominio_base,
                    estado,
                    f"{metodo} {path[:60]}",
                    req_dec["formato"],
                    parametros_detectados,
                    resumen_payload,
                ])

                # Bloque detallado para lectura en pantalla y exportación TXT
                bloque = (
                    f"[{ev_id}] {timestamp} | {host} -> {sdk_atribuido}\n"
                    f"    Petición   : {metodo} {path[:90]}\n"
                    f"    Formato Req: {req_dec['formato']} | Formato Res: {res_dec['formato']}\n"
                    f"    Parámetros : {parametros_detectados}\n"
                )

                if req_dec["texto_plano"]:
                    vista_req = req_dec["texto_plano"][:600]
                    sufijo = "\n    ... [truncado en vista, use 'Exportar Payloads' para ver completo]" if len(req_dec["texto_plano"]) > 600 else ""
                    bloque += f"    --- Payload Request Decodificado ---\n    " + vista_req.replace("\n", "\n    ") + sufijo + "\n"

                if "Protobuf" in res_dec["formato"] and res_dec["texto_plano"]:
                    vista_res = res_dec["texto_plano"][:400]
                    bloque += f"    --- Payload Response Protobuf Decodificado ---\n    " + vista_res.replace("\n", "\n    ") + "\n"

                bloque += f"{'-' * 95}\n"
                self.texto_salida.insert(tk.END, bloque)

                # Guardar versión completa sin truncar para exportación TXT
                detalle_completo = (
                    f"========================================================================\n"
                    f"[{ev_id}] {timestamp} | {host} ({sdk_atribuido})\n"
                    f"Endpoint: {metodo} {path}\n"
                    f"Formato Request: {req_dec['formato']} | Formato Response: {res_dec['formato']}\n"
                    f"Parámetros detectados: {parametros_detectados}\n"
                    f"--- REQUEST DECODIFICADO ---\n{req_dec['texto_plano'] or '(Sin cuerpo)'}\n"
                    f"--- RESPONSE DECODIFICADO ---\n{res_dec['texto_plano'] or '(Sin cuerpo)'}\n\n"
                )
                self.payloads_detallados.append(detalle_completo)
                contador_ev += 1

        except Exception as e:
            messagebox.showerror("Error", f"No se pudo procesar el XML de Burp Suite:\n{e}")

    def cargar_txt(self):
        ruta = filedialog.askopenfilename(filetypes=[("Archivos de texto", "*.txt")])
        if not ruta:
            return
        try:
            with open(ruta, "r", encoding="utf-8") as f:
                hosts = sorted(list(set([line.strip() for line in f if line.strip()])))

            self.resultados.clear()
            self.payloads_detallados.clear()
            self.texto_salida.delete(1.0, tk.END)
            self.texto_salida.insert(
                tk.END, f"=== ANÁLISIS DE LISTA TXT ({len(hosts)} hosts únicos) ===\n\n"
            )

            contador_ev = 1
            for host in hosts:
                sdk_atribuido, dominio_base = clasificar_dominio(host)
                ev_id = f"EV-DYN-{contador_ev:03d}"
                estado = "COINCIDENCIA SDK" if dominio_base != "-" else "OTRO / RUIDO"

                self.resultados.append([
                    ev_id, "N/A (TXT)", host, sdk_atribuido, dominio_base, estado, "N/A", "N/A", "N/A", "N/A"
                ])
                self.texto_salida.insert(
                    tk.END, f"[{ev_id}] Host: {host:<38} | Atribución: {sdk_atribuido}\n"
                )
                contador_ev += 1
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo leer el archivo:\n{e}")

    def exportar_csv(self):
        if not self.resultados:
            messagebox.showwarning("Sin datos", "Primero cargue un archivo de tráfico para analizar.")
            return
        ruta = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
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
                "Formato_Payload",
                "Parametros_Sensibles_Detectados",
                "Muestra_Payload_Decodificado",
            ])
            writer.writerows(self.resultados)
        messagebox.showinfo("Exportado", f"Matriz de evidencias guardada correctamente en:\n{ruta}")

    def exportar_payloads_txt(self):
        if not self.payloads_detallados:
            messagebox.showwarning("Sin datos", "Primero cargue un archivo XML de Burp Suite.")
            return
        ruta = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Texto plano", "*.txt")])
        if not ruta:
            return
        with open(ruta, "w", encoding="utf-8") as f:
            f.writelines(self.payloads_detallados)
        messagebox.showinfo("Exportado", f"Payloads decodificados guardados en:\n{ruta}")


if __name__ == "__main__":
    root = tk.Tk()
    app = ComparadorDominiosTFM(root)
    root.mainloop()