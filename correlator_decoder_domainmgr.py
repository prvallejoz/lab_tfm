import base64
import csv
import gzip
import json
import os
import re
import struct
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, simpledialog, ttk
import urllib.parse
import xml.etree.ElementTree as ET
import zlib

# Ruta del archivo de configuración persistente junto al script
RUTA_CATALOGO_JSON = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "catalogo_sdks.json"
)

# Catálogo base de dominios conocidos según los SDKs delimitados en el TFM
DOMINIOS_BASE_DEFAULT = {
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


def cargar_catalogo():
    """Carga el catálogo desde JSON si existe; de lo contrario crea uno con los valores base."""
    if os.path.exists(RUTA_CATALOGO_JSON):
        try:
            with open(RUTA_CATALOGO_JSON, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
        except Exception:
            pass
    return {sdk: list(doms) for sdk, doms in DOMINIOS_BASE_DEFAULT.items()}


def guardar_catalogo(catalogo):
    """Guarda el catálogo actual en formato JSON."""
    with open(RUTA_CATALOGO_JSON, "w", encoding="utf-8") as f:
        json.dump(catalogo, f, indent=4, ensure_ascii=False)


# Catálogo activo en memoria
DOMINIOS_CONOCIDOS = cargar_catalogo()

# Patrones endurecidos: soporta tanto clave-valor (JSON/URL) como valores sueltos en Protobuf
PATRONES_SENSIBLES = {
    "AAID/UUID/AppID": re.compile(
        r"(?:(?:advertiser_id|gaid|aaid|adid|resettable_device_id|app_instance_id|uuid)"
        r"[\"':=\s]+([0-9a-fA-F]{32})"
        r"|\b([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b"
        r"|\b(1:\d{8,15}:android:[0-9a-fA-F]{16,})\b)",
        re.IGNORECASE,
    ),
    "Ubicacion": re.compile(
        r"(?:lat|latitude|lon|lng|longitude|gps)[\"':=\s]+(-?\d{1,3}\.\d{3,})",
        re.IGNORECASE,
    ),
    "Dispositivo/App": re.compile(
        r"(?:(?:device_model|submodel|model|os_version|sdk_version|carrier|bundle_id|app_name)"
        r"[\"':=\s]+([a-zA-Z0-9._\-]{2,45})"
        r"|\"(sdk_gphone[a-zA-Z0-9_]+|Pixel\s\d+[a-zA-Z0-9 ]*|SM-[A-Z0-9]+|Android\s\d+(?:\.\d+)?)\""
        r"|\"((?:com|org|net|io|ec)\.[a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)+)\")",
        re.IGNORECASE,
    ),
    "Eventos_SDK": re.compile(
        r"(?:(?:event_name|_eventName|escenario_tfm)[\"':=\s]+([a-zA-Z0-9._\-]{3,50})"
        r"|\b(first_open|session_start|screen_view|user_engagement|app_update|app_remove"
        r"|purchase|ad_impression|fb_mobile_activate_app|MOBILE_APP_INSTALL"
        r"|evento_controlado_tfm|fb_evento_controlado_tfm|SC_001)\b)",
        re.IGNORECASE,
    ),
}


def clasificar_dominio(host):
    host = host.lower().strip()
    for sdk, dominios in DOMINIOS_CONOCIDOS.items():
        for dom in dominios:
            dom_limpio = dom.lower().strip()
            if host == dom_limpio or host.endswith("." + dom_limpio):
                return sdk, dom_limpio
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

            elif wire_type == 2:  # Length-delimited
                tam, pos = _leer_varint(data, pos)
                if tam < 0 or pos + tam > longitud:
                    return False, []
                subdata = data[pos:pos + tam]
                pos += tam

                if len(subdata) >= 2 and not _es_texto_legible(subdata):
                    es_pb, sublineas = decodificar_protobuf(subdata, profundidad + 1, max_profundidad)
                    if es_pb and sublineas:
                        lineas.append(f"{indent}Campo {field_num} (mensaje) {{")
                        lineas.extend(sublineas)
                        lineas.append(f"{indent}}}")
                        continue

                if _es_texto_legible(subdata):
                    texto_limpio = subdata.decode("utf-8", errors="replace").strip()
                    lineas.append(f'{indent}Campo {field_num} (str): "{texto_limpio}"')
                else:
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
    """Decodifica un elemento <request> o <response> del XML de Burp Suite."""
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

    body_bytes, fue_comprimido = descomprimir_si_aplica(headers_str, body_bytes)
    etiqueta_comp = "GZIP + " if fue_comprimido else ""

    es_protobuf_header = any(
        ct in headers_str.lower()
        for ct in ("application/x-protobuf", "application/protobuf", "application/octet-stream")
    )

    if not es_protobuf_header and _es_texto_legible(body_bytes):
        texto = urllib.parse.unquote(body_bytes.decode("utf-8", errors="replace"))
        resultado["texto_plano"] = texto
        resultado["formato"] = f"{etiqueta_comp}Texto plano / JSON"
        return resultado

    es_pb, lineas_pb = decodificar_protobuf(body_bytes)
    if es_pb:
        resultado["texto_plano"] = "\n".join(lineas_pb)
        resultado["formato"] = f"{etiqueta_comp}Protobuf decodificado"
        return resultado

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
        valores = []
        for match in coincidencias:
            if isinstance(match, tuple):
                val = next((g for g in match if g), "")
            else:
                val = match
            if val:
                valores.append(val)
        if valores:
            valores_unicos = sorted(list(set(valores)))
            muestra = ", ".join(valores_unicos[:6])
            hallazgos.append(f"{categoria}: [{muestra}]")
    return " | ".join(hallazgos) if hallazgos else "Sin parámetros clave visibles"


# ============================================================================
# FORMULARIO DE GESTIÓN DE SDKs Y DOMINIOS CONOCIDOS
# ============================================================================

class GestorSDKsWindow(tk.Toplevel):

    def __init__(self, parent, callback_actualizacion):
        super().__init__(parent)
        self.title("Gestor de SDKs y Dominios Conocidos")
        self.geometry("760x460")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        self.callback_actualizacion = callback_actualizacion
        self.catalogo_temp = {sdk: list(doms) for sdk, doms in DOMINIOS_CONOCIDOS.items()}
        self.sdk_seleccionado = None

        self._construir_ui()
        self._cargar_lista_sdks()

    def _construir_ui(self):
        frame_main = tk.Frame(self, padx=12, pady=12)
        frame_main.pack(fill=tk.BOTH, expand=True)

        frame_izq = tk.LabelFrame(frame_main, text="SDKs Registrados", padx=8, pady=8)
        frame_izq.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 6))

        self.lista_sdks = tk.Listbox(frame_izq, exportselection=False, font=("Consolas", 9))
        self.lista_sdks.pack(fill=tk.BOTH, expand=True)
        self.lista_sdks.bind("<<ListboxSelect>>", self._al_seleccionar_sdk)

        frame_btn_sdk = tk.Frame(frame_izq, pady=6)
        frame_btn_sdk.pack(fill=tk.X)
        tk.Button(frame_btn_sdk, text="+ Agregar SDK", command=self._agregar_sdk, bg="#e8f5e9").pack(side=tk.LEFT, padx=2)
        tk.Button(frame_btn_sdk, text="Renombrar", command=self._renombrar_sdk).pack(side=tk.LEFT, padx=2)
        tk.Button(frame_btn_sdk, text="Eliminar", command=self._eliminar_sdk, bg="#ffebee").pack(side=tk.RIGHT, padx=2)

        frame_der = tk.LabelFrame(frame_main, text="Dominios Asociados al SDK", padx=8, pady=8)
        frame_der.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(6, 0))

        self.lista_dominios = tk.Listbox(frame_der, exportselection=False, font=("Consolas", 9))
        self.lista_dominios.pack(fill=tk.BOTH, expand=True)

        frame_add_dom = tk.Frame(frame_der, pady=6)
        frame_add_dom.pack(fill=tk.X)
        self.entry_dominio = tk.Entry(frame_add_dom, font=("Consolas", 9))
        self.entry_dominio.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 4))
        self.entry_dominio.bind("<Return>", lambda e: self._agregar_dominio())
        tk.Button(frame_add_dom, text="+ Añadir", command=self._agregar_dominio, bg="#e1f5fe").pack(side=tk.LEFT, padx=2)
        tk.Button(frame_add_dom, text="Quitar", command=self._eliminar_dominio, bg="#ffebee").pack(side=tk.RIGHT, padx=2)

        frame_bot = tk.Frame(self, padx=12, pady=8)
        frame_bot.pack(fill=tk.X)

        tk.Button(frame_bot, text="Restaurar Catálogo Base", command=self._restaurar_defecto).pack(side=tk.LEFT)
        tk.Button(frame_bot, text="Cancelar", command=self.destroy).pack(side=tk.RIGHT, padx=(6, 0))
        tk.Button(
            frame_bot,
            text="Guardar y Cerrar",
            command=self._guardar_y_cerrar,
            bg="#c8e6c9",
            font=("TkDefaultFont", 9, "bold"),
        ).pack(side=tk.RIGHT)

    def _cargar_lista_sdks(self, seleccionar_nombre=None):
        self.lista_sdks.delete(0, tk.END)
        sdks = list(self.catalogo_temp.keys())
        for sdk in sdks:
            self.lista_sdks.insert(tk.END, sdk)

        if sdks:
            idx = sdks.index(seleccionar_nombre) if seleccionar_nombre in sdks else 0
            self.lista_sdks.selection_set(idx)
            self.lista_sdks.activate(idx)
            self._al_seleccionar_sdk()
        else:
            self.sdk_seleccionado = None
            self.lista_dominios.delete(0, tk.END)

    def _al_seleccionar_sdk(self, event=None):
        sel = self.lista_sdks.curselection()
        if not sel:
            return
        self.sdk_seleccionado = self.lista_sdks.get(sel[0])
        self.lista_dominios.delete(0, tk.END)
        for dom in self.catalogo_temp.get(self.sdk_seleccionado, []):
            self.lista_dominios.insert(tk.END, dom)

    def _agregar_sdk(self):
        nombre = simpledialog.askstring("Nuevo SDK", "Nombre del SDK (ej. AppsFlyer, Unity Ads):", parent=self)
        if not nombre:
            return
        nombre = nombre.strip()
        if not nombre:
            return
        if nombre in self.catalogo_temp:
            messagebox.showwarning("Duplicado", "Ese SDK ya existe en el catálogo.", parent=self)
            return
        self.catalogo_temp[nombre] = []
        self._cargar_lista_sdks(seleccionar_nombre=nombre)

    def _renombrar_sdk(self):
        if not self.sdk_seleccionado:
            return
        nuevo = simpledialog.askstring(
            "Renombrar SDK",
            "Nuevo nombre para el SDK:",
            initialvalue=self.sdk_seleccionado,
            parent=self,
        )
        if not nuevo:
            return
        nuevo = nuevo.strip()
        if not nuevo or nuevo == self.sdk_seleccionado:
            return
        if nuevo in self.catalogo_temp:
            messagebox.showwarning("Duplicado", "Ya existe un SDK con ese nombre.", parent=self)
            return
        self.catalogo_temp[nuevo] = self.catalogo_temp.pop(self.sdk_seleccionado)
        self._cargar_lista_sdks(seleccionar_nombre=nuevo)

    def _eliminar_sdk(self):
        if not self.sdk_seleccionado:
            return
        if messagebox.askyesno(
            "Confirmar",
            f"¿Eliminar el SDK '{self.sdk_seleccionado}' y todos sus dominios?",
            parent=self,
        ):
            self.catalogo_temp.pop(self.sdk_seleccionado, None)
            self._cargar_lista_sdks()

    def _agregar_dominio(self):
        if not self.sdk_seleccionado:
            messagebox.showwarning("Sin SDK", "Primero seleccione o cree un SDK.", parent=self)
            return
        dom = self.entry_dominio.get().strip().lower()
        dom = re.sub(r"^https?://", "", dom).split("/")[0].strip()
        if not dom:
            return
        lista = self.catalogo_temp[self.sdk_seleccionado]
        if dom in lista:
            messagebox.showinfo("Existente", "Ese dominio ya está registrado en este SDK.", parent=self)
            return
        lista.append(dom)
        self.entry_dominio.delete(0, tk.END)
        self._al_seleccionar_sdk()

    def _eliminar_dominio(self):
        if not self.sdk_seleccionado:
            return
        sel = self.lista_dominios.curselection()
        if not sel:
            return
        dom = self.lista_dominios.get(sel[0])
        self.catalogo_temp[self.sdk_seleccionado].remove(dom)
        self._al_seleccionar_sdk()

    def _restaurar_defecto(self):
        if messagebox.askyesno(
            "Restaurar",
            "¿Restaurar el catálogo original del TFM (Firebase, Facebook SDK y AdMob)?",
            parent=self,
        ):
            self.catalogo_temp = {sdk: list(doms) for sdk, doms in DOMINIOS_BASE_DEFAULT.items()}
            self._cargar_lista_sdks()

    def _guardar_y_cerrar(self):
        global DOMINIOS_CONOCIDOS
        DOMINIOS_CONOCIDOS = {sdk: list(doms) for sdk, doms in self.catalogo_temp.items()}
        try:
            guardar_catalogo(DOMINIOS_CONOCIDOS)
        except Exception as e:
            messagebox.showerror("Error al guardar", f"No se pudo guardar catalogo_sdks.json:\n{e}", parent=self)
            return
        self.callback_actualizacion()
        self.destroy()


# ============================================================================
# INTERFAZ GRÁFICA PRINCIPAL (TKINTER) CON BARRA DE PROGRESO Y THREADING
# ============================================================================

class ComparadorDominiosTFM:

    def __init__(self, root):
        self.root = root
        self.root.title("Comparador de Dominios y Decodificador Protobuf - Laboratorio TFM")
        self.root.geometry("1150x700")

        # --- Panel superior de botones ---
        frame_top = tk.Frame(root, pady=10)
        frame_top.pack(fill=tk.X, padx=10)

        self.btn_xml = tk.Button(
            frame_top,
            text="1. Cargar XML de Burp Suite",
            command=self.cargar_xml_burp,
            bg="#e1f5fe",
        )
        self.btn_xml.pack(side=tk.LEFT, padx=4)

        self.btn_txt = tk.Button(
            frame_top,
            text="2. Cargar TXT de Dominios",
            command=self.cargar_txt,
            bg="#e8f5e9",
        )
        self.btn_txt.pack(side=tk.LEFT, padx=4)

        self.btn_gestor = tk.Button(
            frame_top,
            text="Gestionar SDKs y Dominios",
            command=self.abrir_gestor_sdks,
            bg="#ffe0b2",
        )
        self.btn_gestor.pack(side=tk.LEFT, padx=8)

        self.btn_exp_txt = tk.Button(
            frame_top,
            text="Exportar Payloads Decodificados (TXT)",
            command=self.exportar_payloads_txt,
            bg="#f3e5f5",
        )
        self.btn_exp_txt.pack(side=tk.RIGHT, padx=4)

        self.btn_exp_csv = tk.Button(
            frame_top,
            text="Exportar Matriz Evidencias (CSV)",
            command=self.exportar_csv,
            bg="#fff9c4",
        )
        self.btn_exp_csv.pack(side=tk.RIGHT, padx=4)

        self.botones_accion = [
            self.btn_xml,
            self.btn_txt,
            self.btn_gestor,
            self.btn_exp_txt,
            self.btn_exp_csv,
        ]

        # --- Área de resultados ---
        self.texto_salida = scrolledtext.ScrolledText(
            root, wrap=tk.WORD, font=("Consolas", 9)
        )
        self.texto_salida.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 6))

        # --- Barra de estado y progreso inferior ---
        frame_status = tk.Frame(root, padx=10, pady=6)
        frame_status.pack(fill=tk.X, side=tk.BOTTOM)

        self.lbl_estado = tk.Label(
            frame_status,
            text="Listo. Seleccione un archivo XML de Burp Suite o TXT para iniciar.",
            anchor="w",
            font=("TkDefaultFont", 9),
        )
        self.lbl_estado.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.barra_progreso = ttk.Progressbar(
            frame_status,
            orient="horizontal",
            length=300,
            mode="determinate",
        )
        self.barra_progreso.pack(side=tk.RIGHT, padx=(10, 0))

        self.resultados = []
        self.payloads_detallados = []
        self.mostrar_catalogo()

    # --- Helpers de control de UI y progreso ---

    def _set_botones_estado(self, habilitado):
        estado = tk.NORMAL if habilitado else tk.DISABLED
        for btn in self.botones_accion:
            btn.config(state=estado)

    def _iniciar_progreso_indeterminado(self, mensaje):
        self._set_botones_estado(False)
        self.lbl_estado.config(text=mensaje)
        self.barra_progreso.config(mode="indeterminate", value=0)
        self.barra_progreso.start(12)

    def _configurar_progreso_determinado(self, maximo, mensaje):
        self.barra_progreso.stop()
        self.barra_progreso.config(mode="determinate", maximum=max(maximo, 1), value=0)
        self.lbl_estado.config(text=mensaje)

    def _actualizar_progreso(self, actual, total):
        pct = int((actual / max(total, 1)) * 100)
        self.barra_progreso.config(value=actual)
        self.lbl_estado.config(text=f"Procesando peticiones: {actual} / {total} ({pct}%)...")

    def _finalizar_progreso(self, mensaje):
        self.barra_progreso.stop()
        self.barra_progreso.config(mode="determinate", value=self.barra_progreso["maximum"])
        self.lbl_estado.config(text=mensaje)
        self._set_botones_estado(True)

    # --- Gestión de catálogo ---

    def abrir_gestor_sdks(self):
        GestorSDKsWindow(self.root, self.al_actualizar_catalogo)

    def al_actualizar_catalogo(self):
        if not self.resultados:
            self.texto_salida.delete(1.0, tk.END)
            self.mostrar_catalogo()
        else:
            messagebox.showinfo(
                "Catálogo actualizado",
                "Los cambios en SDKs y dominios se guardaron en catalogo_sdks.json.\n"
                "Vuelva a cargar el archivo XML o TXT para aplicar la nueva clasificación.",
            )

    def mostrar_catalogo(self):
        self.texto_salida.insert(tk.END, "=== CATÁLOGO DE REFERENCIA CONFIGURADO (TFM) ===\n")
        for sdk, doms in DOMINIOS_CONOCIDOS.items():
            self.texto_salida.insert(tk.END, f"\n[*] {sdk}:\n")
            if doms:
                for d in doms:
                    self.texto_salida.insert(tk.END, f"    - {d}\n")
            else:
                self.texto_salida.insert(tk.END, "    (Sin dominios asignados)\n")
        self.texto_salida.insert(
            tk.END,
            "\n----------------------------------------------------------------------------------\n"
            "Cargue un archivo XML de Burp Suite para correlacionar dominios, decodificar\n"
            "cuerpos GZIP/Protobuf y extraer parámetros sensibles en texto plano.\n"
            "Use 'Gestionar SDKs y Dominios' para añadir o editar el catálogo de referencia.\n\n",
        )

    # --- Carga y procesamiento XML en hilo secundario ---

    def cargar_xml_burp(self):
        ruta = filedialog.askopenfilename(filetypes=[("Archivos XML de Burp", "*.xml")])
        if not ruta:
            return
        self._iniciar_progreso_indeterminado("Leyendo archivo XML de Burp Suite...")
        hilo = threading.Thread(target=self._procesar_xml_worker, args=(ruta,), daemon=True)
        hilo.start()

    def _procesar_xml_worker(self, ruta):
        try:
            tree = ET.parse(ruta)
            root_xml = tree.getroot()
            items = root_xml.findall("item")
            total = len(items)

            self.root.after(
                0,
                self._configurar_progreso_determinado,
                total,
                f"Analizando {total} peticiones...",
            )

            resultados_temp = []
            payloads_temp = []
            bloques_vista = [
                f"=== ANÁLISIS DE TRÁFICO BURP SUITE ({total} peticiones procesadas) ===\n\n"
            ]

            contador_ev = 1
            for idx, item in enumerate(items, start=1):
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

                resumen_payload = (
                    req_dec["texto_plano"].replace("\n", " | ")[:200]
                    if req_dec["texto_plano"]
                    else "-"
                )

                resultados_temp.append([
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

                bloque = (
                    f"[{ev_id}] {timestamp} | {host} -> {sdk_atribuido}\n"
                    f"    Petición   : {metodo} {path[:90]}\n"
                    f"    Formato Req: {req_dec['formato']} | Formato Res: {res_dec['formato']}\n"
                    f"    Parámetros : {parametros_detectados}\n"
                )

                if req_dec["texto_plano"]:
                    vista_req = req_dec["texto_plano"][:600]
                    sufijo = (
                        "\n    ... [truncado en vista, use 'Exportar Payloads' para ver completo]"
                        if len(req_dec["texto_plano"]) > 600
                        else ""
                    )
                    bloque += (
                        "    --- Payload Request Decodificado ---\n    "
                        + vista_req.replace("\n", "\n    ")
                        + sufijo
                        + "\n"
                    )

                if "Protobuf" in res_dec["formato"] and res_dec["texto_plano"]:
                    vista_res = res_dec["texto_plano"][:400]
                    bloque += (
                        "    --- Payload Response Protobuf Decodificado ---\n    "
                        + vista_res.replace("\n", "\n    ")
                        + "\n"
                    )

                bloque += f"{'-' * 95}\n"
                bloques_vista.append(bloque)

                detalle_completo = (
                    f"========================================================================\n"
                    f"[{ev_id}] {timestamp} | {host} ({sdk_atribuido})\n"
                    f"Endpoint: {metodo} {path}\n"
                    f"Formato Request: {req_dec['formato']} | Formato Response: {res_dec['formato']}\n"
                    f"Parámetros detectados: {parametros_detectados}\n"
                    f"--- REQUEST DECODIFICADO ---\n{req_dec['texto_plano'] or '(Sin cuerpo)'}\n"
                    f"--- RESPONSE DECODIFICADO ---\n{res_dec['texto_plano'] or '(Sin cuerpo)'}\n\n"
                )
                payloads_temp.append(detalle_completo)
                contador_ev += 1

                # Actualizar barra de progreso cada 5 elementos o al final para mantener fluidez
                if idx % 5 == 0 or idx == total:
                    self.root.after(0, self._actualizar_progreso, idx, total)

            texto_final = "".join(bloques_vista)
            self.root.after(
                0,
                self._mostrar_resultados_xml,
                resultados_temp,
                payloads_temp,
                texto_final,
                total,
            )

        except Exception as e:
            self.root.after(0, self._mostrar_error_proceso, f"No se pudo procesar el XML de Burp Suite:\n{e}")

    def _mostrar_resultados_xml(self, resultados_temp, payloads_temp, texto_final, total):
        self.resultados = resultados_temp
        self.payloads_detallados = payloads_temp
        self.texto_salida.delete(1.0, tk.END)
        self.texto_salida.insert(tk.END, texto_final)
        self._finalizar_progreso(f"Completado: {len(self.resultados)} peticiones analizadas de {total} registros.")

    # --- Carga y procesamiento TXT en hilo secundario ---

    def cargar_txt(self):
        ruta = filedialog.askopenfilename(filetypes=[("Archivos de texto", "*.txt")])
        if not ruta:
            return
        self._iniciar_progreso_indeterminado("Leyendo lista de dominios TXT...")
        hilo = threading.Thread(target=self._procesar_txt_worker, args=(ruta,), daemon=True)
        hilo.start()

    def _procesar_txt_worker(self, ruta):
        try:
            with open(ruta, "r", encoding="utf-8") as f:
                hosts = sorted(list(set([line.strip() for line in f if line.strip()])))

            total = len(hosts)
            self.root.after(
                0,
                self._configurar_progreso_determinado,
                total,
                f"Clasificando {total} hosts únicos...",
            )

            resultados_temp = []
            lineas_vista = [f"=== ANÁLISIS DE LISTA TXT ({total} hosts únicos) ===\n\n"]

            for idx, host in enumerate(hosts, start=1):
                sdk_atribuido, dominio_base = clasificar_dominio(host)
                ev_id = f"EV-DYN-{idx:03d}"
                estado = "COINCIDENCIA SDK" if dominio_base != "-" else "OTRO / RUIDO"

                resultados_temp.append([
                    ev_id, "N/A (TXT)", host, sdk_atribuido, dominio_base, estado, "N/A", "N/A", "N/A", "N/A"
                ])
                lineas_vista.append(f"[{ev_id}] Host: {host:<38} | Atribución: {sdk_atribuido}\n")

                if idx % 10 == 0 or idx == total:
                    self.root.after(0, self._actualizar_progreso, idx, total)

            texto_final = "".join(lineas_vista)
            self.root.after(0, self._mostrar_resultados_txt, resultados_temp, texto_final, total)
        except Exception as e:
            self.root.after(0, self._mostrar_error_proceso, f"No se pudo leer el archivo:\n{e}")

    def _mostrar_resultados_txt(self, resultados_temp, texto_final, total):
        self.resultados = resultados_temp
        self.payloads_detallados = []
        self.texto_salida.delete(1.0, tk.END)
        self.texto_salida.insert(tk.END, texto_final)
        self._finalizar_progreso(f"Completado: {total} hosts únicos clasificados.")

    def _mostrar_error_proceso(self, mensaje):
        self.barra_progreso.stop()
        self.barra_progreso.config(mode="determinate", value=0)
        self.lbl_estado.config(text="Error durante el procesamiento.")
        self._set_botones_estado(True)
        messagebox.showerror("Error", mensaje)

    # --- Exportaciones ---

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