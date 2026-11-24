#INTERFAZ TKINTER


import tkinter as tk
from tkinter import ttk

from rsa_core import ErrorRSA, parsear_entero, encriptar, desencriptar


def entre_comillas(texto):
    return f'"{texto}"'


def caracteres_visibles(texto):
    
    return " ".join(f"'{ch}'" for ch in texto)


class PanelBase(ttk.Frame):

    def __init__(self, master, app):
        super().__init__(master, padding=10)
        self.app = app
        self.columnconfigure(0, weight=1)
        self.campos = {}

    # --- entradas 
    def fila_parametros(self, parent):
        marco = ttk.Frame(parent)
        self.var_p = tk.StringVar(value="367")
        self.var_q = tk.StringVar(value="373")
        self.var_e = tk.StringVar(value="17")
        for i, (etq, var) in enumerate((("p:", self.var_p), ("q:", self.var_q), ("e:", self.var_e))):
            ttk.Label(marco, text=etq).grid(row=0, column=2 * i, padx=(0 if i == 0 else 12, 4))
            ttk.Entry(marco, textvariable=var, width=12).grid(row=0, column=2 * i + 1)
        return marco

    # --- salidas 
    def crear_error(self, fila):
        self.lbl_error = tk.Label(self, text="", fg="#b00020", anchor="w",
                                  justify="left", wraplength=900)
        self.lbl_error.grid(row=fila, column=0, sticky="ew", pady=(6, 0))

    def crear_resultados(self, fila, titulo, campos):
        marco = ttk.LabelFrame(self, text=titulo, padding=8)
        marco.grid(row=fila, column=0, sticky="ew", pady=8)
        marco.columnconfigure(1, weight=1)
        for i, (clave, etiqueta) in enumerate(campos):
            ttk.Label(marco, text=etiqueta).grid(row=i, column=0, sticky="w", padx=(0, 8), pady=2)
            var = tk.StringVar()
            ttk.Entry(marco, textvariable=var, state="readonly").grid(row=i, column=1, sticky="ew", pady=2)
            self.campos[clave] = var
        return marco

    def crear_tabla(self, fila, columnas):
        marco = ttk.LabelFrame(self, text="Detalle del proceso", padding=6)
        marco.grid(row=fila, column=0, sticky="nsew", pady=4)
        marco.columnconfigure(0, weight=1)
        marco.rowconfigure(0, weight=1)
        self.rowconfigure(fila, weight=1)
        ids = [c[0] for c in columnas]
        self.tabla = ttk.Treeview(marco, columns=ids, show="headings", height=8)
        for ident, titulo, ancho in columnas:
            self.tabla.heading(ident, text=titulo)
            self.tabla.column(ident, width=ancho, anchor="center")
        barra = ttk.Scrollbar(marco, orient="vertical", command=self.tabla.yview)
        self.tabla.configure(yscrollcommand=barra.set)
        self.tabla.grid(row=0, column=0, sticky="nsew")
        barra.grid(row=0, column=1, sticky="ns")

    def poner(self, clave, valor):
        self.campos[clave].set(valor)

    def limpiar_resultados(self):
        for var in self.campos.values():
            var.set("")
        for item in self.tabla.get_children():
            self.tabla.delete(item)

    def mostrar_error(self, mensaje):
        self.limpiar_resultados()
        self.lbl_error.config(text="⚠ " + mensaje)

    def copiar(self, texto):
        self.clipboard_clear()
        self.clipboard_append(texto)

    def leer_parametros(self):
        p = parsear_entero(self.var_p.get(), "p")
        q = parsear_entero(self.var_q.get(), "q")
        e = parsear_entero(self.var_e.get(), "e")
        return p, q, e


class PanelEncriptar(PanelBase):
    def __init__(self, master, app):
        super().__init__(master, app)
        self.ultimo = None

        entrada = ttk.Frame(self)
        entrada.grid(row=0, column=0, sticky="ew")
        entrada.columnconfigure(1, weight=1)
        ttk.Label(entrada, text="Mensaje M:").grid(row=0, column=0, sticky="nw", padx=(0, 8))
        self.txt_m = tk.Text(entrada, height=3, wrap="word")
        self.txt_m.grid(row=0, column=1, sticky="ew")
        self.txt_m.insert("1.0", "RSA")
        ttk.Label(entrada, text="Parámetros:").grid(row=1, column=0, sticky="w", pady=(8, 0))
        self.fila_parametros(entrada).grid(row=1, column=1, sticky="w", pady=(8, 0))

        botones = ttk.Frame(self)
        botones.grid(row=1, column=0, sticky="w", pady=8)
        ttk.Button(botones, text="Encriptar", command=self.ejecutar).pack(side="left")
        ttk.Button(botones, text="Copiar C", command=self.copiar_c).pack(side="left", padx=6)
        ttk.Button(botones, text="Enviar a Desencriptar", command=self.enviar).pack(side="left")

        self.crear_error(2)
        self.crear_resultados(3, "Resultado", [
            ("cifrado", "Cifrado C:"),
            ("L", "Longitud L:"),
            ("llave", "Llave pública (e, n):"),
            ("n", "n = p·q:"),
            ("phi", "φ = (p−1)(q−1):"),
            ("relleno", "Relleno:"),
            ("con_relleno", "Mensaje con relleno:"),
        ])
        self.crear_tabla(4, [
            ("i", "Bloque", 60),
            ("par", "Caracteres", 100),
            ("ascii", "ASCII (3 dígitos)", 130),
            ("m", "m (antes de cifrar)", 150),
            ("c", "c = m^e mod n", 140),
            ("c6", "c (6 dígitos)", 120),
        ])

    def ejecutar(self):
        self.lbl_error.config(text="")
        try:
            p, q, e = self.leer_parametros()
            mensaje = self.txt_m.get("1.0", "end-1c")
            r = encriptar(mensaje, p, q, e)
        except ErrorRSA as ex:
            self.ultimo = None
            self.mostrar_error(str(ex))
            return
        except Exception as ex:  # nunca cerrar el programa por un error inesperado
            self.ultimo = None
            self.mostrar_error(f"Error inesperado: {ex}")
            return

        self.limpiar_resultados()
        self.ultimo = r
        self.poner("cifrado", r.cifrado)
        self.poner("L", str(r.L))
        self.poner("llave", f"({r.e}, {r.n})")
        self.poner("n", str(r.n))
        self.poner("phi", str(r.phi))
        self.poner("relleno", "Sí: se agregó 1 espacio al final (L es impar)" if r.relleno
                   else "No (L es par)")
        self.poner("con_relleno", entre_comillas(r.mensaje_relleno))
        for f in r.filas:
            self.tabla.insert("", "end", values=(
                f.indice,
                caracteres_visibles(f.caracteres),
                f"{f.codigos[0]:03d} {f.codigos[1]:03d}",
                f"{f.m:06d}",
                f.c,
                f"{f.c:06d}",
            ))

    def copiar_c(self):
        if self.ultimo:
            self.copiar(self.ultimo.cifrado)

    def enviar(self):
        if not self.ultimo:
            self.mostrar_error("Primero encripta un mensaje válido.")
            return
        r = self.ultimo
        self.app.cargar_en_desencriptar(r.cifrado, r.L, r.p, r.q, r.e)


class PanelDesencriptar(PanelBase):
    def __init__(self, master, app):
        super().__init__(master, app)

        entrada = ttk.Frame(self)
        entrada.grid(row=0, column=0, sticky="ew")
        entrada.columnconfigure(1, weight=1)
        ttk.Label(entrada, text="Cifrado C:").grid(row=0, column=0, sticky="nw", padx=(0, 8))
        self.txt_c = tk.Text(entrada, height=3, wrap="word")
        self.txt_c.grid(row=0, column=1, sticky="ew")
        ttk.Label(entrada, text="Longitud L:").grid(row=1, column=0, sticky="w", pady=(8, 0))
        self.var_L = tk.StringVar()
        ttk.Entry(entrada, textvariable=self.var_L, width=12).grid(row=1, column=1, sticky="w", pady=(8, 0))
        ttk.Label(entrada, text="Parámetros:").grid(row=2, column=0, sticky="w", pady=(8, 0))
        self.fila_parametros(entrada).grid(row=2, column=1, sticky="w", pady=(8, 0))

        botones = ttk.Frame(self)
        botones.grid(row=1, column=0, sticky="w", pady=8)
        ttk.Button(botones, text="Desencriptar", command=self.ejecutar).pack(side="left")
        ttk.Button(botones, text="Copiar M", command=self.copiar_m).pack(side="left", padx=6)

        self.crear_error(2)
        self.crear_resultados(3, "Resultado", [
            ("mensaje", "Mensaje M:"),
            ("mensaje_q", "M entre comillas:"),
            ("d", "Exponente privado d:"),
            ("llave", "Llave privada (d, n):"),
            ("n", "n = p·q:"),
            ("phi", "φ = (p−1)(q−1):"),
            ("L", "Longitud L:"),
            ("relleno", "Relleno:"),
            ("con_relleno", "Texto recuperado (con relleno):"),
        ])
        self.crear_tabla(4, [
            ("i", "Bloque", 60),
            ("c6", "c (6 dígitos)", 110),
            ("m", "m = c^d mod n", 130),
            ("m6", "m (6 dígitos)", 110),
            ("ascii", "ASCII", 110),
            ("par", "Caracteres", 100),
        ])

    def cargar(self, cifrado, L, p, q, e):
        self.txt_c.delete("1.0", "end")
        self.txt_c.insert("1.0", cifrado)
        self.var_L.set(str(L))
        self.var_p.set(str(p))
        self.var_q.set(str(q))
        self.var_e.set(str(e))
        self.lbl_error.config(text="")

    def ejecutar(self):
        self.lbl_error.config(text="")
        try:
            p, q, e = self.leer_parametros()
            cifrado = self.txt_c.get("1.0", "end-1c")
            r = desencriptar(cifrado, self.var_L.get(), p, q, e)
        except ErrorRSA as ex:
            self.mostrar_error(str(ex))
            return
        except Exception as ex:
            self.mostrar_error(f"Error inesperado: {ex}")
            return

        self.limpiar_resultados()
        self.poner("mensaje", r.mensaje)
        self.poner("mensaje_q", entre_comillas(r.mensaje))
        self.poner("d", str(r.d))
        self.poner("llave", f"({r.d}, {r.n})")
        self.poner("n", str(r.n))
        self.poner("phi", str(r.phi))
        self.poner("L", str(r.L))
        self.poner("relleno", "Sí: se retiró exactamente el último carácter (espacio de relleno)"
                   if r.relleno else "No (L es par): no se retiró ningún carácter")
        self.poner("con_relleno", entre_comillas(r.texto_recuperado))
        self.mensaje_actual = r.mensaje
        for f in r.filas:
            self.tabla.insert("", "end", values=(
                f.indice,
                f"{f.c:06d}",
                f.m,
                f"{f.m:06d}",
                f"{f.codigos[0]:03d} {f.codigos[1]:03d}",
                caracteres_visibles(f.caracteres),
            ))

    def copiar_m(self):
        self.copiar(self.campos["mensaje"].get())


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("RSA – MM2015 Matemática Discreta 1")
        self.geometry("980x760")
        self.minsize(860, 660)
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=8, pady=8)
        self.tab_enc = PanelEncriptar(self.nb, self)
        self.tab_dec = PanelDesencriptar(self.nb, self)
        self.nb.add(self.tab_enc, text="Encriptar")
        self.nb.add(self.tab_dec, text="Desencriptar")

    def cargar_en_desencriptar(self, cifrado, L, p, q, e):
        self.tab_dec.cargar(cifrado, L, p, q, e)
        self.nb.select(self.tab_dec)


if __name__ == "__main__":
    App().mainloop()
