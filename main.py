import streamlit as st
from rsa_core import ErrorRSA, desencriptar, encriptar, parsear_entero


def entre_comillas(texto: str) -> str:
    return f'"{texto}"'


def caracteres_visibles(texto: str) -> str:
    return " ".join(f"'{ch}'" for ch in texto)


def init_state() -> None:
    defaults = {
        "p_val": "367",
        "q_val": "373",
        "e_val": "17",
        "msg_val": "RSA",
        "enc_result": None,
        "enc_error": "",
        "enc_copy_c": "",
        "dec_c_val": "",
        "dec_l_val": "",
        "dec_p_val": "367",
        "dec_q_val": "373",
        "dec_e_val": "17",
        "dec_result": None,
        "dec_error": "",
        "dec_copy_m": "",
        "modo_actual": "Encriptar",
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


def leer_parametros(p_txt: str, q_txt: str, e_txt: str):
    p = parsear_entero(p_txt, "p")
    q = parsear_entero(q_txt, "q")
    e = parsear_entero(e_txt, "e")
    return p, q, e


def fila_parametros(prefix: str, p_key: str, q_key: str, e_key: str):
    c_lbl, c_p, c_q, c_e = st.columns([1.2, 1.5, 1.5, 1.5])
    with c_lbl:
        st.markdown("**Parámetros:**")
    with c_p:
        p_val = st.text_input("p:", value=st.session_state[p_key], key=f"{prefix}_p")
        st.session_state[p_key] = p_val
    with c_q:
        q_val = st.text_input("q:", value=st.session_state[q_key], key=f"{prefix}_q")
        st.session_state[q_key] = q_val
    with c_e:
        e_val = st.text_input("e:", value=st.session_state[e_key], key=f"{prefix}_e")
        st.session_state[e_key] = e_val


def campo_readonly(etiqueta: str, valor: str, key: str) -> None:
    c_etq, c_val = st.columns([1.4, 3.6])
    with c_etq:
        st.markdown(f"**{etiqueta}**")
    with c_val:
        st.text_input(
            etiqueta,
            value=valor,
            disabled=True,
            label_visibility="collapsed",
            key=key,
        )


def render_encriptar() -> None:
    with st.container(border=True):
        c_lbl, c_txt = st.columns([1.2, 4.5])
        with c_lbl:
            st.markdown("**Mensaje M:**")
        with c_txt:
            st.session_state["msg_val"] = st.text_area(
                "Mensaje M:",
                value=st.session_state["msg_val"],
                height=80,
                label_visibility="collapsed",
                key="enc_msg_area",
            )

        fila_parametros("enc", "p_val", "q_val", "e_val")

    b1, b2, b3, _ = st.columns([1.2, 1.2, 2.0, 2.5])
    with b1:
        ejecutar_click = st.button("Encriptar", use_container_width=True, key="btn_enc")
    with b2:
        copiar_click = st.button("Copiar C", use_container_width=True, key="btn_copiar_c")
    with b3:
        enviar_click = st.button(
            "Enviar a Desencriptar", use_container_width=True, key="btn_enviar_dec"
        )

    if ejecutar_click:
        st.session_state["enc_error"] = ""
        st.session_state["enc_copy_c"] = ""
        try:
            p, q, e = leer_parametros(
                st.session_state["p_val"],
                st.session_state["q_val"],
                st.session_state["e_val"],
            )
            st.session_state["enc_result"] = encriptar(
                st.session_state["msg_val"], p, q, e
            )
        except ErrorRSA as ex:
            st.session_state["enc_result"] = None
            st.session_state["enc_error"] = str(ex)
        except Exception as ex:
            st.session_state["enc_result"] = None
            st.session_state["enc_error"] = f"Error inesperado: {ex}"

    if copiar_click:
        if st.session_state["enc_result"]:
            st.session_state["enc_copy_c"] = st.session_state["enc_result"].cifrado

    if enviar_click:
        r = st.session_state["enc_result"]
        if not r:
            st.session_state["enc_error"] = "Primero encripta un mensaje válido."
        else:
            st.session_state["dec_c_val"] = r.cifrado
            st.session_state["dec_l_val"] = str(r.L)
            st.session_state["dec_p_val"] = str(r.p)
            st.session_state["dec_q_val"] = str(r.q)
            st.session_state["dec_e_val"] = str(r.e)
            st.session_state["dec_error"] = ""
            st.session_state["modo_actual"] = "Desencriptar"
            st.rerun()

    if st.session_state["enc_error"]:
        st.error("⚠ " + st.session_state["enc_error"])

    if st.session_state["enc_copy_c"]:
        st.caption("Cifrado C listo para copiar:")
        st.code(st.session_state["enc_copy_c"], language=None)

    r = st.session_state["enc_result"]
    if r is not None:
        with st.container(border=True):
            st.markdown("### Resultado")
            relleno_txt = (
                "Sí: se agregó 1 espacio al final (L es impar)"
                if r.relleno
                else "No (L es par)"
            )
            campo_readonly("Cifrado C:", r.cifrado, "res_enc_c")
            campo_readonly("Longitud L:", str(r.L), "res_enc_l")
            campo_readonly("Llave pública (e, n):", f"({r.e}, {r.n})", "res_enc_llave")
            campo_readonly("n = p·q:", str(r.n), "res_enc_n")
            campo_readonly("φ = (p−1)(q−1):", str(r.phi), "res_enc_phi")
            campo_readonly("Relleno:", relleno_txt, "res_enc_relleno")
            campo_readonly(
                "Mensaje con relleno:",
                entre_comillas(r.mensaje_relleno),
                "res_enc_con_relleno",
            )

        with st.container(border=True):
            st.markdown("### Detalle del proceso")
            filas = [
                {
                    "Bloque": f.indice,
                    "Caracteres": caracteres_visibles(f.caracteres),
                    "ASCII (3 dígitos)": f"{f.codigos[0]:03d} {f.codigos[1]:03d}",
                    "m (antes de cifrar)": f"{f.m:06d}",
                    "c = m^e mod n": f.c,
                    "c (6 dígitos)": f"{f.c:06d}",
                }
                for f in r.filas
            ]
            st.dataframe(filas, use_container_width=True, hide_index=True)


def render_desencriptar() -> None:
    with st.container(border=True):
        c_lbl, c_txt = st.columns([1.2, 4.5])
        with c_lbl:
            st.markdown("**Cifrado C:**")
        with c_txt:
            st.session_state["dec_c_val"] = st.text_area(
                "Cifrado C:",
                value=st.session_state["dec_c_val"],
                height=80,
                label_visibility="collapsed",
                key="dec_c_area",
            )

        l_lbl, l_inp, _ = st.columns([1.2, 1.5, 3.0])
        with l_lbl:
            st.markdown("**Longitud L:**")
        with l_inp:
            st.session_state["dec_l_val"] = st.text_input(
                "Longitud L:",
                value=st.session_state["dec_l_val"],
                label_visibility="collapsed",
                key="dec_l_input",
            )

        fila_parametros("dec", "dec_p_val", "dec_q_val", "dec_e_val")

    b1, b2, _ = st.columns([1.3, 1.2, 4.5])
    with b1:
        ejecutar_click = st.button("Desencriptar", use_container_width=True, key="btn_dec")
    with b2:
        copiar_click = st.button("Copiar M", use_container_width=True, key="btn_copiar_m")

    if ejecutar_click:
        st.session_state["dec_error"] = ""
        st.session_state["dec_copy_m"] = ""
        try:
            p, q, e = leer_parametros(
                st.session_state["dec_p_val"],
                st.session_state["dec_q_val"],
                st.session_state["dec_e_val"],
            )
            st.session_state["dec_result"] = desencriptar(
                st.session_state["dec_c_val"],
                st.session_state["dec_l_val"],
                p,
                q,
                e,
            )
        except ErrorRSA as ex:
            st.session_state["dec_result"] = None
            st.session_state["dec_error"] = str(ex)
        except Exception as ex:
            st.session_state["dec_result"] = None
            st.session_state["dec_error"] = f"Error inesperado: {ex}"

    if copiar_click:
        if st.session_state["dec_result"]:
            st.session_state["dec_copy_m"] = st.session_state["dec_result"].mensaje

    if st.session_state["dec_error"]:
        st.error("⚠ " + st.session_state["dec_error"])

    if st.session_state["dec_copy_m"]:
        st.caption("Mensaje M listo para copiar:")
        st.code(st.session_state["dec_copy_m"], language=None)

    r = st.session_state["dec_result"]
    if r is not None:
        with st.container(border=True):
            st.markdown("### Resultado")
            relleno_txt = (
                "Sí: se retiró exactamente el último carácter (espacio de relleno)"
                if r.relleno
                else "No (L es par): no se retiró ningún carácter"
            )
            campo_readonly("Mensaje M:", r.mensaje, "res_dec_m")
            campo_readonly("M entre comillas:", entre_comillas(r.mensaje), "res_dec_mq")
            campo_readonly("Exponente privado d:", str(r.d), "res_dec_d")
            campo_readonly("Llave privada (d, n):", f"({r.d}, {r.n})", "res_dec_llave")
            campo_readonly("n = p·q:", str(r.n), "res_dec_n")
            campo_readonly("φ = (p−1)(q−1):", str(r.phi), "res_dec_phi")
            campo_readonly("Longitud L:", str(r.L), "res_dec_l")
            campo_readonly("Relleno:", relleno_txt, "res_dec_relleno")
            campo_readonly(
                "Texto recuperado (con relleno):",
                entre_comillas(r.texto_recuperado),
                "res_dec_con_relleno",
            )

        with st.container(border=True):
            st.markdown("### Detalle del proceso")
            filas = [
                {
                    "Bloque": f.indice,
                    "c (6 dígitos)": f"{f.c:06d}",
                    "m = c^d mod n": f.m,
                    "m (6 dígitos)": f"{f.m:06d}",
                    "ASCII": f"{f.codigos[0]:03d} {f.codigos[1]:03d}",
                    "Caracteres": caracteres_visibles(f.caracteres),
                }
                for f in r.filas
            ]
            st.dataframe(filas, use_container_width=True, hide_index=True)


def main() -> None:
    st.set_page_config(
        page_title="RSA – MM2015 Matemática Discreta 1",
        layout="wide",
    )
    init_state()
    st.markdown("### RSA – MM2015 Matemática Discreta 1")

    seleccion = st.radio(
        "Pestañas",
        ["Encriptar", "Desencriptar"],
        index=0 if st.session_state["modo_actual"] == "Encriptar" else 1,
        horizontal=True,
        label_visibility="collapsed",
        key="selector_pestana",
    )
    if seleccion != st.session_state["modo_actual"]:
        st.session_state["modo_actual"] = seleccion
        st.rerun()

    if st.session_state["modo_actual"] == "Encriptar":
        render_encriptar()
    else:
        render_desencriptar()


if __name__ == "__main__":
    main()