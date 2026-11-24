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
        "dec_c_val": "",
        "dec_l_val": "",
        "dec_p_val": "367",
        "dec_q_val": "373",
        "dec_e_val": "17",
        "dec_result": None,
        "dec_error": "",
        "active_tab": "Encriptar",
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


def leer_parametros(p_txt: str, q_txt: str, e_txt: str):
    p = parsear_entero(p_txt, "p")
    q = parsear_entero(q_txt, "q")
    e = parsear_entero(e_txt, "e")
    return p, q, e


def render_encriptar() -> None:
    st.session_state["msg_val"] = st.text_area(
        "Mensaje M:",
        value=st.session_state["msg_val"],
        height=90,
    )

    col1, col2, col3 = st.columns(3)
    with col1:
        st.session_state["p_val"] = st.text_input("p:", value=st.session_state["p_val"])
    with col2:
        st.session_state["q_val"] = st.text_input("q:", value=st.session_state["q_val"])
    with col3:
        st.session_state["e_val"] = st.text_input("e:", value=st.session_state["e_val"])

    c_btn1, c_btn2, _ = st.columns([1.2, 1.8, 3])
    with c_btn1:
        if st.button("Encriptar", type="primary", use_container_width=True):
            st.session_state["enc_error"] = ""
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

    with c_btn2:
        if st.button("Enviar a Desencriptar", use_container_width=True):
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
                st.session_state["active_tab"] = "Desencriptar"
                st.rerun()

    if st.session_state["enc_error"]:
        st.error(st.session_state["enc_error"])

    r = st.session_state["enc_result"]
    if r is not None:
        st.subheader("Resultado")
        st.text_input("Cifrado C:", value=r.cifrado, disabled=True)

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Longitud L", r.L)
        m2.metric("Llave pública (e, n)", f"({r.e}, {r.n})")
        m3.metric("n = p·q", r.n)
        m4.metric("φ = (p−1)(q−1)", r.phi)

        relleno_txt = (
            "Sí: se agregó 1 espacio al final (L es impar)"
            if r.relleno
            else "No (L es par)"
        )
        st.write(f"**Relleno:** {relleno_txt}")
        st.write(f"**Mensaje con relleno:** `{entre_comillas(r.mensaje_relleno)}`")

        st.subheader("Detalle del proceso")
        filas_dict = [
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
        st.dataframe(filas_dict, use_container_width=True, hide_index=True)


def render_desencriptar() -> None:
    st.session_state["dec_c_val"] = st.text_area(
        "Cifrado C:",
        value=st.session_state["dec_c_val"],
        height=90,
    )
    st.session_state["dec_l_val"] = st.text_input(
        "Longitud L:",
        value=st.session_state["dec_l_val"],
    )

    col1, col2, col3 = st.columns(3)
    with col1:
        st.session_state["dec_p_val"] = st.text_input(
            "p:", value=st.session_state["dec_p_val"], key="dec_p_input"
        )
    with col2:
        st.session_state["dec_q_val"] = st.text_input(
            "q:", value=st.session_state["dec_q_val"], key="dec_q_input"
        )
    with col3:
        st.session_state["dec_e_val"] = st.text_input(
            "e:", value=st.session_state["dec_e_val"], key="dec_e_input"
        )

    if st.button("Desencriptar", type="primary"):
        st.session_state["dec_error"] = ""
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

    if st.session_state["dec_error"]:
        st.error(st.session_state["dec_error"])

    r = st.session_state["dec_result"]
    if r is not None:
        st.subheader("Resultado")
        st.text_input("Mensaje M:", value=r.mensaje, disabled=True)
        st.write(f"**M entre comillas:** `{entre_comillas(r.mensaje)}`")

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Exponente privado d", r.d)
        m2.metric("Llave privada (d, n)", f"({r.d}, {r.n})")
        m3.metric("n = p·q", r.n)
        m4.metric("φ = (p−1)(q−1)", r.phi)

        relleno_txt = (
            "Sí: se retiró exactamente el último carácter (espacio de relleno)"
            if r.relleno
            else "No (L es par): no se retiró ningún carácter"
        )
        st.write(f"**Longitud L:** {r.L}")
        st.write(f"**Relleno:** {relleno_txt}")
        st.write(f"**Texto recuperado (con relleno):** `{entre_comillas(r.texto_recuperado)}`")

        st.subheader("Detalle del proceso")
        filas_dict = [
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
        st.dataframe(filas_dict, use_container_width=True, hide_index=True)


def main() -> None:
    st.set_page_config(
        page_title="RSA – MM2015 Matemática Discreta 1",
        layout="wide",
    )
    init_state()
    st.title("RSA – MM2015 Matemática Discreta 1")

    modo = st.radio(
        "Operación",
        ["Encriptar", "Desencriptar"],
        index=0 if st.session_state["active_tab"] == "Encriptar" else 1,
        horizontal=True,
        label_visibility="collapsed",
    )
    st.session_state["active_tab"] = modo

    if modo == "Encriptar":
        render_encriptar()
    else:
        render_desencriptar()


if __name__ == "__main__":
    main()