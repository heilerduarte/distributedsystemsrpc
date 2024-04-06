import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import xmlrpc.client
import ssl
from cryptography.fernet import Fernet
import threading
from datetime import datetime, timedelta
import socket
import base64
import time

# Configuración inicial
clave_encriptacion = b'DG-cgQo2hRFJCCq4sZlyQWZtPUzTczxoSeG0RmQvaQA='
cipher_suite = Fernet(clave_encriptacion)
usuario_enc = cipher_suite.encrypt(b'usuario123')
contraseña_enc = cipher_suite.encrypt(b'contrasenaSegura')

# Configura SSLContext
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile='./cert.pem')
context.check_hostname = False
context.verify_mode = ssl.CERT_REQUIRED

# Variables para la sesión
last_auth_time = None
SESSION_TIMEOUT = 5  # en minutos
AUTH_RENEWAL_THRESHOLD = 0.8

proxy = None

# Funciones de utilidad
def get_new_proxy():
    server = xmlrpc.client.ServerProxy("https://192.168.56.1:8000/", context=context, allow_none=True)
    return server

def show_status_message(message):
    status_var.set(message)
    root.after(10000, lambda: status_var.set("Listo"))

def show_error_message(message):
    error_var.set(message)
    root.after(10000, lambda: error_var.set(""))

def get_client_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception as e:
        show_error_message(f"No se pudo obtener la dirección IP del cliente: {e}")
        return "Desconocido"

# Funciones principales
def attempt_connection():
    global proxy
    while True:
        try:
            proxy = xmlrpc.client.ServerProxy("https://192.168.56.1:8000/", context=context, allow_none=True)
            # Intenta una operación simple para verificar la conexión, como autenticarse.
            if proxy.autenticar(xmlrpc.client.Binary(usuario_enc), xmlrpc.client.Binary(contraseña_enc)):
                print("Conectado al servidor.")
                show_status_message("Conectado al servidor.")
                client_ip = get_client_ip()
                welcome_message = proxy.client_connected(client_ip)
                print(f"{client_ip} conectado al servidor.")
                show_status_message(welcome_message)
                global last_auth_time
                last_auth_time = datetime.now()
                break  # Salir del bucle si la conexión y autenticación son exitosas.
        except Exception as e:
            print(f"Reintentando conexión: {e}")
            show_error_message("Reintentando conexión...")
        time.sleep(5)  # Espera 5 segundos antes de reintentar.    

def attempt_connection_old(retries=3, delay=5):
    global proxy
    for attempt in range(retries):
        try:
            proxy = get_new_proxy()
            if proxy.autenticar(xmlrpc.client.Binary(usuario_enc), xmlrpc.client.Binary(contraseña_enc)):
                client_ip = get_client_ip()
                welcome_message = proxy.client_connected(client_ip)
                print(f"{client_ip} conectado al servidor.")
                show_status_message(welcome_message)
                global last_auth_time
                last_auth_time = datetime.now()
                return True
        except Exception as e:
            show_error_message(f"Intento {attempt+1} fallido: {e}")
            time.sleep(delay)  # Espera antes de reintento
    return False

def attempt_renew_auth():
    global last_auth_time
    now = datetime.now()
    if last_auth_time and (now - last_auth_time) > timedelta(minutes=SESSION_TIMEOUT * AUTH_RENEWAL_THRESHOLD):
        try:
            if proxy.autenticar(xmlrpc.client.Binary(usuario_enc), xmlrpc.client.Binary(contraseña_enc)):
                show_status_message("Sesión renovada correctamente.")
                last_auth_time = now
            else:
                show_error_message("Fallo al renovar la sesión.")
        except Exception as e:
            show_error_message(f"Error al renovar la sesión: {e}")
    threading.Timer(60 * SESSION_TIMEOUT * AUTH_RENEWAL_THRESHOLD, attempt_renew_auth).start()

def initialize_proxy():
    global proxy, last_auth_time
    if attempt_connection():
        last_auth_time = datetime.now()
        attempt_renew_auth()  # Inicia la verificación y renovación de la sesión
        verify_connection()   # Verifica la conexión inmediatamente y periódicamente

def update_file_list():
    if proxy:
        try:
            files = proxy.list_files()  # Suponiendo que esta es la llamada que podría devolver el mensaje de sesión expirada
            if files == "Sesión expirada. Por favor, autentíquese de nuevo.":
                show_error_message(files)  # Muestra el mensaje de error en la UI
                # Intenta reconectar
                print("Intentando reconectar debido a sesión expirada...")
                threading.Thread(target=initialize_proxy, daemon=True).start()
            else:
                file_list.delete(0, tk.END)  # Limpia la lista actual
                for file in files:  # Itera sobre la nueva lista de archivos
                    file_list.insert(tk.END, file)
                show_status_message("Lista de archivos actualizada.")
                show_error_message("")
        except Exception as e:
            show_error_message(f"Error al actualizar lista de archivos: {e}")
    root.after(5000, update_file_list)  # Programa la próxima actualización

def update_file_list_old():
    if proxy:
        try:
            files = proxy.list_files()
            file_list.delete(0, tk.END)
            for file in files:
                file_list.insert(tk.END, file)
            show_status_message("Lista de archivos actualizada.")
        except Exception as e:
            show_error_message(f"Error al actualizar lista de archivos: {e}")
    root.after(5000, update_file_list)

def download_file():
    selected_file = file_list.get(tk.ANCHOR)
    if not selected_file:
        show_error_message("Seleccione un archivo para descargar.")
        return
    threading.Thread(target=lambda: perform_download(selected_file), daemon=True).start()

def perform_download(selected_file):
    try:
        encoded_content = proxy.get_file_base64(selected_file)
        if encoded_content.startswith("Error"):
            show_error_message(encoded_content)
            return
        content = base64.b64decode(encoded_content)
        root.after(0, lambda: save_downloaded_file(selected_file, content))
    except Exception as e:
        show_error_message(f"Error al descargar archivo: {e}")

def save_downloaded_file(selected_file, content):
    save_path = filedialog.asksaveasfilename(initialfile=selected_file)
    if save_path:
        with open(save_path, 'wb') as file:
            file.write(content)
        show_status_message(f"Archivo '{selected_file}' descargado exitosamente.")

def on_closing():
    if proxy:
        try:
            client_ip = get_client_ip()
            proxy.client_disconnected(client_ip)
            print(f"{client_ip} desconectado del servidor.")
        except Exception as e:
            print(f"Error al enviar mensaje de desconexión: {e}")
    root.destroy()

def verify_connection():
    global proxy
    try:
        if proxy:
            proxy.system.listMethods()
            show_status_message("Conexión con el servidor activa")
        else:
            show_status_message("Reconectando...")
            initialize_proxy()
    except Exception as e:
        show_error_message("La conexión con el servidor se ha perdido")
    finally:
        threading.Timer(5, verify_connection).start()

# Configuración de la interfaz de usuario Tkinter
root = tk.Tk()
root.title("Cliente RPC - Gestor de Archivos")
root.protocol("WM_DELETE_WINDOW", on_closing)

file_list = tk.Listbox(root, width=50, height=15)
file_list.pack(pady=20)

download_button = ttk.Button(root, text="Descargar Archivo Seleccionado", command=download_file)
download_button.pack(pady=10)

status_var = tk.StringVar(value="Conectando...")
status_bar = ttk.Label(root, textvariable=status_var, relief=tk.SUNKEN, anchor="w")
status_bar.pack(fill=tk.X, side=tk.BOTTOM, ipady=2)

error_var = tk.StringVar()
error_bar = ttk.Label(root, textvariable=error_var, relief=tk.SUNKEN, anchor="w", foreground="red")
error_bar.pack(fill=tk.X, side=tk.BOTTOM, ipady=2)

# Iniciar conexión y renovación de sesión en hilo separado
threading.Thread(target=initialize_proxy, daemon=True).start()
threading.Thread(target=verify_connection, daemon=True).start()
root.after(3000, update_file_list)  # Actualizar lista de archivos periódicamente

root.mainloop()
