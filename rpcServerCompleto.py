from xmlrpc.server import SimpleXMLRPCServer
from socketserver import ThreadingMixIn
import ssl
import os
import base64
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
import threading

class SecureXMLRPCServer(ThreadingMixIn, SimpleXMLRPCServer):
    pass

# Clave Fernet para encriptación/desencriptación de credenciales
# para ello se generó por medio de genClave.py, esto permitió generar los archivos
# cert.pem y key.gen que se deben compartir al cliente 
clave_encriptacion = b'DG-cgQo2hRFJCCq4sZlyQWZtPUzTczxoSeG0RmQvaQA='

# Ruta a la carpeta compartida
SHARED_FOLDER = "archivos_compartidos"
os.makedirs(SHARED_FOLDER, exist_ok=True)

# Sesiones de cliente
client_sessions = {}
session_lock = threading.Lock()
SESSION_TIMEOUT = 5  # minutos

def autenticar(usuario_enc, contraseña_enc):
    cipher_suite = Fernet(clave_encriptacion)
    usuario = cipher_suite.decrypt(usuario_enc.data).decode()
    contraseña = cipher_suite.decrypt(contraseña_enc.data).decode()
    if usuario == "usuario123" and contraseña == "contrasenaSegura":
        with session_lock:
            client_sessions[usuario] = datetime.now()
        return True
    return False

def verificar_sesion(usuario):
    with session_lock:
        if usuario in client_sessions:
            last_activity = client_sessions[usuario]
            if datetime.now() - last_activity < timedelta(minutes=SESSION_TIMEOUT):
                client_sessions[usuario] = datetime.now()
                return True
    return False

def list_files(directory="."):
    if not verificar_sesion("usuario123"):
        return "Sesión expirada. Por favor, autentíquese de nuevo."
    try:
        return os.listdir(os.path.join(SHARED_FOLDER, directory))
    except Exception as e:
        return str(e)

def get_file_base64(filepath):
    if not verificar_sesion("usuario123"):
        return "Sesión expirada. Por favor, autentíquese de nuevo."
    try:
        full_path = os.path.join(SHARED_FOLDER, filepath)
        with open(full_path, 'rb') as file:
            return base64.b64encode(file.read()).decode('utf-8')
    except Exception as e:
        return str(e)

def client_connected(client_ip):
    print(f"Cliente con IP {client_ip} conectado.")
    # Aquí se podría inicializar una sesión si es necesario
    return f"Bienvenido, tu IP es {client_ip}."

def client_disconnected(client_ip):
    print(f"Cliente con IP {client_ip} desconectado.")
    # Opcional: limpiar datos de sesión aquí

# Configuración del servidor con SSL
server_address = ('10.0.2.15', 8000)
server = SecureXMLRPCServer(server_address, allow_none=True)

# Envolver el socket del servidor con TLS/SSL
# Crear un SSLContext
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile='./cert.pem', keyfile='./key.pem')

# Envolver el socket del servidor con SSLContext
server.socket = context.wrap_socket(server.socket, server_side=True)

# Registro de funciones
server.register_function(autenticar, "autenticar")
server.register_function(list_files, "list_files")
server.register_function(get_file_base64, "get_file_base64")
server.register_function(client_connected, "client_connected")
server.register_function(client_disconnected, "client_disconnected")

try:
    print("Servidor iniciado en https://10.0.2.15:8000")
    server.serve_forever()
except KeyboardInterrupt:
    print("Servidor detenido.")
    server.server_close()
