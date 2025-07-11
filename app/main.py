from flask import Flask, request, jsonify
from base64 import b64encode
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from flask import send_from_directory
import os
import traceback

app = Flask(__name__)
CERT_FILE_PATH = "/opt/secure_certs/banorte.pem"
SECURE_TOKEN = "dZxGyHfKwoDxX0BWI9nMHPQ9kz9uxWBVYxBMgEdqHRE=" # Token for secure access

@app.route('/')
def index():
    return send_from_directory('static_site', 'index.html')

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "OK"})

@app.route('/certificate', methods=['GET'])
def get_certificate():
    if request.args.get('token') != SECURE_TOKEN:
        return jsonify({"error": "Unauthorized"}), 401
    
    if not os.path.exists(CERT_FILE_PATH):
        return jsonify({"error": "Certificate file not found"}), 404
    
    with open(CERT_FILE_PATH, 'rb') as cert_file:
        cert_content = cert_file.read()
    
    return jsonify({"certificate": cert_content.decode('utf-8')}), 200

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        data = request.json
        message = data['message']
        cert_path = data['cert_path']
        
        print(f"Mensaje a cifrar: {message}")
        print(f"Certificado: {cert_path}")
        
        # Verificar que el archivo existe
        if not os.path.exists(cert_path):
            return jsonify({"error": f"El archivo {cert_path} no existe"}), 400
        
        # Leer clave pública desde el archivo
        with open(cert_path, 'rb') as f:
            cert_content = f.read()
        
        # Intentar cargar como clave pública PEM
        try:
            public_key = serialization.load_pem_public_key(cert_content)
        except Exception as e:
            # Si falla, intentar como certificado
            try:
                from cryptography import x509
                cert = x509.load_pem_x509_certificate(cert_content)
                public_key = cert.public_key()
            except Exception as e2:
                return jsonify({"error": f"No se pudo cargar el certificado: {str(e2)}"}), 400
        
        print(f"Clave pública cargada exitosamente")
        
        # Cifrar usando OAEP con SHA256 + MGF1(SHA1) según especificación Banorte
        # RSA/ECB/OAEPWITHSHA256ANDMGF1WITHSHA1PADDING
        encrypted = public_key.encrypt(
            message.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),  # MGF1 con SHA1
                algorithm=hashes.SHA256(),                  # Hash principal SHA256
                label=None
            )
        )
        
        encrypted_base64 = b64encode(encrypted).decode('utf-8')
        print(f"Cifrado exitoso, longitud: {len(encrypted_base64)}")
        
        return jsonify({
            "encrypted_base64": encrypted_base64,
            "success": True
        })
        
    except Exception as e:
        print(f"Error: {str(e)}")
        print(traceback.format_exc())
        return jsonify({
            "error": str(e),
            "success": False
        }), 500

if __name__ == '__main__':
    print("Iniciando servidor Python para cifrado RSA Banorte...")
    print("Puerto: 5000")
    app.run(host='0.0.0.0', port=5000, debug=True)