from flask import Flask, app, jsonify, request
import sqlite3
import jwt, datetime
from functools import wraps
import re

"""
Trabajo realizado sobre Api de registro de Vulnerabilidades. Decidimos implementarlo en este tema ya
que pensamos en las fallas que llevan y que a la vez se encuentran en un sistema, como su codigo y que
tan grave es, esta api en si no guarda exploits ni nada de codigo de ataque por el estilo, solamente 
datos de control

Integrantes:
- Daimerson Avila
- Juan Bonilla
- Sofia Siza
- Sebastian Cetina 

Materia:
Cloud Computing para el desarrollo de software
"""

DB_NAME = 'vulnerabilidades.db'
app = Flask(__name__)
app.config['SECRET_KEY'] = 'RegistroVulnerabilidadesSecretKey'
Users = {'admin': 'demo123'}

SEVERIDADES = ['baja', 'media', 'alta', 'critica']
ESTADOS = ['abierta', 'en_revision', 'cerrada', 'mitigada']
PATRON_CVE = re.compile(r'^CVE-\d{4}-\d{4,}$')

def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilidades (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            titulo TEXT NOT NULL,
            cve_codigo TEXT NOT NULL,
            severidad TEXT NOT NULL
                CHECK (severidad IN ('baja', 'media', 'alta', 'critica')),
            estado TEXT NOT NULL
                CHECK (estado IN ('abierta', 'en_revision', 'cerrada','mitigada')),
            puntaje_cvss REAL NOT NULL
                CHECK (puntaje_cvss >= 0 AND puntaje_cvss <= 10)
        )
''')
    conn.commit()
    conn.close()


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({'error': 'Envia un objeto JSON'}), 400
    username = data.get('username')
    clave = data.get('clave')
    if not isinstance(username, str) or not isinstance(clave, str):
        return jsonify({'error': 'username y clave son obligatiorios'}), 400
    if username in Users and Users[username] == clave:
        token = jwt.encode({
            'user': username,
            'exp': datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(hours=1)
        }, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'token': token}), 200
    return jsonify({'token': 'Credenciales invalidas'}), 401

def token_required(f):
    @wraps(f)
    def decorador(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        partes = auth.split()
        if len(partes) != 2 or partes[0].lower() != 'bearer':
            return jsonify({'error': 'Usa bearer seguido del token'}), 401
        try:
            jwt.decode(partes[1], app.config['SECRET_KEY'],
                       algorithms='HS256',
                       options={'require': ['exp', 'user']})
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expirado'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Token invalido'}), 401
        return f(*args, **kwargs)
    return decorador

@app.route('/')
def root():
    return jsonify({'message': 'Api de registro de vulnerabilidades', 'recurso': '/vulnerabilidades'}), 200

def validar_vulnerabilidad(data):
    if not isinstance(data, dict):
        return 'Envía un objeto JSON'
    for campo in ('titulo', 'cve_codigo', 'severidad', 'estado'):
        valor = data.get(campo)
        if not isinstance(valor, str) or not valor.strip():
            return f'{campo} debe ser un texto no vacío'
    if not PATRON_CVE.match(data['cve_codigo'].strip()):
        return 'cve_codigo debe tener el formato CVE-AAAA-NNNN (ej: CVE-2024-12345)'
    if data['severidad'].strip() not in SEVERIDADES:
        return 'severidad debe ser una de: ' + ', '.join(SEVERIDADES)
    if data['estado'].strip() not in ESTADOS:
        return 'estado debe ser uno de: ' + ', '.join(ESTADOS)
    puntaje = data.get('puntaje_cvss')
    if type(puntaje) not in (int, float) or puntaje < 0 or puntaje > 10:
        return 'puntaje_cvss debe ser un número entre 0 y 10'
    return None

@app.route('/vulnerabilidades', methods=['GET'])
def list_vulnerabilidades():
    conn = get_db()
    filas = conn.execute('SELECT * FROM vulnerabilidades').fetchall()
    conn.close()
    return jsonify([dict(fila) for fila in filas]), 200

@app.route('/vulnerabilidades/<int:vuln_id>', methods=['GET'])
def get_vulnerabilidad(vuln_id):
    conn = get_db()
    fila = conn.execute(
        'SELECT * FROM vulnerabilidades WHERE id = ?', (vuln_id,)
    ).fetchone()
    conn.close()
    if fila is None:
        return jsonify({'error': 'Vulnerabilidad no encontrada'}), 404
    return jsonify(dict(fila)), 200


    
@app.route('/vulnerabilidades', methods=['POST'])
@token_required
def create_vulnerabilidad():
    data = request.get_json(silent=True)
    error = validar_vulnerabilidad(data)
    if error:
        return jsonify({'error': error}), 400
    conn = get_db()
    cur = conn.execute('''
        INSERT INTO vulnerabilidades
            (titulo, cve_codigo, severidad, estado, puntaje_cvss)
            VALUES (?, ?, ?, ?, ?)
    ''', (data['titulo'].strip(), data['cve_codigo'].strip(),
           data['severidad'].strip(), data['estado'].strip(),
           data['puntaje_cvss']))
    nuevo_id = cur.lastrowid
    conn.commit()
    conn.close()
    return jsonify({'id': nuevo_id,
                    'message': 'Vulnerabilidad registrada'}), 201

@app.route('/vulnerabilidades/<int:vuln_id>', methods=['PUT'])
@token_required
def update_vulnerabilidad(vuln_id):
    data = request.get_json(silent=True)
    error = validar_vulnerabilidad(data)
    if error:
        return jsonify({'error': error}), 400
    conn = get_db()
    vuln = conn.execute(
        'SELECT id FROM vulnerabilidades WHERE id = ?', (vuln_id,)
    ).fetchone()
    if vuln is None:
        conn.close()
        return jsonify({'error': 'Vulnerabilidad no encontrada'}), 404
    conn.execute('''
        UPDATE vulnerabilidades
        SET titulo = ?, cve_codigo = ?, severidad = ?, estado = ?, puntaje_cvss = ?
        WHERE id = ?''', (data['titulo'].strip(), data['cve_codigo'].strip(),
                          data['severidad'].strip(), data['estado'].strip(),
                          data['puntaje_cvss'], vuln_id))
    conn.commit()
    conn.close()
    return jsonify({'message': 'vulnerabilidad actualizada'}), 200

@app.route('/vulnerabilidades/<int:vuln_id>', methods=['DELETE'])
@token_required
def delete_vulnerabilidad(vuln_id):
    conn = get_db()
    vuln = conn.execute(
        'SELECT id FROM vulnerabilidades WHERE id = ?', (vuln_id,)
    ).fetchone()
    if vuln is None:
        conn.close()
        return jsonify({'error': 'Vulnerabilidad no encontrada'}), 404
    conn.execute('DELETE FROM vulnerabilidades WHERE id = ?', (vuln_id,))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Vulneabilidad eliminada'}), 200

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
