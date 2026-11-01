from flask import Flask, app, jsonify, request, render_template
from flask_cors import CORS
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
    return render_template('index.html')

@app.route('/api')
def api_info():
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

# =====================================================================
# FUNCIONALIDAD ESPECIAL: GENERADOR DE PLAYBOOKS DE MITIGACION EN CLOUD
# La API NO ejecuta nada: solo devuelve texto de ejemplo (modo simulacion).
# Los identificadores (sg-..., i-...) son ficticios.
# =====================================================================

def generar_comandos_mitigacion(severidad, cve_codigo):
    """
    Motor de reglas: devuelve contramedidas tecnicas simuladas para
    infraestructura cloud segun la severidad y el codigo CVE.
    """
    severidad_limpia = severidad.strip().lower()

    playbooks = {
        'baja': {
            'accion_inmediata': 'Monitoreo preventivo y auditoria de parches periodica.',
            'comando_consola': '# Listar actualizaciones de seguridad disponibles en el servidor\n'
                               'sudo apt-get update && sudo apt-get --just-print upgrade | grep -i security',
            'politica_cloud': '# AWS CLI: Habilitar el escaneo automatico de imagenes al subir contenedores (ECR)\n'
                              'aws ecr put-image-scanning-configuration --repository-name app-repo '
                              '--image-scanning-configuration scanOnPush=true'
        },
        'media': {
            'accion_inmediata': 'Restriccion perimetral intermedia y actualizacion programada (max 30 dias).',
            'comando_consola': '# Limitar el trafico hacia el puerto del servicio (ej. 8080): aceptar hasta 25/min y descartar el resto\n'
                               'sudo iptables -A INPUT -p tcp --dport 8080 -m limit --limit 25/minute -j ACCEPT\n'
                               'sudo iptables -A INPUT -p tcp --dport 8080 -j DROP',
            'politica_cloud': '# AWS WAF: Bloquear peticiones sospechosas que contengan patrones del CVE\n'
                              f'# Regla creada preventivamente para mitigar inspecciones sobre {cve_codigo}'
        },
        'alta': {
            'accion_inmediata': 'Aplicar parches urgentes en la presente ventana de mantenimiento. Limitar accesos.',
            'comando_consola': '# Actualizar solo el paquete afectado y sus dependencias criticas\n'
                               'sudo apt-get install --only-upgrade -y openssl libssl-dev',
            'politica_cloud': '# AWS CLI: Restringir el acceso al recurso vulnerable solo a la red de la VPN corporativa\n'
                              'aws ec2 revoke-security-group-ingress --group-id sg-0123456789abcdef0 --protocol tcp --port 443 --cidr 0.0.0.0/0\n'
                              'aws ec2 authorize-security-group-ingress --group-id sg-0123456789abcdef0 --protocol tcp --port 443 --cidr 192.168.1.0/24'
        },
        'critica': {
            'accion_inmediata': 'AISLAMIENTO TOTAL E INMEDIATO DEL RECURSO. Mitigacion de emergencia activa.',
            'comando_consola': '# Detener de inmediato el servicio afectado para frenar la explotacion\n'
                               'sudo systemctl stop vulnerable-service && sudo systemctl disable vulnerable-service',
            'politica_cloud': '# AWS CLI: Aislar la instancia EC2 vulnerable asociandole un Security Group de cuarentena\n'
                              'aws ec2 modify-instance-attribute --instance-id i-0123456789abcdef0 --groups sg-quarantine-isolated-id\n'
                              f'# NOTA DE EMERGENCIA: Alertas enviadas a CloudWatch por posible explotacion de {cve_codigo}.'
        }
    }

    return playbooks.get(severidad_limpia, {
        'accion_inmediata': 'Analizar manualmente por el equipo de SecOps.',
        'comando_consola': '# No se disponen de scripts automatizados para esta severidad.',
        'politica_cloud': '# Configurar alertas manuales en la consola de administracion Cloud.'
    })

@app.route('/vulnerabilidades/<int:vuln_id>/playbook', methods=['GET'])
@token_required
def get_playbook_mitigacion(vuln_id):
    conn = get_db()
    fila = conn.execute(
        'SELECT titulo, cve_codigo, severidad, estado FROM vulnerabilidades WHERE id = ?',
        (vuln_id,)
    ).fetchone()
    conn.close()

    if fila is None:
        return jsonify({'error': 'Vulnerabilidad no encontrada'}), 404

    datos = dict(fila)
    metadata = {
        'vulnerabilidad_id': vuln_id,
        'titulo_analizado': datos['titulo'],
        'identificador': datos['cve_codigo'],
        'severidad_declarada': datos['severidad'],
        'estado_actual': datos['estado'],
        'fecha_generacion': datetime.datetime.now(datetime.timezone.utc).isoformat()
    }

    # Si ya fue cerrada o mitigada no hay accion pendiente
    if datos['estado'] in ('cerrada', 'mitigada'):
        return jsonify({
            'metadata': metadata,
            'plan_mitigacion': None,
            'estado_playbook': 'Sin accion pendiente: la vulnerabilidad esta ' + datos['estado']
        }), 200

    comandos = generar_comandos_mitigacion(datos['severidad'], datos['cve_codigo'])
    return jsonify({
        'metadata': metadata,
        'plan_mitigacion': {
            'estrategia_cloud': comandos['accion_inmediata'],
            'script_consola_sistema': comandos['comando_consola'],
            'infraestructura_como_codigo_aws': comandos['politica_cloud']
        },
        'estado_playbook': 'Listo para despliegue / Modo Simulacion'
    }), 200

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
