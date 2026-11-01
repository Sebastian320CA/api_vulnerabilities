import pytest
import api_vulnerabilidades as api


@pytest.fixture
def client(tmp_path, monkeypatch):
    """Cliente de pruebas con una base de datos temporal (no toca la real)."""
    monkeypatch.setattr(api, 'DB_NAME', str(tmp_path / 'test.db'))
    api.init_db()
    api.app.config['TESTING'] = True
    return api.app.test_client()


@pytest.fixture
def auth(client):
    r = client.post('/login', json={'username': 'admin', 'clave': 'demo123'})
    return {'Authorization': 'Bearer ' + r.get_json()['token']}


def vuln(**cambios):
    datos = {'titulo': 'SQL Injection en login', 'cve_codigo': 'CVE-2024-12345',
             'severidad': 'alta', 'estado': 'abierta', 'puntaje_cvss': 8.1}
    datos.update(cambios)
    return datos


def crear(client, auth, **cambios):
    r = client.post('/vulnerabilidades', json=vuln(**cambios), headers=auth)
    assert r.status_code == 201
    return r.get_json()['id']


# ---------------- Raiz ----------------
def test_root(client):
    r = client.get('/api')
    assert r.status_code == 200
    assert r.get_json()['recurso'] == '/vulnerabilidades'


# ---------------- Login / JWT ----------------
def test_login_ok(client):
    r = client.post('/login', json={'username': 'admin', 'clave': 'demo123'})
    assert r.status_code == 200
    assert 'token' in r.get_json()


def test_login_credenciales_invalidas(client):
    r = client.post('/login', json={'username': 'admin', 'clave': 'mala'})
    assert r.status_code == 401


def test_login_faltan_campos(client):
    assert client.post('/login', json={'username': 'admin'}).status_code == 400


def test_login_sin_json(client):
    assert client.post('/login', data='hola').status_code == 400


def test_sin_token_401(client):
    assert client.post('/vulnerabilidades', json=vuln()).status_code == 401


def test_token_invalido_401(client):
    r = client.post('/vulnerabilidades', json=vuln(),
                    headers={'Authorization': 'Bearer abc.def.ghi'})
    assert r.status_code == 401


def test_token_expirado_401(client):
    import jwt, datetime
    token = jwt.encode(
        {'user': 'admin',
         'exp': datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=5)},
        api.app.config['SECRET_KEY'], algorithm='HS256')
    r = client.post('/vulnerabilidades', json=vuln(),
                    headers={'Authorization': 'Bearer ' + token})
    assert r.status_code == 401
    assert r.get_json()['error'] == 'Token expirado'


# ---------------- Crear ----------------
def test_crear_ok(client, auth):
    r = client.post('/vulnerabilidades', json=vuln(), headers=auth)
    assert r.status_code == 201
    assert r.get_json()['id'] == 1


@pytest.mark.parametrize('cambio', [
    {'titulo': ''},
    {'cve_codigo': 'CVE-24-1'},
    {'severidad': 'extrema'},
    {'estado': 'perdida'},
    {'puntaje_cvss': 11},
    {'puntaje_cvss': -1},
    {'puntaje_cvss': 'alto'},
])
def test_crear_datos_invalidos_400(client, auth, cambio):
    r = client.post('/vulnerabilidades', json=vuln(**cambio), headers=auth)
    assert r.status_code == 400
    assert 'error' in r.get_json()


def test_crear_campo_faltante_400(client, auth):
    datos = vuln()
    del datos['puntaje_cvss']
    assert client.post('/vulnerabilidades', json=datos, headers=auth).status_code == 400


# ---------------- Listar / consultar ----------------
def test_listar_vacio(client):
    r = client.get('/vulnerabilidades')
    assert r.status_code == 200
    assert r.get_json() == []


def test_listar_y_persistencia(client, auth):
    crear(client, auth)
    crear(client, auth, cve_codigo='CVE-2023-0001')
    r = client.get('/vulnerabilidades')
    assert len(r.get_json()) == 2


def test_consultar_por_id(client, auth):
    vid = crear(client, auth)
    r = client.get(f'/vulnerabilidades/{vid}')
    assert r.status_code == 200
    assert r.get_json()['cve_codigo'] == 'CVE-2024-12345'


def test_consultar_no_existe_404(client):
    assert client.get('/vulnerabilidades/999').status_code == 404


# ---------------- Actualizar ----------------
def test_actualizar_ok(client, auth):
    vid = crear(client, auth)
    r = client.put(f'/vulnerabilidades/{vid}',
                   json=vuln(estado='mitigada'), headers=auth)
    assert r.status_code == 200
    assert client.get(f'/vulnerabilidades/{vid}').get_json()['estado'] == 'mitigada'


def test_actualizar_no_existe_404(client, auth):
    assert client.put('/vulnerabilidades/999', json=vuln(), headers=auth).status_code == 404


def test_actualizar_invalido_400(client, auth):
    vid = crear(client, auth)
    r = client.put(f'/vulnerabilidades/{vid}', json=vuln(severidad='x'), headers=auth)
    assert r.status_code == 400


def test_actualizar_sin_token_401(client, auth):
    vid = crear(client, auth)
    assert client.put(f'/vulnerabilidades/{vid}', json=vuln()).status_code == 401


# ---------------- Eliminar ----------------
def test_eliminar_ok(client, auth):
    vid = crear(client, auth)
    assert client.delete(f'/vulnerabilidades/{vid}', headers=auth).status_code == 200
    assert client.get(f'/vulnerabilidades/{vid}').status_code == 404


def test_eliminar_no_existe_404(client, auth):
    assert client.delete('/vulnerabilidades/999', headers=auth).status_code == 404


def test_eliminar_sin_token_401(client, auth):
    vid = crear(client, auth)
    assert client.delete(f'/vulnerabilidades/{vid}').status_code == 401


# ---------------- Funcionalidad especial: playbook ----------------
def test_playbook_critica(client, auth):
    vid = crear(client, auth, severidad='critica', cve_codigo='CVE-2021-44228')
    r = client.get(f'/vulnerabilidades/{vid}/playbook', headers=auth)
    assert r.status_code == 200
    d = r.get_json()
    assert d['metadata']['identificador'] == 'CVE-2021-44228'
    assert d['plan_mitigacion']['estrategia_cloud'].startswith('AISLAMIENTO TOTAL')
    assert 'CVE-2021-44228' in d['plan_mitigacion']['infraestructura_como_codigo_aws']
    assert 'Simulacion' in d['estado_playbook']


@pytest.mark.parametrize('sev, texto', [
    ('baja', 'Monitoreo preventivo'),
    ('media', 'Restriccion perimetral'),
    ('alta', 'parches urgentes'),
    ('critica', 'AISLAMIENTO TOTAL'),
])
def test_playbook_por_severidad(client, auth, sev, texto):
    vid = crear(client, auth, severidad=sev)
    d = client.get(f'/vulnerabilidades/{vid}/playbook', headers=auth).get_json()
    assert texto in d['plan_mitigacion']['estrategia_cloud']


def test_playbook_media_descarta_trafico(client, auth):
    vid = crear(client, auth, severidad='media')
    d = client.get(f'/vulnerabilidades/{vid}/playbook', headers=auth).get_json()
    assert '-j DROP' in d['plan_mitigacion']['script_consola_sistema']


@pytest.mark.parametrize('estado', ['cerrada', 'mitigada'])
def test_playbook_sin_accion_si_resuelta(client, auth, estado):
    vid = crear(client, auth, estado=estado)
    d = client.get(f'/vulnerabilidades/{vid}/playbook', headers=auth).get_json()
    assert d['plan_mitigacion'] is None
    assert 'Sin accion pendiente' in d['estado_playbook']


def test_playbook_no_existe_404(client, auth):
    assert client.get('/vulnerabilidades/999/playbook', headers=auth).status_code == 404


def test_playbook_sin_token_401(client, auth):
    vid = crear(client, auth)
    assert client.get(f'/vulnerabilidades/{vid}/playbook').status_code == 401


def test_generar_comandos_severidad_desconocida():
    r = api.generar_comandos_mitigacion('rara', 'CVE-2024-0001')
    assert 'manualmente' in r['accion_inmediata']
