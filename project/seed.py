"""Carga datos de ejemplo en vulnerabilidades.db (solo si esta vacia).
Uso: python seed.py
"""
import api_vulnerabilidades as api

EJEMPLOS = [
    ('Log4Shell: ejecucion remota en Log4j', 'CVE-2021-44228', 'critica', 'abierta', 10.0),
    ('Heartbleed: fuga de memoria en OpenSSL', 'CVE-2014-0160', 'alta', 'mitigada', 7.5),
    ('Shellshock en Bash', 'CVE-2014-6271', 'critica', 'cerrada', 9.8),
    ('Inyeccion SQL en formulario de login', 'CVE-2023-12345', 'alta', 'en_revision', 8.1),
    ('Cabecera HTTP expone version del servidor', 'CVE-2022-0001', 'baja', 'abierta', 3.1),
    ('XSS reflejado en buscador', 'CVE-2023-0456', 'media', 'abierta', 6.1),
]

if __name__ == '__main__':
    api.init_db()
    conn = api.get_db()
    if conn.execute('SELECT COUNT(*) FROM vulnerabilidades').fetchone()[0] == 0:
        conn.executemany(
            'INSERT INTO vulnerabilidades (titulo, cve_codigo, severidad, estado, puntaje_cvss) '
            'VALUES (?, ?, ?, ?, ?)', EJEMPLOS)
        conn.commit()
        print(f'{len(EJEMPLOS)} registros cargados.')
    else:
        print('La base ya tiene datos; no se cargo nada.')
    conn.close()
