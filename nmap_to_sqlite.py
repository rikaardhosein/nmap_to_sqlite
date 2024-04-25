import sqlite3
import xml.etree.ElementTree as ET
import sys

conn = sqlite3.connect('nmap_scan.db')
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS Scans (
    scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
    start_time TEXT,
    end_time TEXT,
    nmap_version TEXT
)
''')

cursor.execute('''
CREATE TABLE IF NOT EXISTS Hosts (
    host_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER,
    ip_address TEXT,
    hostname TEXT,
    os TEXT,
    FOREIGN KEY(scan_id) REFERENCES Scans(scan_id)
)
''')

cursor.execute('''
CREATE TABLE IF NOT EXISTS Ports (
    port_id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER,
    port_number INTEGER,
    protocol TEXT,
    state TEXT,
    service_name TEXT,
    FOREIGN KEY(host_id) REFERENCES Hosts(host_id)
)
''')

def ingest_xml(xml_file):
    tree = ET.parse(xml_file)
    root = nmaprun = tree.getroot()

    start_time = nmaprun.get('start')
    end_time = nmaprun.get('end')
    nmap_version = nmaprun.get('version')

    cursor.execute('''
    INSERT INTO Scans (start_time, end_time, nmap_version)
    VALUES (?, ?, ?)
    ''', (start_time, end_time, nmap_version))
    scan_id = cursor.lastrowid

    hosts = root.findall('.//host')
    for host in hosts:
        ip_address = host.find('.//address[@addrtype="ipv4"]').get('addr')
        hostname_elem = host.find('.//hostname')
        hostname = hostname_elem.get('name') if hostname_elem is not None else None
        os_elem = host.find('.//osmatch')
        os = os_elem.get('name') if os_elem is not None else None

        cursor.execute('''
        INSERT INTO Hosts (scan_id, ip_address, hostname, os)
        VALUES (?, ?, ?, ?)
        ''', (scan_id, ip_address, hostname, os))
        host_id = cursor.lastrowid

        ports = host.findall('.//port')
        for port in ports:
            port_number = int(port.get('portid'))
            protocol = port.get('protocol')
            state = port.find('.//state').get('state')
            service_name = port.find('.//service').get('name')

            cursor.execute('''
            INSERT INTO Ports (host_id, port_number, protocol, state, service_name)
            VALUES (?, ?, ?, ?, ?)
            ''', (host_id, port_number, protocol, state, service_name))

    conn.commit()

ingest_xml(sys.argv[1])

conn.close()

