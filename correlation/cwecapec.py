import xml.etree.ElementTree as ET
import json
import os

# Configurazione percorsi
CWE_XML_FILE = "../data/raw/cwec_v4.19.1.xml"
CAPEC_XML_FILE = "../data/raw/capec_v3.9.xml"
OUTPUT_FILE = "../data/cwe_capec.json"

# Dizionario per memorizzare la correlazione { "CWE-ID": { "CAPEC-IDs" } }
cwe_to_capec_map = {}

def add_relation(cwe_id, capec_id):
    """Associa un CAPEC ID a un CWE ID in modo univoco."""
    if not cwe_id or not capec_id:
        return
    
    # Normalizzazione ID (es: 120 -> CWE-120)
    cwe_key = f"CWE-{cwe_id}" if not str(cwe_id).startswith("CWE-") else cwe_id
    capec_val = f"CAPEC-{capec_id}" if not str(capec_id).startswith("CAPEC-") else capec_id

    if cwe_key not in cwe_to_capec_map:
        cwe_to_capec_map[cwe_key] = set()
    cwe_to_capec_map[cwe_key].add(capec_val)

def parse_cwe_xml(file_path):
    """Estrae link a CAPEC dall'XML delle CWE."""
    print(f"🔍 Analisi {file_path}...")
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        ns = {'cwe': root.tag.split('}')[0].strip('{')} if '}' in root.tag else {}
        
        # Cerca ogni Weakness
        for weakness in root.findall(".//{*}Weakness"):
            cwe_id = weakness.get('ID')
            # In CWE, i CAPEC sono sotto <Related_Attack_Patterns>
            related_patterns = weakness.find(".//{*}Related_Attack_Patterns")
            if related_patterns is not None:
                for ap in related_patterns.findall(".//{*}Related_Attack_Pattern"):
                    capec_id = ap.get('CAPEC_ID')
                    add_relation(cwe_id, capec_id)
    except Exception as e:
        print(f"❌ Errore durante l'analisi CWE: {e}")

def parse_capec_xml(file_path):
    """Estrae link a CWE dall'XML dei CAPEC."""
    print(f"🔍 Analisi {file_path}...")
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        # Cerca ogni Attack_Pattern
        for ap in root.findall(".//{*}Attack_Pattern"):
            capec_id = ap.get('ID')
            # In CAPEC, le CWE sono sotto <Related_Weaknesses>
            related_weaknesses = ap.find(".//{*}Related_Weaknesses")
            if related_weaknesses is not None:
                for cw in related_weaknesses.findall(".//{*}Related_Weakness"):
                    cwe_id = cw.get('CWE_ID')
                    add_relation(cwe_id, capec_id)
    except Exception as e:
        print(f"❌ Errore durante l'analisi CAPEC: {e}")

def main():
    if not os.path.exists(CWE_XML_FILE) or not os.path.exists(CAPEC_XML_FILE):
        print("⚠️ Assicurati che i file XML siano nella stessa cartella dello script.")
        return

    # 1. Analizza CWE (cerca riferimenti a CAPEC)
    parse_cwe_xml(CWE_XML_FILE)
    
    # 2. Analizza CAPEC (cerca riferimenti a CWE)
    parse_capec_xml(CAPEC_XML_FILE)

    # 3. Conversione set -> list per serializzazione JSON
    final_data = {k: sorted(list(v)) for k, v in sorted(cwe_to_capec_map.items())}

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(final_data, f, indent=4)

    print(f"\n🚀 Correlazione completata!")
    print(f"File generato: {OUTPUT_FILE}")
    print(f"Totale CWE correlate a CAPEC: {len(final_data)}")

if __name__ == "__main__":
    main()
