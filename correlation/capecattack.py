import json
import xml.etree.ElementTree as ET
import os

# Configurazione
CAPEC_XML_FILE = "../data/raw/capec_v3.9.xml"  # Assicurati che il nome sia corretto
OUTPUT_FILE = "../data/capec_attack.json"

def parse_capec_xml(file_path):
    """Analizza l'XML CAPEC per estrarre mappature ATT&CK."""
    if not os.path.exists(file_path):
        print(f"⚠️ File CAPEC {file_path} non trovato!")
        return {}

    capec_to_attack = {}
    
    print(f"🔍 Analisi file CAPEC: {file_path}")
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        # Gestione namespace (CAPEC usa solitamente xmlns="http://capec.mitre.org/capec-3")
        ns = {'ca': root.tag.split('}')[0].strip('{')} if '}' in root.tag else {}
        prefix = "ca:" if ns else ""

        # Cerchiamo tutti i nodi Attack_Pattern
        for pattern in root.findall(f".//{prefix}Attack_Pattern", ns):
            capec_id = f"CAPEC-{pattern.get('ID')}"
            
            # Troviamo i Taxonomy_Mapping dove Taxonomy_Name è "ATTACK"
            mappings = pattern.findall(f".//{prefix}Taxonomy_Mapping[@Taxonomy_Name='ATTACK']", ns)
            
            attack_ids = []
            for mapping in mappings:
                entry_id = mapping.find(f"{prefix}Entry_ID", ns)
                if entry_id is not None and entry_id.text:
                    # Formattiamo l'ID ATT&CK (es. T1550.003)
                    attack_ids.append(f"T{entry_id.text.strip()}")

            if attack_ids:
                capec_to_attack[capec_id] = sorted(list(set(attack_ids)))

        return capec_to_attack

    except Exception as e:
        print(f"❌ Errore durante il parsing XML: {e}")
        return {}

def main():
    # 1. Estrazione dati
    data = parse_capec_xml(CAPEC_XML_FILE)
    
    # 2. Salvataggio
    if data:
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4)
        print(f"✅ Successo! Creato '{OUTPUT_FILE}' con {len(data)} pattern correlati.")
    else:
        print("❌ Nessuna correlazione trovata.")

if __name__ == "__main__":
    main()
