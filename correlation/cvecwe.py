import json
import xml.etree.ElementTree as ET
import os

# Configurazione percorsi
CVE_BASE_DIR = "../data/raw/cves"  # La tua cartella principale con gli anni
CWE_XML_FILE = "../data/raw/cwec_v4.19.1.xml"
OUTPUT_FILE = "../data/cve_cwe.json"

# Dizionario globale per le relazioni { "CVE-ID": { "CWE-ID", ... } }
cve_to_cwe_map = {}

def add_relation(cve_id, cwe_id):
    """Aggiunge una relazione univoca tra CVE e CWE."""
    if not cve_id or not cwe_id:
        return
    cve_id = cve_id.strip()
    cwe_id = cwe_id.strip()
    if cve_id not in cve_to_cwe_map:
        cve_to_cwe_map[cve_id] = set()
    cve_to_cwe_map[cve_id].add(cwe_id)

def process_all_cves(base_dir):
    """Scansiona ricorsivamente la struttura Anno/Migliaia per i file JSON."""
    print(f"🔍 Avvio scansione cartella CVE: {base_dir}")
    count = 0
    for root, dirs, files in os.walk(base_dir):
        for file in files:
            if file.endswith(".json") and file.startswith("CVE-"):
                file_path = os.path.join(root, file)
                parse_cve_json(file_path)
                count += 1
                if count % 5000 == 0:
                    print(f"Processed {count} file...")
    print(f"✅ Scansione completata. {count} file CVE processati.")

def parse_cve_json(file_path):
    """Estrae CWE da un singolo file JSON CVE 5.0."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        cve_id = data.get("cveMetadata", {}).get("cveId")
        # In JSON 5.0 le CWE sono in containers -> cna -> problemTypes
        problem_types = data.get("containers", {}).get("cna", {}).get("problemTypes", [])
        
        for pt in problem_types:
            for desc in pt.get("descriptions", []):
                # Cerchiamo ID che iniziano con CWE-
                cwe_id = desc.get("cweId")
                if cwe_id:
                    add_relation(cve_id, cwe_id)
    except Exception:
        pass # Ignora file corrotti o non conformi

def parse_cwe_xml(file_path):
    """Analizza l'XML CWE per Observed Examples e Gerarchie."""
    if not os.path.exists(file_path):
        print(f"⚠️ File CWE {file_path} non trovato!")
        return

    print(f"🔍 Analisi file CWE: {file_path}")
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        ns = {'cwe': root.tag.split('}')[0].strip('{')} if '}' in root.tag else {}
        find_p = ".//cwe:" if ns else ".//"

        for weakness in root.findall(f"{find_p}Weakness", ns):
            current_cwe = f"CWE-{weakness.get('ID')}"
            
            # Related Weaknesses (Genitori/Figli)
            related_ids = [f"CWE-{r.get('CWE_ID')}" for r in weakness.findall(f"{find_p}Related_Weakness", ns)]
                
            # Observed Examples (Relazione inversa: CWE -> CVE)
            for obs in weakness.findall(f"{find_p}Observed_Example", ns):
                ref_elem = obs.find(f"{find_p}Reference", ns)
                if ref_elem is not None and ref_elem.text:
                    cve_ref = ref_elem.text.strip()
                    add_relation(cve_ref, current_cwe)
                    # Applica ereditarietà: la CVE appartiene anche alle correlate
                    for r_cwe in related_ids:
                        add_relation(cve_ref, r_cwe)
    except Exception as e:
        print(f"❌ Errore XML: {e}")

def main():
    # 1. Processa tutti i file JSON nelle sottocartelle
    process_all_cves(CVE_BASE_DIR)
    
    # 2. Arricchisci con i dati dall'XML CWE
    parse_cwe_xml(CWE_XML_FILE)
    
    # 3. Salva il file finale pulito
    final_output = {k: sorted(list(v)) for k, v in cve_to_cwe_map.items()}
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(final_output, f, indent=4)
    
    print(f"\n🚀 FINE! Creato '{OUTPUT_FILE}' con {len(final_output)} relazioni CVE-CWE univoche.")

if __name__ == "__main__":
    main()
