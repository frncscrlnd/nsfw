import json
import os

# Configurazione percorsi
CVE_BASE_DIR = "../data/raw/cves"  # Cartella principale con gli anni
OUTPUT_FILE = "../data/cve_cpe.json"

# Dizionario globale { "CVE-ID": { "cpe:2.3:...", ... } }
cve_to_cpe_map = {}

def add_relation(cve_id, cpe_id):
    """Aggiunge una relazione univoca tra CVE e CPE."""
    if not cve_id or not cpe_id:
        return
    cve_id = cve_id.strip()
    cpe_id = cpe_id.strip()
    if cve_id not in cve_to_cpe_map:
        cve_to_cpe_map[cve_id] = set()
    cve_to_cpe_map[cve_id].add(cpe_id)

def parse_cve_json(file_path):
    """Estrae CPE da un singolo file JSON CVE 5.0."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        cve_id = data.get("cveMetadata", {}).get("cveId")
        if not cve_id:
            return

        # Le CPE sono in containers -> cna -> affected
        affected_list = data.get("containers", {}).get("cna", {}).get("affected", [])

        for affected in affected_list:
            # Metodo 1: campo "cpes" esplicito
            for cpe in affected.get("cpes", []):
                add_relation(cve_id, cpe)

            # Metodo 2: CPE dentro versions
            for version in affected.get("versions", []):
                for cpe in version.get("cpes", []):
                    add_relation(cve_id, cpe)

        # Cerca anche in containers -> adp (dati arricchiti da terze parti)
        for adp in data.get("containers", {}).get("adp", []):
            for affected in adp.get("affected", []):
                for cpe in affected.get("cpes", []):
                    add_relation(cve_id, cpe)
                for version in affected.get("versions", []):
                    for cpe in version.get("cpes", []):
                        add_relation(cve_id, cpe)

    except Exception:
        pass  # Ignora file corrotti o non conformi

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
                    print(f"  Processati {count} file...")
    print(f"✅ Scansione completata. {count} file CVE processati.")

def main():
    process_all_cves(CVE_BASE_DIR)

    # Salva il file finale con liste ordinate
    final_output = {k: sorted(list(v)) for k, v in cve_to_cpe_map.items()}

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(final_output, f, indent=4)

    total_cpes = sum(len(v) for v in final_output.values())
    print(f"\n🚀 FINE! Creato '{OUTPUT_FILE}'")
    print(f"   CVE con almeno una CPE: {len(final_output)}")
    print(f"   Relazioni CVE-CPE totali: {total_cpes}")

if __name__ == "__main__":
    main()
