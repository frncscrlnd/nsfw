import json
import os

# CONFIGURAZIONE
STIX_FILE = "../data/raw/enterprise-attack.json"  # Il file scaricato da MITRE
OUTPUT_FILE = "../data/attack_defend.json"

# I dati che mi hai fornito (M -> D3FEND)
MITIGATION_TO_D3FEND = {
  "M1015": ["D3-ANCI", "D3-DTP", "D3-UAP"],
  "M1018": ["D3-LFP", "D3-SCF", "D3-SCP"],
  "M1020": ["D3-NTA"],
  "M1021": ["D3-DNSAL", "D3-DNSDL", "D3-FA", "D3-ITF", "D3-NTA", "D3-OTF", "D3-UA"],
  "M1022": ["D3-LFP"],
  "M1024": ["D3-SCP"],
  "M1025": ["D3-BA", "D3-DLIC", "D3-PSEP", "D3-SCF"],
  "M1026": ["D3-DAM", "D3-LAM", "D3-SPP"],
  "M1027": ["D3-OTP", "D3-SPP"],
  "M1028": ["D3-PH"],
  "M1030": ["D3-BDI", "D3-ET", "D3-ISVA", "D3-ITF"],
  "M1031": ["D3-ITF", "D3-NTA", "D3-OTF"],
  "M1032": ["D3-MFA"],
  "M1033": ["D3-EAL", "D3-EDL"],
  "M1034": ["D3-IOPR"],
  "M1035": ["D3-NI"],
  "M1036": ["D3-AL", "D3-ANCI", "D3-ANET", "D3-AZET"],
  "M1037": ["D3-NI"],
  "M1038": ["D3-DLIC", "D3-EAL", "D3-EDL", "D3-PSEP"],
  "M1039": ["D3-ACH", "D3-SFA"],
  "M1040": ["D3-ANET", "D3-AZET", "D3-JFAPA", "D3-RAPA", "D3-SDA", "D3-UDTA", "D3-UGLPA", "D3-WSAA"],
  "M1041": ["D3-DENCR", "D3-ET", "D3-FE", "D3-MENCR"],
  "M1042": ["D3-ACH", "D3-EDL", "D3-SCF"],
  "M1043": ["D3-HBPI"],
  "M1044": ["D3-SCF"],
  "M1045": ["D3-DLIC", "D3-EAL", "D3-SBV"],
  "M1046": ["D3-BA", "D3-TBI"],
  "M1047": ["D3-DAM", "D3-LAM", "D3-SFA"],
  "M1048": ["D3-DA", "D3-HBPI", "D3-SCF"],
  "M1049": ["D3-FCR", "D3-FH", "D3-PA"],
  "M1050": ["D3-AH", "D3-EHPV", "D3-ITF", "D3-SSC"],
  "M1051": ["D3-SU"],
  "M1052": ["D3-SCF"],
  "M1054": ["D3-ACH", "D3-CP"],
  "M1056": ["D3-DE", "D3-DO"]
}

def build_offline_correlation():
    if not os.path.exists(STIX_FILE):
        print(f"❌ Errore: Il file {STIX_FILE} non esiste. Scaricalo prima di procedere.")
        return

    print("📖 Caricamento dataset MITRE ATT&CK...")
    with open(STIX_FILE, 'r', encoding='utf-8') as f:
        data = json.load(f)

    stix_id_to_attack_id = {}
    tech_to_mitigations = {}

    # Passo 1: Mappatura ID STIX -> ID ATT&CK (Txxxx, Mxxxx)
    for obj in data.get('objects', []):
        if 'external_references' in obj:
            for ref in obj['external_references']:
                if ref.get('source_name') in ['mitre-attack', 'mitre-mobile-attack']:
                    stix_id_to_attack_id[obj['id']] = ref['external_id']

    # Passo 2: Estrazione relazioni "mitigates"
    for obj in data.get('objects', []):
        if obj.get('type') == 'relationship' and obj.get('relationship_type') == 'mitigates':
            source_id = stix_id_to_attack_id.get(obj['source_ref']) # La Mitigazione (M)
            target_id = stix_id_to_attack_id.get(obj['target_ref']) # La Tecnica (T)

            if source_id and target_id and source_id.startswith('M') and target_id.startswith('T'):
                if target_id not in tech_to_mitigations:
                    tech_to_mitigations[target_id] = []
                tech_to_mitigations[target_id].append(source_id)

    # Passo 3: Incrocio con D3FEND
    # Struttura finale: { "T1550.003": ["D3-ANCI", "D3-DTP", ...] }
    final_map = {}
    for tech_id, mitigations in tech_to_mitigations.items():
        d3fend_techniques = set()
        for m_id in mitigations:
            if m_id in MITIGATION_TO_D3FEND:
                # Aggiungiamo tutte le tecniche D3 associate a questa mitigazione
                d3fend_techniques.update(MITIGATION_TO_D3FEND[m_id])
        
        if d3fend_techniques:
            final_map[tech_id] = sorted(list(d3fend_techniques))

    # Salvataggio
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(final_map, f, indent=4)
    
    print(f"✅ Correlazione completata! Creato '{OUTPUT_FILE}' con {len(final_map)} tecniche.")

if __name__ == "__main__":
    build_offline_correlation()
