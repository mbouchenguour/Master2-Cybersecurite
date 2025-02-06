import os
import json

# 📂 Dossiers contenant les fichiers JSON MITRE et NVD
MITRE_DIR = "./MITRE"
NVD_DIR = "./NVD/NVD_CVE/final"
OUTPUT_DIR = "./FUSION"

# 📌 Charger un fichier JSON et gérer les erreurs
def load_json(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            data = json.load(file)
            if isinstance(data, list):
                return data  # ✅ Retourne directement la liste de CVE
            else:
                print(f"⚠️ Mauvaise structure JSON détectée dans {file_path}, ignoré.")
                return []
    except Exception as e:
        print(f"❌ Erreur de lecture {file_path}: {e}")
        return []

# 📌 Extraire les données depuis MITRE
def extract_mitre_data(mitre_json):
    extracted_data = {}

    for cve in mitre_json:
        cve_id = cve.get("CVE_ID")
        if not cve_id:
            continue

        extracted_data[cve_id] = {
            "id": cve["id"],
            "CVE_ID": cve_id,
            "Description": cve.get("Description"),  # Prend la valeur brute, None si absent
            "Base_Score": cve.get("Base_Score")  # Prend la valeur brute, None si absent

        }
    
    return extracted_data

# 📌 Extraire les données depuis NVD
def extract_nvd_data(nvd_json):
    extracted_data = {}

    for cve in nvd_json:
        cve_id = cve.get("CVE_ID")
        if not cve_id:
            continue

        extracted_data[cve_id] = {
            "id": cve["id"],
            "CVE_ID": cve_id,
            "Description": cve.get("Description"),  # Prend la valeur brute, None si absent
            "Base_Score": cve.get("Base_Score")  # Prend la valeur brute, None si absent
        }
    
    return extracted_data

# 📌 Fusionner les données MITRE & NVD avec gestion des scores
def merge_cve_data(mitre_data, nvd_data):
    merged_data = {}

    # 🔹 Ajouter les données de NVD en premier
    for cve_id, nvd_entry in nvd_data.items():
        merged_data[cve_id] = nvd_entry

    # 🔹 Compléter avec MITRE
    # 🔹 Compléter avec MITRE
    for cve_id, mitre_entry in mitre_data.items():
        if cve_id in merged_data:
            # 🔹 Compléter la description si elle est absente (uniquement si MITRE en a une)
            if merged_data[cve_id]["Description"] is None and mitre_entry["Description"] is not None:
                merged_data[cve_id]["Description"] = mitre_entry["Description"]

            # 🔹 Prendre le score qui est disponible si l'autre est absent ou invalide
            if merged_data[cve_id]["Base_Score"] is None and mitre_entry["Base_Score"] is not None:
                merged_data[cve_id]["Base_Score"] = mitre_entry["Base_Score"]
            elif merged_data[cve_id]["Base_Score"] not in [None, "null"] and mitre_entry["Base_Score"] not in [None, "null"]:
                try:
                    merged_data[cve_id]["Base_Score"] = max(
                        float(merged_data[cve_id]["Base_Score"]),
                        float(mitre_entry["Base_Score"])
                    )
                except ValueError:
                    print(f"⚠️ Erreur de conversion Base_Score pour {cve_id} → {merged_data[cve_id]['Base_Score']} / {mitre_entry['Base_Score']}")
                    merged_data[cve_id]["Base_Score"] = None  # Assure une valeur correcte

        else:
            # 🔹 Ajouter la CVE de MITRE si absente dans NVD
            merged_data[cve_id] = mitre_entry

    
    return merged_data

# 📌 Fusionner tous les fichiers MITRE & NVD
def process_all_files():
    os.makedirs(OUTPUT_DIR, exist_ok=True)  # 📂 Créer le dossier de sortie s'il n'existe pas

    for mitre_file in os.listdir(MITRE_DIR):
        if not mitre_file.endswith(".json"):
            continue  # 🔄 Ignorer les fichiers non JSON

        # 📌 Construire le chemin des fichiers
        mitre_path = os.path.join(MITRE_DIR, mitre_file)
        nvd_path = os.path.join(NVD_DIR, mitre_file.replace("cve_descriptions_", "cve_extracted_nvdcve-1.1-"))

        # 📌 Charger les fichiers JSON
        mitre_data = extract_mitre_data(load_json(mitre_path))
        nvd_data = extract_nvd_data(load_json(nvd_path)) if os.path.exists(nvd_path) else {}

        # 📌 Fusionner les données
        merged_cve_data = merge_cve_data(mitre_data, nvd_data)

        # 📌 Sauvegarde des résultats
        output_file = os.path.join(OUTPUT_DIR, mitre_file.replace("cve_descriptions_", "merged_cve_"))
        with open(output_file, "w", encoding="utf-8") as json_out:
            json.dump(list(merged_cve_data.values()), json_out, indent=4)

        print(f"✅ Fusion terminée pour {mitre_file} → {output_file}")

# 📌 Exécuter le script
if __name__ == "__main__":
    process_all_files()
