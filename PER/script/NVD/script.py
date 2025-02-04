import os
import json
import re
import multiprocessing
from concurrent.futures import ProcessPoolExecutor

# Dossier contenant les fichiers JSON CVE de NVD
CVE_ROOT = "./"

# Fonction pour générer un ID numérique à partir du CVE_ID
def generate_cve_numeric_id(cve_id):
    return int("".join(re.findall(r"\d+", cve_id)))  # Garde uniquement les chiffres

# Fonction pour extraire les informations d'un fichier JSON
def process_json_file(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as json_file:
            data = json.load(json_file)

            cve_data = []
            for item in data.get("CVE_Items", []):
                cve_id = item["cve"]["CVE_data_meta"]["ID"]
                cve_numeric_id = generate_cve_numeric_id(cve_id)

                # Récupération de la description en anglais
                descriptions = item["cve"].get("description", {}).get("description_data", [])
                description_text = next(
                    (desc.get("value", "No description available") for desc in descriptions if desc.get("lang") == "en"),
                    "No description available"
                )

                # Récupération du score CVSS (priorité à v3, sinon v2)
                impact = item.get("impact", {})
                base_score = None
                if "baseMetricV3" in impact:
                    base_score = impact["baseMetricV3"]["cvssV3"]["baseScore"]
                elif "baseMetricV2" in impact:
                    base_score = impact["baseMetricV2"]["cvssV2"]["baseScore"]

                cve_data.append({
                    "id": cve_numeric_id,
                    "CVE_ID": cve_id,
                    "Description": description_text,
                    "Base_Score": base_score
                })

            return cve_data

    except Exception as e:
        print(f"❌ Erreur avec le fichier {file_path}: {e}")
        return []

# Fonction pour traiter tous les fichiers d'un dossier
def process_all_files():
    # Liste des fichiers JSON dans le dossier
    file_paths = [os.path.join(CVE_ROOT, file) for file in os.listdir(CVE_ROOT) if file.endswith(".json")]

    # Traitement en parallèle des fichiers
    with ProcessPoolExecutor(max_workers=multiprocessing.cpu_count()) as executor:
        for file_path, result in zip(file_paths, executor.map(process_json_file, file_paths)):
            output_filename = f"cve_extracted_{os.path.basename(file_path).replace('.json', '')}.json"

            # Sauvegarde des résultats individuels
            with open(output_filename, "w", encoding="utf-8") as json_out:
                json.dump(result, json_out, indent=4)

            print(f"✅ Extraction terminée pour {file_path}! Résultats enregistrés dans {output_filename}.")

# Exécuter l'extraction sur tous les fichiers
if __name__ == "__main__":
    process_all_files()
    print("🚀 Extraction complète pour tous les fichiers!")
