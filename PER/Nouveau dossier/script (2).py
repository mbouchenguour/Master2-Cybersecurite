import json
import os
import re

# Définir le dossier contenant les fichiers JSON
json_folder = "./NVD_CVE"
output_folder = os.path.join(json_folder, "final")

# Vérifier si le dossier existe
if not os.path.exists(json_folder):
    print(f"Le dossier {json_folder} n'existe pas.")
    exit()

# Créer le dossier de sortie s'il n'existe pas
if not os.path.exists(output_folder):
    os.makedirs(output_folder)

# Liste des fichiers JSON dans le dossier
json_files = [f for f in os.listdir(json_folder) if f.endswith(".json")]

# Vérifier qu'il y a des fichiers JSON
if not json_files:
    print("Aucun fichier JSON trouvé dans le dossier.")
    exit()

# Fonction récursive pour trouver le `baseScore`
def find_base_score(impact_data):
    """Recherche récursive du `baseScore` dans toutes les versions de CVSS."""
    if not isinstance(impact_data, dict):
        return None

    for key, value in impact_data.items():
        if isinstance(value, dict):
            if "cvssV3" in value and "baseScore" in value["cvssV3"]:
                return value["cvssV3"]["baseScore"]
            elif "cvssV2" in value and "baseScore" in value["cvssV2"]:
                return value["cvssV2"]["baseScore"]
            else:
                result = find_base_score(value)
                if result != None:
                    return result
    return None

# Parcourir tous les fichiers JSON et extraire les données
for json_file in json_files:
    file_path = os.path.join(json_folder, json_file)
    print(f"📂 Traitement de {json_file}...")

    # Réinitialiser la liste pour stocker uniquement les CVE de l'année actuelle
    cve_list = []

    # Charger le fichier JSON
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Extraire l'année à partir du nom du fichier
    year_match = re.search(r"(\d{4})", json_file)
    year = year_match.group(1) if year_match else "unknown"

    # Extraire les CVE
    for item in data.get("CVE_Items", []):
        cve_id = item["cve"]["CVE_data_meta"]["ID"]
        cve_number = int(cve_id.replace("CVE-", "").replace("-", ""))  # Concaténation des chiffres
        description = item["cve"]["description"]["description_data"][0]["value"] if item["cve"]["description"]["description_data"] else None
        base_score = find_base_score(item.get("impact", {}))

        # Ajouter la CVE à la liste
        cve_list.append({
            "id": cve_number,
            "CVE_ID": cve_id,
            "Description": description,
            "Base_Score": base_score
        })

    # Définir le fichier de sortie JSON
    json_output = os.path.join(output_folder, f"cve_extracted_nvdcve-1.1-{year}.json")

    # Enregistrer les données extraites en JSON
    with open(json_output, "w", encoding="utf-8") as outfile:
        json.dump(cve_list, outfile, indent=4, ensure_ascii=False)

    print(f"✅ Fichier JSON enregistré : {json_output} ({len(cve_list)} CVEs)")

print("\n🎯 Extraction terminée ! Tous les fichiers sont stockés dans:", output_folder)
