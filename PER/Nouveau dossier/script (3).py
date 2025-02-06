import os
import json
import re
import multiprocessing
from concurrent.futures import ProcessPoolExecutor

# Dossier racine contenant les CVE
CVE_ROOT = "./MITRE/cves"

# Années à traiter (de 1999 à 2025)
YEARS_TO_PROCESS = [str(year) for year in range(1999, 2026)]

# Fonction pour générer un ID en concaténant tous les chiffres du CVE_ID
def generate_cve_numeric_id(cve_id):
    return int("".join(re.findall(r"\d+", cve_id)))  # Récupère uniquement les chiffres et les assemble

def find_base_score(data):
    """Recherche récursive de baseScore dans un dictionnaire JSON."""
    if isinstance(data, dict):
        for key, value in data.items():
            if key == "baseScore":
                return value  # Retourne immédiatement le premier baseScore trouvé
            found_score = find_base_score(value)  # Recherche dans les sous-éléments
            if found_score is not None:
                return found_score
    elif isinstance(data, list):
        for item in data:
            found_score = find_base_score(item)
            if found_score is not None:
                return found_score
    return None  # Retourne None si aucun baseScore n'est trouvé

# Fonction pour traiter un fichier JSON et extraire les données
def process_json_file(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as json_file:
            data = json.load(json_file)
            cve_id = data["cveMetadata"]["cveId"]

            # Générer l'ID numérique
            cve_numeric_id = generate_cve_numeric_id(cve_id)

            # Extraire la description en anglais (commençant par "en")
            descriptions = data.get("containers", {}).get("cna", {}).get("descriptions", [])
            description_text = next(
                (desc.get("value", None) for desc in descriptions if desc.get("lang", "").startswith("en")),
                None
            )
            
            # Si aucune description n'est trouvée, vérifier `rejectedReasons`
            if not description_text:
                rejected_reasons = data.get("containers", {}).get("cna", {}).get("rejectedReasons", [])
                description_text = "Reject" if rejected_reasons else None


            # Extraire le score CVSS peu importe son emplacement
            cvss_score = find_base_score(data)


            return {
                "id": cve_numeric_id,
                "CVE_ID": cve_id,
                "Description": description_text,
                "Base_Score": cvss_score,
            }

    except Exception as e:
        print(f"Erreur avec le fichier {file_path}: {e}")
        return None  # Retourne None en cas d'erreur

# Fonction pour traiter tous les fichiers d'une année
def process_year(year):
    year_path = os.path.join(CVE_ROOT, year)
    json_output = f"MITRE/cve_descriptions_{year}.json"
    
    cve_data_year = []

    if os.path.isdir(year_path):  # Vérifier que c'est un dossier
        file_paths = []
        
        # Collecter tous les fichiers JSON de l'année
        for cve_group in os.listdir(year_path):  # Parcourir les sous-dossiers (plages CVE)
            group_path = os.path.join(year_path, cve_group)
            if os.path.isdir(group_path):
                for file in os.listdir(group_path):  # Parcourir les fichiers JSON
                    if file.endswith(".json"):
                        file_paths.append(os.path.join(group_path, file))

        # Traitement en parallèle des fichiers de l'année
        with ProcessPoolExecutor(max_workers=multiprocessing.cpu_count()) as executor:
            for result in executor.map(process_json_file, file_paths):
                if result:  # Ne pas ajouter les résultats None
                    cve_data_year.append(result)

    # Sauvegarde des résultats en JSON pour l'année en cours
    with open(json_output, "w", encoding="utf-8") as json_out:
        json.dump(cve_data_year, json_out, indent=4)

    print(f"✅ Année {year} terminée ! Résultats enregistrés dans {json_output}.")

# Protection nécessaire pour Windows (empêche le crash)
if __name__ == "__main__":
    with ProcessPoolExecutor(max_workers=multiprocessing.cpu_count()) as executor:
        executor.map(process_year, YEARS_TO_PROCESS)

    print(f"🚀 Extraction terminée ! Résultats enregistrés dans cve_descriptions_YYYY.json pour chaque année.")
