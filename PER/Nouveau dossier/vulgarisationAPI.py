import json
import requests
import concurrent.futures

# 📂 Fichiers d'entrée et de sortie
INPUT_FILE = "./FUSION/merged_cve_1999_test.json"       # Fichier JSON contenant les CVE
OUTPUT_FILE = "./Vulgariser/vulgarised_cve_1999_test.json"  # Fichier où enregistrer les résultats

# ⚙️ Choix du modèle Ollama installé localement
MODEL = "deepseek-r1:1.5b"  # Remplace par le modèle que tu as installé

# 📌 Charger les CVE depuis un fichier JSON
def load_json(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return json.load(file)
    except Exception as e:
        print(f"Erreur de lecture du fichier {file_path} : {e}")
        return []

# 📌 Générer un prompt adapté pour vulgariser la vulnérabilité
def generate_prompt(cve):
    prompt = f"""
    Parle en français et répond uniquement explication ::
    Vulgarise cette vulnérabilité en un paragraphe très très court, clair et surtout destiné à une personne n'ayant aucune connaissance en cybersécurité.
    Explique comment un attaquant pourrait l'exploiter et quelles en seraient les conséquences pour un site web.
    Ajoute une phrase proposant une solution pour atténuer cette vulnérabilité.

    CVE ID : {cve.get('CVE_ID', 'ID inconnu')}
    Description technique : {cve.get('Description', 'Description non disponible')}
    Score de sévérité : {cve.get('Base_Score', 'Score inconnu')}
    """
    return prompt.strip()

# 📌 Traitement d'une seule CVE avec l'API Ollama
def process_single_cve(cve):
    print(f"Traitement de {cve.get('CVE_ID', 'ID inconnu')}...")
    prompt = generate_prompt(cve)

    url = "http://localhost:11434/api/generate"
    payload = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False  # Désactivé pour recevoir une réponse complète d'un coup
    }

    try:
        response = requests.post(url, json=payload)
        response_json = response.json()

        # Vérification et extraction de la réponse
        if "response" in response_json:
            vulgarized_text = response_json["response"]
        else:
            vulgarized_text = "Erreur de génération."

    except Exception as e:
        print(f"Erreur pour {cve.get('CVE_ID', 'ID inconnu')} : {e}")
        vulgarized_text = "Erreur de génération."

    cve["Vulgarized_Description"] = vulgarized_text
    return cve

# 📌 Traitement des CVE en parallèle avec ThreadPoolExecutor
def vulgarize_cve(cve_data):
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        results = executor.map(process_single_cve, cve_data)
        return list(results)

# 📌 Exécuter le traitement et sauvegarder les résultats
def process_cve_vulgarization():
    cve_data = load_json(INPUT_FILE)
    if not cve_data:
        print("Aucune donnée à traiter.")
        return

    vulgarized_cve_data = vulgarize_cve(cve_data)

    try:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as json_out:
            json.dump(vulgarized_cve_data, json_out, indent=4, ensure_ascii=False)
        print(f"✅ Vulgarisation terminée ! Résultats enregistrés dans {OUTPUT_FILE}")
    except Exception as e:
        print(f"Erreur lors de l'écriture du fichier {OUTPUT_FILE} : {e}")

# 📌 Lancer le script
if __name__ == "__main__":
    process_cve_vulgarization()
