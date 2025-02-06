import json
import ollama

# 📂 Fichier d'entrée et de sortie
INPUT_FILE = "./FUSION/merged_cve_1999_test.json"  # Nom du fichier JSON contenant les CVE
OUTPUT_FILE = "./Vulgariser/vulgarised_cve_1999_test.json"  # Fichier où enregistrer les prompts générés

# 📌 Charger les CVE depuis un fichier JSON
def load_json(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return json.load(file)
    except Exception as e:
        print(f"Erreur de lecture du fichier {file_path}: {e}")
        return []

# 📌 Générer un prompt pour chaque CVE
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
    return prompt

# 📌 Utiliser Ollama pour vulgariser chaque CVE
def vulgarize_cve(cve_data):
    vulgarized_cve_data = []

    for cve in cve_data:
        print(f"Traitement de {cve['CVE_ID']}...")

        # Générer le prompt
        prompt = generate_prompt(cve)

        try:
            # Envoyer à Ollama (local)
            response = ollama.chat(
                model="deepseek-r1:1.5b",
                messages=[{"role": "user", "content": prompt}],
            )
            vulgarized_text = response["message"]["content"]
        except Exception as e:
            print(f"Erreur pour {cve['CVE_ID']}: {e}")
            vulgarized_text = "Erreur de génération."

        # Ajouter le texte généré
        cve["Vulgarized_Description"] = vulgarized_text
        vulgarized_cve_data.append(cve)

    return vulgarized_cve_data

# 📌 Exécuter le traitement et sauvegarder les résultats
def process_cve_vulgarization():
    cve_data = load_json(INPUT_FILE)

    if not cve_data:
        print("Aucune donnée à traiter.")
        return

    vulgarized_cve_data = vulgarize_cve(cve_data)

    # 📌 Sauvegarde des résultats
    with open(OUTPUT_FILE, "w", encoding="utf-8") as json_out:
        json.dump(vulgarized_cve_data, json_out, indent=4, ensure_ascii=False)

    print(f"✅ Vulgarisation terminée ! Résultats enregistrés dans {OUTPUT_FILE}")

# 📌 Lancer le script
if __name__ == "__main__":
    process_cve_vulgarization()