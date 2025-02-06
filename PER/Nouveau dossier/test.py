import json
import requests

def get_top_n_cve(json_file, n, api_key, output_file="result_cve.json"):
    """
    Charge un fichier JSON contenant une liste de CVE et extrait les n premiers avec leur ID et description.
    Envoie ces données à l'API Groq pour enrichissement et enregistre automatiquement la réponse nettoyée.
    """
    try:
        with open(json_file, 'r', encoding='utf-8') as file:
            cve_data = json.load(file)
            
            # Extraction des n premiers CVE avec seulement ID et Description
            top_cve = [
                {"CVE_ID": cve["CVE_ID"], "Description": cve["Description"]} 
                for cve in cve_data[:n]
            ]
            
            # Préparation de la requête API
            url = "https://api.groq.com/openai/v1/chat/completions"
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}"
            }
            payload = {
                "model": "llama-3.3-70b-versatile",
                "messages": [{
                    "role": "user",
                    "content": f"Voici une liste de vulnérabilités CVE en JSON. Pour chaque CVE, ajoute un champ 'Vulgarisation' qui contient une explication courte en français suivie d'une solution. Réponds uniquement avec un JSON formaté : {json.dumps(top_cve, indent=4)}"
                }]
            }
            
            response = requests.post(url, headers=headers, json=payload)
            
            if response.status_code == 200:
                api_response = response.json()
                
                # Vérification et extraction sécurisée du contenu JSON
                raw_content = api_response.get("choices", [{}])[0].get("message", {}).get("content", "").strip()

                if not raw_content:
                    print("❌ Réponse vide ou invalide de l'API")
                    return []

                # Suppression des éventuels caractères parasites (backticks, "json\n", etc.)
                cleaned_content = raw_content.replace("```json", "").replace("```", "").strip()

                try:
                    cleaned_json = json.loads(cleaned_content)  # Vérification et conversion en JSON
                except json.JSONDecodeError as e:
                    print(f"❌ Erreur de parsing JSON : {e}")
                    print(f"Réponse brute API : {cleaned_content}")
                    return []

                # Enregistrement des résultats dans un fichier JSON
                with open(output_file, 'w', encoding='utf-8') as out_file:
                    json.dump(cleaned_json, out_file, indent=4, ensure_ascii=False)
                
                print(f"✅ Résultat sauvegardé automatiquement dans {output_file}")
                return cleaned_json
            else:
                print(f"❌ Erreur API : {response.status_code} - {response.text}")
                return []
            
    except Exception as e:
        print(f"❌ Erreur lors du traitement : {e}")
        return []

# Exemple d'utilisation
json_file = "./FUSION/merged_cve_1999.json"  # Remplace par ton fichier JSON réel
n = 50  # Nombre de CVE à récupérer
api_key = "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"  # Remplace par ta clé API
output_file = "cleaned_cve_data.json"  # Nom du fichier où stocker les résultats

cve_list = get_top_n_cve(json_file, n, api_key, output_file)

# ✅ Résultat final automatiquement enregistré dans cleaned_cve_data.json
