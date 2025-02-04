import os
from django.http import JsonResponse
from django.views.decorators.http import require_GET

UPLOAD_FOLDER = "C:/Users/Momol/Documents/GitHub/Master2-Cybersecurite/SecuriteDesAppWeb/TP1/docs"

def lire_fichier(nom_du_fichier):
    file_path = os.path.join(UPLOAD_FOLDER, nom_du_fichier)
    
    try:
        with open(file_path, "r", encoding="utf-8") as fichier:
            return fichier.read()
    except FileNotFoundError:
        return "Le fichier n'existe pas."
    except Exception as erreur:
        return f"Une erreur s'est produite : {erreur}"

@require_GET
def lire_fichier_api(request):
    nom_du_fichier = request.GET.get("nom")
    if not nom_du_fichier:
        return JsonResponse({"erreur": "Paramètre 'nom' manquant."}, status=400)
    
    contenu = lire_fichier(nom_du_fichier)
    return JsonResponse({"contenu": contenu})
