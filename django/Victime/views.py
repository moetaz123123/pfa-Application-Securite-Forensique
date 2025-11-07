import logging
import os
import hashlib  # Pour le hachage
import yara  # Pour utiliser YARA
import requests  # Pour communiquer avec VirusTotal
import time
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from scapy.all import rdpcap, IP, TCP,UDP
from django.contrib.auth.decorators import login_required

# # Assurez-vous que MEDIA_ROOT et MEDIA_URL sont bien définis dans settings.py
MEDIA_ROOT = os.path.join(settings.BASE_DIR, 'media')
MEDIA_URL = '/media/'

# # Créer le dossier media s'il n'existe pas
os.makedirs(MEDIA_ROOT, exist_ok=True)

# # Extension autorisée pour les fichiers de trafic réseau
ALLOWED_EXTENSIONS = {'pcap'}

# # Remplace cette clé par ta propre clé API de VirusTotal
API_KEY = "78a2d69f6874a7f18f1872d698c8cd41594c434e7a14a5e3f21a855e0252bb86"
VT_URL = "https://www.virustotal.com/api/v3/files"

def allowed_file(filename):
     """
     Vérifie si le fichier a une extension autorisée (ici .pcap).
#     """
     return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS 
from django.http import JsonResponse
from scapy.all import rdpcap, IP, TCP, UDP
import os
import logging

@csrf_exempt
def analyze_traffic(request):
    if request.method == 'POST':
        if 'trafficFile' not in request.FILES or not allowed_file(request.FILES['trafficFile'].name):
            return JsonResponse({'error': 'Seuls les fichiers .pcap sont autorisés'}, status=400)
        
        traffic_file = request.FILES['trafficFile']
        file_path = os.path.join('media', traffic_file.name)

        # Sécurisation du fichier et sauvegarde
        with open(file_path, 'wb') as f:
            for chunk in traffic_file.chunks():
                f.write(chunk)

        try:
            # Charger le fichier pcap
            packets = rdpcap(file_path)

            open_ports = set()
            suspicious_ips = set()

            for packet in packets:
                if IP in packet:
                    ip_src = packet[IP].src
                    ip_dst = packet[IP].dst
                    # Marquer les IPs suspectes (par exemple, les IPs privées)
                    if ip_src.startswith('192.') or ip_src.startswith('10.') or ip_dst.startswith('192.') or ip_dst.startswith('10.'):
                        suspicious_ips.add(ip_src)
                        suspicious_ips.add(ip_dst)
  
                    # Vérifier la présence de la couche TCP ou UDP avant d'accéder à sport et dport
                    if TCP in packet:
                        open_ports.add(packet[TCP].sport)
                        open_ports.add(packet[TCP].dport)
                    elif UDP in packet:
                        open_ports.add(packet[UDP].sport)
                        open_ports.add(packet[UDP].dport)

            # Convertir en liste pour la réponse JSON
            open_ports_list = list(open_ports)
            suspicious_ips_list = list(suspicious_ips)

            # Générer un rapport filtré
            filtered_analysis_file_name = f"{traffic_file.name}_filtered_analysis.txt"
            filtered_analysis_file_path = os.path.join('media', filtered_analysis_file_name)
            
            with open(filtered_analysis_file_path, 'w', encoding='utf-8', errors='replace') as f:
                f.write("Ports ouverts détectés:\n")
                f.writelines(f"{port}\n" for port in open_ports_list)
                f.write("\nIPs suspectes détectées:\n")
                f.writelines(f"{ip}\n" for ip in suspicious_ips_list)

            # Lien vers le fichier d'analyse filtré
            analysis_link = f"/media/{filtered_analysis_file_name}"

            # Renvoyer la réponse avec les résultats et le lien vers l'analyse
            return JsonResponse({
                  'open_ports': open_ports_list,
                  'suspicious_ips': suspicious_ips_list,
                  'analysis_link': analysis_link
            })

        except Exception as e:
            logging.error(f"Une erreur inattendue s'est produite : {e}")
            return JsonResponse({'error': f"Une erreur inattendue s'est produite lors de l'analyse: {e}"}, status=500)

    return JsonResponse({'error': 'Méthode non autorisée'}, status=405)
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import time
import requests
from .utils import calculate_file_hash

# Analyse d'un fichier via VirusTotal
@csrf_exempt
def analyze_file(request):
    if request.method == 'POST' and request.FILES.get('file'):
        file = request.FILES['file']
        headers = {"x-apikey": API_KEY}
        response = requests.post(VT_URL, headers=headers, files={"file": file})

        if response.status_code == 200:
            analysis_id = response.json().get('data', {}).get('id', None)
            if not analysis_id:
                return JsonResponse({"error": "Erreur lors de la récupération de l'ID d'analyse."}, status=500)

            fichier_status = "clean"
            file_hash = calculate_file_hash(file)

            try:
                # Enregistrement dans la base de données
                file_analysis = FileAnalysis.objects.create(
                    user=None,  # Accepte les utilisateurs anonymes
                    file_hash=file_hash,
                    fichier_status=fichier_status,
                    analysis_id=analysis_id,
                    fichier_status_details=response.json()
                )
                file_analysis.save()

                return JsonResponse({
                    "message": "Analyse enregistrée avec succès.",
                    "analysis_id": analysis_id,
                    "fichier_status": fichier_status,
                    "file_hash": file_hash
                })

            except Exception as e:
                return JsonResponse({"error": f"Erreur lors de l'enregistrement de l'analyse: {str(e)}"}, status=500)

        return JsonResponse({"error": "Échec de l'analyse VirusTotal."}, status=500)

    return JsonResponse({"error": "Méthode non autorisée."}, status=405)

# Récupération du rapport d'analyse
def get_report(request, analysis_id):
    report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    headers = {"x-apikey": API_KEY}

    try:
        response = requests.get(report_url, headers=headers)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        return JsonResponse({"error": f"Erreur lors de la requête à VirusTotal: {str(e)}"}, status=500)

    if response.status_code == 200:
        try:
            result = response.json()["data"]["attributes"]["stats"]
        except KeyError:
            return JsonResponse({"error": "Erreur de format de réponse de VirusTotal."}, status=500)
        return JsonResponse(result, status=200)
    else:
        return JsonResponse({"error": "Erreur lors de la récupération du rapport"}, status=response.status_code)

# Récupération d'un rapport détaillé
@csrf_exempt
def get_detailed_report(request, analysis_id):
    report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    headers = {"x-apikey": API_KEY}

    try:
        response = requests.get(report_url, headers=headers)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        return JsonResponse({"error": f"Erreur lors de la requête à VirusTotal: {str(e)}"}, status=500)

    if response.status_code == 200:
        try:
            result = response.json()["data"]["attributes"]
        except KeyError:
            return JsonResponse({"error": "Erreur de format de réponse de VirusTotal."}, status=500)
        return JsonResponse(result, status=200)
    else:
        return JsonResponse({"error": "Erreur lors de la récupération du rapport détaillé"}, status=response.status_code)
    
def scan_file_for_malware(file_path):
    """
    Analyse un fichier pour détecter des malwares à l'aide de YARA.
    """
    try:
        rules = yara.compile(filepath='malware_rules.yar')  # Charger les règles YARA
        matches = rules.match(file_path)
        if matches:
            return {"status": "infected", "details": matches}
        else:
            return {"status": "clean"}
    except Exception as e:
        logging.error(f"Erreur lors du scan de malware avec YARA : {e}")
    return {"status": "error", "message": str(e)}

def load_known_signatures():
    """Charge une liste de hachages connus de malwares."""
    return set()


# Analyse et récupération du rapport
def analyze_and_get_report(request):
    if request.method == 'POST' and request.FILES.get('file'):
        file = request.FILES['file']
        headers = {"x-apikey": API_KEY}

        try:
            response = requests.post(VT_URL, headers=headers, files={"file": file})
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            return JsonResponse({"error": f"Erreur lors de l'envoi du fichier à VirusTotal: {str(e)}"}, status=500)

        if response.status_code == 200:
            analysis_id = response.json()['data']['id']
            print(f"Fichier envoyé avec succès. ID d'analyse: {analysis_id}")

            while True:
                time.sleep(10)
                report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                try:
                    response = requests.get(report_url, headers=headers)
                    response.raise_for_status()
                except requests.exceptions.RequestException as e:
                    return JsonResponse({"error": f"Erreur lors de la requête pour récupérer le rapport : {str(e)}"}, status=500)

                if response.status_code == 200:
                    try:
                        result = response.json()["data"]["attributes"]["stats"]
                        return JsonResponse(result, status=200)
                    except KeyError:
                        return JsonResponse({"error": "Erreur de format de réponse de VirusTotal."}, status=500)
                else:
                    print("Analyse en cours... Attente de 10 secondes.")
                    continue
        else:
            return JsonResponse({"error": "Erreur lors de l'envoi du fichier à VirusTotal"}, status=response.status_code)

    return JsonResponse({"error": "Aucun fichier fourni"}, status=400)





from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import FileAnalysis, FileHash
from django.contrib.auth.models import User
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User
from .models import FileHash
import json
from django.http import JsonResponse
from .models import FileHash
from django.contrib.auth.models import User

@csrf_exempt
def add_file_hash(request):
     if request.method == 'POST':
         file_path = request.POST.get('file_path')
         file_hash = request.POST.get('file_hash')
         status = request.POST.get('status')
         user_id = request.POST.get('user_id')

         if not file_path or not file_hash or not status or not user_id:
             return JsonResponse({'error': 'Données manquantes'}, status=400)

         try:
             # Vérification et récupération de l'utilisateur
             user = User.objects.get(id=user_id)
             print(f"Utilisateur trouvé: {user.username}")

#             # Création de l'enregistrement dans la base de données
             file_record = FileHash.objects.create(
                 user=user,
                 file_path=file_path,
                 file_hash=file_hash,
                 status=status
             )
             file_record.save()

             return JsonResponse({'message': 'Fichier ajouté avec succès', 'file_id': file_record.id}, status=201)

         except User.DoesNotExist:
             return JsonResponse({'error': 'Utilisateur non trouvé'}, status=404)
    
     return JsonResponse({'error': 'Méthode non autorisée'}, status=405)

from django.http import JsonResponse
from .models import FileHash
from django.http import JsonResponse#
from .models import FileHash

def get_file_hashes(request):
     file_hashes = FileHash.objects.all()
     print(file_hashes)  # Ajoute cette ligne pour voir si les données sont récupérées
     data = []
     for file_hash in file_hashes:
         data.append({
             "file_path": file_hash.file_path,
             "file_hash": file_hash.file_hash,
             "status": file_hash.status,
             "user_id": file_hash.user.id,
             "created_at": file_hash.created_at
         })
     return JsonResponse(data, safe=False)

import hashlib

def calculate_file_hash(file):
     """
     Fonction pour calculer le hash SHA-256 d'un fichier.
     """
     sha256 = hashlib.sha256()  # Création de l'objet de hashage SHA-256
     for chunk in file.chunks():  # Parcours du fichier en morceaux (pour ne pas tout charger en mémoire)
         sha256.update(chunk)  # Mise à jour du hash avec chaque morceau
     return sha256.hexdigest()  # Retourne le hash final sous forme de chaîne hexadécimale

from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import TrafficAnalysis
from .serializers import TrafficAnalysisSerializer

@api_view(['GET'])
def get_traffic_analysis(request):
     analyses = TrafficAnalysis.objects.all()  # Récupérer toutes les analyses
     serializer = TrafficAnalysisSerializer(analyses, many=True)  # Sérialiser les données
     return Response(serializer.data)  # Retourner la réponse JSON



# anlyse all
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .views import analyze_traffic, analyze_file, get_detailed_report  
import logging

logger = logging.getLogger(__name__)

@csrf_exempt
def analyze_all(request):
    logger.info(f"Requête reçue : {request.method} - {request.GET} - {request.FILES}")

    if request.method == 'POST':
        if 'trafficFile' in request.FILES:
            return analyze_traffic(request)
        elif 'file' in request.FILES:
            return analyze_file(request)
        else:
            return JsonResponse({"error": "Aucun fichier trouvé dans la requête."}, status=400)

    elif request.method == 'GET':
        analysis_id = request.GET.get('analysis_id')
        if analysis_id:
            return get_detailed_report(request, analysis_id)
        else:
            return JsonResponse({"error": "L'ID d'analyse est requis."}, status=400)

    return JsonResponse({"error": "Méthode non autorisée."}, status=405)



# docker
import logging
import os
import pyclamd
import traceback
import hashlib

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

logger = logging.getLogger(__name__)

@csrf_exempt
def scan_docker_files(request):
    if request.method != 'POST':
        return JsonResponse({"error": "Méthode non autorisée"}, status=405)

    if 'file' not in request.FILES:
        return JsonResponse({"error": "Aucun fichier fourni"}, status=400)

    uploaded_file = request.FILES['file']

    temp_dir = 'scanner/temp/'
    os.makedirs(temp_dir, exist_ok=True)

    file_path = os.path.join(temp_dir, uploaded_file.name)
    file_hash = None

    try:
        # Calculer le hash tout en enregistrant le fichier
        sha256_hash = hashlib.sha256()
        with open(file_path, 'wb') as f:
            for chunk in uploaded_file.chunks():
                f.write(chunk)
                sha256_hash.update(chunk)
        file_hash = sha256_hash.hexdigest()

        # Connexion à ClamAV
        logger.info("Connexion à ClamAV...")
        cd = pyclamd.ClamdNetworkSocket(host="clamav", port=3310)
        cd.ping()
        logger.info("ClamAV est en ligne.")

        # Scanner le fichier
        infected_files = cd.scan_file(file_path)

    except FileNotFoundError as fnf_err:
        logger.error(f"Fichier introuvable: {fnf_err}")
        return JsonResponse({
            "message": "Erreur pendant le scan",
            "infected": False,
            "details": [{
                "file": file_path,
                "status": "ERROR",
                "error": str(fnf_err)
            }]
        })

    except pyclamd.ConnectionError as ce:
        logger.error(f"Erreur de connexion à ClamAV: {ce}")
        return JsonResponse({
            "message": "Erreur de connexion à ClamAV",
            "infected": False,
            "details": [{
                "status": "ERROR",
                "error": str(ce)
            }]
        }, status=500)

    except Exception as e:
        logger.error(f"Erreur inattendue: {traceback.format_exc()}")
        return JsonResponse({
            "message": "Erreur inattendue pendant le traitement",
            "infected": False,
            "details": [{
                "status": "ERROR",
                "error": str(e)
            }]
        }, status=500)

    finally:
        if os.path.exists(file_path):
            os.remove(file_path)

    if infected_files:
        return JsonResponse({
            "message": "Virus détecté !",
            "infected": True,
            "hash": file_hash,
            "details": infected_files
        })
    else:
        return JsonResponse({
            "message": "Aucun virus détecté dans le fichier",
            "infected": False,
            "hash": file_hash
        })



#  dependice youssef 
import hashlib
import subprocess
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import RemoteEvidenceSerializer
from .utils import collect_evidence_linux, collect_evidence_windows , capture_disk_forensic_linux, capture_disk_forensic_ssh, capture_disk_forensic_windows, capture_disk_forensic_ssh_windows
from django.contrib.auth.models import User
from .models import ForensicImage
import os


# travaillle youssef


class CollectRemoteEvidence(APIView):
    """
    Collecte des preuves à distance depuis une machine distante via SSH ou PowerShell.
    """
    def post(self, request):
        # Extraire les données de la requête
        host = request.data.get('host')
        username = request.data.get('username')
        password = request.data.get('password')
        remote_file_path = request.data.get('remote_file_path')
        os_type = request.data.get('os_type')  # linux ou windows
        user_id = request.data.get('user_id')  # ID de l'utilisateur

        if not all([host, username, password, remote_file_path, os_type, user_id]):
            return Response({"error": "Tous les champs sont obligatoires."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(id=user_id)  # Récupère l'utilisateur à partir de son ID
        except User.DoesNotExist:
            return Response({"error": "Utilisateur non trouvé."}, status=status.HTTP_400_BAD_REQUEST)

        # Collecte des preuves en fonction du type de système
        if os_type == 'linux':
            remote_evidence = collect_evidence_linux(host, username, password, remote_file_path, user)
        elif os_type == 'windows':
            remote_evidence = collect_evidence_windows(host, username, password, remote_file_path, user)
        else:
            return Response({"error": "Type de système non pris en charge."}, status=status.HTTP_400_BAD_REQUEST)

        # Sérialiser les données de la preuve collectée
        serializer = RemoteEvidenceSerializer(remote_evidence)
        
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    


class ForensicCaptureAPIView(APIView):
    def post(self, request):
        # Récupérer les paramètres depuis la requête
        host = request.data.get('host')
        username = request.data.get('username')
        password = request.data.get('password')
        disk_name = request.data.get('disk_name')
        output_file = request.data.get('output_file')  # Chemin du fichier où l'image sera enregistrée
        local_output_dir = request.data.get('local_output_dir')
        user_id = request.data.get('user_id')  # ID de l'utilisateur

        # Vérification des données nécessaires
        if not host or not username or not password or not disk_name or not output_file:
            return Response({"error": "All fields are required."}, status=status.HTTP_400_BAD_REQUEST)

        # Vérification si local_output_dir est nécessaire pour la capture distante
        if host != 'localhost' and not local_output_dir:
            return Response({"error": "local_output_dir is required for remote capture."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Capture de l'image forensique, local ou distant
            if host == 'localhost':
                # Si le système est local, capturer avec la méthode Linux
                if os.name == 'posix':  # Si c'est un système Linux
                    hash_value = capture_disk_forensic_linux(disk_name, output_file)
                elif os.name == 'nt':  # Si c'est un système Windows
                    hash_value = capture_disk_forensic_windows(disk_name, output_file)
            else:
                # Si le système est distant, capturer via SSH
                if host.lower().endswith('.local') or host.lower().startswith('192.'):
                    print("capture distant pour linux")
                    hash_value = capture_disk_forensic_ssh(host, username, password, disk_name, output_file, local_output_dir)
                else:
                    hash_value = capture_disk_forensic_ssh_windows(host, username, password, disk_name, output_file, local_output_dir)

            # Vérifier si le fichier d'image existe
            if not os.path.exists(local_output_dir):
                return Response({"error": "directory not found."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            try:
              user = User.objects.get(id=user_id)  # Récupère l'utilisateur à partir de son ID
            except User.DoesNotExist:
                   return Response({"error": "Utilisateur non trouvé."}, status=status.HTTP_400_BAD_REQUEST)
            # Sauvegarder l'image forensique dans le modèle ForensicImage
            forensic_image = ForensicImage.objects.create(
                user=user,
                disk_name=disk_name,
                image_file=output_file,  # Assurez-vous que le fichier est dans un répertoire géré par Django (MEDIA_ROOT)
                hash_value=hash_value
            )

            return Response({
                "message": f"Forensic image captured successfully. Hash: {hash_value}",
                "image_id": forensic_image.id
            }, status=status.HTTP_200_OK)

        except Exception as e:
            # Gestion des erreurs avec traceback pour le débogage
            print(str(e))
            return Response({"error": f"Erreur lors de la capture: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        