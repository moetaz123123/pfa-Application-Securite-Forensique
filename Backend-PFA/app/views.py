from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import RemoteEvidenceSerializer
from .utils import collect_evidence_linux, collect_evidence_windows , capture_disk_forensic_linux, capture_disk_forensic_ssh, capture_disk_forensic_windows, capture_disk_forensic_ssh_windows
from django.contrib.auth.models import User
from .models import ForensicImage
import os
#dependencie taz
#dependencie taz 
import logging
import json
import time
import subprocess
import hashlib
import psutil  # Pour capturer les informations système
# import yara  # Pour utiliser YARA
import requests  # Pour communiquer avec VirusTotal
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
import json
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from io import BytesIO
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from django.core.files.storage import FileSystemStorage




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
        
        #travaille de taz 
# Assurez-vous que MEDIA_ROOT et MEDIA_URL sont bien définis dans settings.py
MEDIA_ROOT = os.path.join(settings.BASE_DIR, 'media')
MEDIA_URL = '/media/'

# Créer le dossier media s'il n'existe pas
os.makedirs(MEDIA_ROOT, exist_ok=True)

# Extension autorisée pour les fichiers de trafic réseau
ALLOWED_EXTENSIONS = {'pcap'}

# Remplace cette clé par ta propre clé API de VirusTotal
API_KEY = "78a2d69f6874a7f18f1872d698c8cd41594c434e7a14a5e3f21a855e0252bb86"
VT_URL = "https://www.virustotal.com/api/v3/files"

def allowed_file(filename):
    """
    Vérifie si le fichier a une extension autorisée (ici .pcap).
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
@csrf_exempt
def analyze_traffic(request):
    if request.method == 'POST':
        if 'trafficFile' not in request.FILES or not allowed_file(request.FILES['trafficFile'].name):
            return JsonResponse({'error': 'Seuls les fichiers .pcap sont autorisés'}, status=400)
        
        traffic_file = request.FILES['trafficFile']
        file_path = os.path.join(MEDIA_ROOT, traffic_file.name)

        # Sécurisation du fichier et sauvegarde
        with open(file_path, 'wb') as f:
            for chunk in traffic_file.chunks():
                f.write(chunk)

        analysis_file_name = f"{traffic_file.name}_ports_analysis.txt"
        analysis_file_path = os.path.join(MEDIA_ROOT, analysis_file_name)

        try:
            # Utiliser TShark pour analyser le fichier pcap et extraire les informations des ports et IPs
            result = subprocess.run([ 
                'tshark', '-r', file_path, '-T', 'fields',
                '-e', 'tcp.port', '-e', 'udp.port', '-e', 'ip.src', '-e', 'ip.dst', '-e', 'ip.proto',
                '-e', 'frame.number'
            ], capture_output=True, text=True, check=True)

            # Initialiser des structures pour stocker les ports et IPs
            open_ports = set()
            suspicious_ips = set()
            
            # Analyser les résultats
            for line in result.stdout.splitlines():
                fields = line.split('\t')
                if len(fields) >= 4:
                    ip_src, ip_dst = fields[2], fields[3]
                    open_ports.add(fields[0])
                    open_ports.add(fields[1])
                    
                    # Marquer les IPs suspectes (par exemple, les IPs privées ou celles connues pour être malveillantes)
                    if ip_src.startswith('192.') or ip_src.startswith('10.') or ip_dst.startswith('192.') or ip_dst.startswith('10.'):
                        suspicious_ips.add(ip_src)
                        suspicious_ips.add(ip_dst)

            # Convertir en liste pour la réponse JSON
            open_ports_list = list(open_ports)
            suspicious_ips_list = list(suspicious_ips)

            # Générer un rapport filtré
            filtered_analysis_file_name = f"{traffic_file.name}_filtered_analysis.txt"
            filtered_analysis_file_path = os.path.join(MEDIA_ROOT, filtered_analysis_file_name)
            
            with open(filtered_analysis_file_path, 'w', encoding='utf-8', errors='replace') as f:
                f.write("Ports ouverts détectés:\n")
                f.writelines(f"{port}\n" for port in open_ports_list)
                f.write("\nIPs suspectes détectées:\n")
                f.writelines(f"{ip}\n" for ip in suspicious_ips_list)

            # Lien vers le fichier d'analyse filtré
            analysis_link = f"{MEDIA_URL}{filtered_analysis_file_name}"

            # Renvoyer la réponse avec les résultats et le lien vers l'analyse
            return JsonResponse({
                'open_ports': open_ports_list,
                'suspicious_ips': suspicious_ips_list,
                'analysis_link': analysis_link
            })

        except subprocess.CalledProcessError as e:
            logging.error(f"Erreur lors de l'exécution de TShark : {e}")
            return JsonResponse({'error': f"Erreur lors de l'analyse du fichier: {e}"}, status=500)
        except Exception as e:
            logging.error(f"Une erreur inattendue s'est produite : {e}")
            return JsonResponse({'error': "Une erreur inattendue s'est produite lors de l'analyse."}, status=500)

    return JsonResponse({'error': 'Méthode non autorisée'}, status=405)


def generate_hash(file_path):
    """
    Génère un hachage SHA-256 pour un fichier donné.
    """
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        logging.error(f"Erreur lors de la génération du hachage : {e}")
        return None

def capture_memory():
    """
    Capture l'état de la mémoire ou du disque et sauvegarde les informations dans un fichier.
    """
    memory_info = psutil.virtual_memory()
    disk_info = psutil.disk_usage('/')
    
    dump_file_name = "system_memory_dump.txt"
    dump_file_path = os.path.join(MEDIA_ROOT, dump_file_name)

    try:
        with open(dump_file_path, 'w', encoding='utf-8') as f:
            f.write("=== Informations sur la mémoire ===\n")
            f.write(f"Total : {memory_info.total}\n")
            f.write(f"Utilisé : {memory_info.used}\n")
            f.write(f"Libre : {memory_info.free}\n")
            f.write(f"Pourcentage utilisé : {memory_info.percent}%\n")

            f.write("\n=== Informations sur le disque ===\n")
            f.write(f"Total : {disk_info.total}\n")
            f.write(f"Utilisé : {disk_info.used}\n")
            f.write(f"Libre : {disk_info.free}\n")
            f.write(f"Pourcentage utilisé : {disk_info.percent}%\n")

        return f"{MEDIA_URL}{dump_file_name}"
    except Exception as e:
        logging.error(f"Erreur lors de la capture de la mémoire : {e}")
        return None

# def scan_file_for_malware(file_path):
#     """
#     Analyse un fichier pour détecter des malwares à l'aide de YARA.
#     """
#     try:
#         rules = yara.compile(filepath='malware_rules.yar')  # Charger les règles YARA
#         matches = rules.match(file_path)
#         if matches:
#             return {"status": "infected", "details": matches}
#         else:
#             return {"status": "clean"}
#     except Exception as e:
#         logging.error(f"Erreur lors du scan de malware avec YARA : {e}")
#         return {"status": "error", "message": str(e)}

def load_known_signatures():
    """Charge une liste de hachages connus de malwares."""
    return set()

def scan_disk_for_malware(directory_path, known_signatures):
    infected_files = []
    for root, _, files in os.walk(directory_path):
        for file in files:
            file_full_path = os.path.join(root, file)
            file_hash = generate_hash(file_full_path)
            if file_hash in known_signatures:
                infected_files.append({"file": file_full_path, "hash": file_hash})
    return {"status": "infected", "files": infected_files} if infected_files else {"status": "clean"}

@csrf_exempt
def analyze_file(request):
    """
    Vue pour analyser un fichier via VirusTotal.
    """
    if request.method == 'POST' and request.FILES.get('file'):
        file = request.FILES['file']
        
        headers = {
            "x-apikey": API_KEY
        }
        
        # Envoi du fichier à VirusTotal pour analyse
        response = requests.post(VT_URL, headers=headers, files={"file": file})
        
        if response.status_code == 200:
            # Si l'envoi a réussi, on récupère l'ID de l'analyse
            analysis_id = response.json()['data']['id']
            return JsonResponse({"analysis_id": analysis_id}, status=200)
        else:
            return JsonResponse({"error": "Erreur lors de l'envoi du fichier à VirusTotal"}, status=response.status_code)
    
    return JsonResponse({"error": "Aucun fichier fourni"}, status=400)

def get_report(request, analysis_id):
    """
    Vue pour récupérer le rapport d'analyse de VirusTotal avec un ID d'analyse.
    """
    report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    headers = {"x-apikey": API_KEY}
    
    try:
        response = requests.get(report_url, headers=headers)
        response.raise_for_status()  # Gère les erreurs HTTP (4xx, 5xx)
    except requests.exceptions.RequestException as e:
        return JsonResponse({"error": f"Erreur lors de la requête à VirusTotal: {str(e)}"}, status=500)

    if response.status_code == 200:
        # Extraction des statistiques de l'analyse
        try:
            result = response.json()["data"]["attributes"]["stats"]
        except KeyError:
            return JsonResponse({"error": "Erreur de format de réponse de VirusTotal."}, status=500)
        return JsonResponse(result, status=200)
    else:
        return JsonResponse({"error": "Erreur lors de la récupération du rapport"}, status=response.status_code)

def get_detailed_report(request, analysis_id):
    """
    Vue pour récupérer un rapport détaillé (les résultats complets) de l'analyse.
    """
    report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    headers = {"x-apikey": API_KEY}
    
    try:
        response = requests.get(report_url, headers=headers)
        response.raise_for_status()  # Gère les erreurs HTTP (4xx, 5xx)
    except requests.exceptions.RequestException as e:
        return JsonResponse({"error": f"Erreur lors de la requête à VirusTotal: {str(e)}"}, status=500)

    if response.status_code == 200:
        # Extraction des résultats complets de l'analyse
        try:
            result = response.json()["data"]["attributes"]
        except KeyError:
            return JsonResponse({"error": "Erreur de format de réponse de VirusTotal."}, status=500)
        return JsonResponse(result, status=200)
    else:
        return JsonResponse({"error": "Erreur lors de la récupération du rapport détaillé"}, status=response.status_code)

def analyze_and_get_report(request):
    """
    Vue pour analyser un fichier et récupérer le rapport après un certain temps d'attente.
    """
    if request.method == 'POST' and request.FILES.get('file'):
        file = request.FILES['file']
        
        headers = {
            "x-apikey": API_KEY
        }
        
        try:
            # Envoi du fichier à VirusTotal pour analyse
            response = requests.post(VT_URL, headers=headers, files={"file": file})
            response.raise_for_status()  # Gère les erreurs HTTP (4xx, 5xx)
        except requests.exceptions.RequestException as e:
            return JsonResponse({"error": f"Erreur lors de l'envoi du fichier à VirusTotal: {str(e)}"}, status=500)
        
        if response.status_code == 200:
            # Si l'envoi a réussi, on récupère l'ID de l'analyse
            analysis_id = response.json()['data']['id']
            print(f"Fichier envoyé avec succès. ID d'analyse: {analysis_id}")
            
            # Attente et récupération du rapport après l'analyse
            while True:
                time.sleep(10)  # Attente de 10 secondes avant de récupérer le rapport
                report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                try:
                    response = requests.get(report_url, headers=headers)
                    response.raise_for_status()  # Gère les erreurs HTTP (4xx, 5xx)
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
                    continue  # Attente pour la prochaine tentative
                    
        else:
            return JsonResponse({"error": "Erreur lors de l'envoi du fichier à VirusTotal"}, status=response.status_code)
    
    return JsonResponse({"error": "Aucun fichier fourni"}, status=400)

def generate_complete_report(file_hash, analysis_link, memory_dump, malware_scan_result, disk_scan_result):
    """
    Génère un rapport PDF contenant tous les résultats de l'analyse.
    """
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    
    # Titre du rapport
    c.setFont("Helvetica-Bold", 16)
    c.drawString(100, 750, "Rapport Complet d'Analyse")
    
    # Hachage du fichier
    c.setFont("Helvetica", 12)
    c.drawString(100, 730, f"Hash du fichier: {file_hash}")
    c.drawString(100, 710, f"Analyse réseau: {analysis_link}")
    c.drawString(100, 690, f"Capture mémoire: {memory_dump}")

    # Résultat du scan de malware
    c.drawString(100, 670, "Résultat du scan de malware:")
    y_position = 650
    for scan in malware_scan_result.get('details', []):
        c.drawString(100, y_position, f"- {scan}")
        y_position -= 20
    
    # Résultat du scan de disque
    c.drawString(100, y_position, "Résultat du scan disque:")
    y_position -= 20
    for infected_file in disk_scan_result.get('files', []):
        c.drawString(100, y_position, f"- {infected_file['file']} (Hash: {infected_file['hash']})")
        y_position -= 20

    # Gestion du cas où le contenu est trop long
    if y_position < 40:
        c.showPage()
        y_position = 750
        c.drawString(100, y_position, "Suite du rapport:")
        y_position -= 20

    # Enregistre le fichier PDF dans le buffer
    c.showPage()
    c.save()

    buffer.seek(0)
    return buffer

@csrf_exempt
def generate_report_view(request):
    """
    Vue pour générer un rapport complet sous forme de PDF après une analyse (POST uniquement) et afficher les résultats (GET).
    """
    if request.method == 'POST':
        # Suppose que les données d'analyse sont envoyées dans le corps de la requête POST
        try:
            data = json.loads(request.body)
            file_hash = data.get('file_hash', 'default_hash')
            analysis_link = data.get('analysis_link', 'http://default.com/analysis')
            memory_dump = data.get('memory_dump', '/media/default_memory_dump.txt')
            malware_scan_result = data.get('malware_scan_result', {"status": "unknown", "details": []})
            disk_scan_result = data.get('disk_scan_result', {"status": "unknown", "files": []})

            # Vérification des données nécessaires
            if not file_hash or not analysis_link or not memory_dump:
                return JsonResponse({"error": "Paramètres manquants"}, status=400)

            # Générer le rapport complet
            report_buffer = generate_complete_report(file_hash, analysis_link, memory_dump, malware_scan_result, disk_scan_result)

            # Enregistrement du rapport dans le dossier 'media'
            fs = FileSystemStorage(location=settings.MEDIA_ROOT)
            file_name = "rapport_complet.pdf"
            file_path = os.path.join(settings.MEDIA_ROOT, file_name)
            with open(file_path, 'wb') as f:
                f.write(report_buffer.getvalue())

            # Renvoyer l'URL du fichier généré dans la réponse
            file_url = fs.url(file_name)
            return JsonResponse({"message": "Rapport généré avec succès", "file_url": file_url})

        except json.JSONDecodeError:
            return JsonResponse({"error": "Données invalides"}, status=400)

    elif request.method == 'GET':
        # Pour la requête GET, on peut afficher les parties du rapport sans générer le PDF
        file_hash = request.GET.get('file_hash', 'default_hash')
        analysis_link = request.GET.get('analysis_link', 'http://default.com/analysis')
        memory_dump = request.GET.get('memory_dump', '/media/default_memory_dump.txt')

        response_data = {
            "file_hash": file_hash,
            "analysis_link": analysis_link,
            "memory_dump": memory_dump
        }

        return JsonResponse(response_data)

    # # Retourner une erreur pour les autres méthodes
    # return JsonResponse({"error": "Méthode non autorisée"}, status=405)