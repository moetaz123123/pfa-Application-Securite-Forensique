
import requests

def get_detailed_report_by_id(analysis_id):
    """
    Récupère le rapport détaillé de VirusTotal à partir de l'ID d'analyse.
    """
    api_key = "78a2d69f6874a7f18f1872d698c8cd41594c434e7a14a5e3f21a855e0252bb86"
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

    headers = {
        "x-apikey": api_key
    }

    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        # Le rapport détaillé est dans la réponse JSON
        report = response.json()
        
        # Extraire des informations spécifiques du rapport
        status = report.get('data', {}).get('attributes', {}).get('status', 'Inconnu')
        detections_count = len(report.get('data', {}).get('attributes', {}).get('malicious', []))
        
        return {
            "status": status,
            "detections_count": detections_count
        }
    else:
        # Si l'API retourne une erreur
        raise Exception(f"Erreur lors de la récupération du rapport : {response.status_code}")


from django.contrib.auth.models import User
from .models import FileHash
import hashlib

def generate_hash_and_save(file_path, user):
    # Générer le hachage du fichier
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    
    file_hash = sha256_hash.hexdigest()

    # Enregistrer dans la base de données (MySQL)
    file_record = FileHash.objects.create(
        user=user,
        file_path=file_path,
        file_hash=file_hash,
        status='clean'  # Ou 'infected' selon l'analyse
    )
    return file_record


import hashlib
import yara
import os
import logging

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




import hashlib
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from io import BytesIO

def calculate_file_hash(file):
    """
    Calcule le hash SHA256 du fichier pour identifier de manière unique ce fichier.
    """
    file_hash = hashlib.sha256()
    for chunk in file.chunks():
        file_hash.update(chunk)
    return file_hash.hexdigest()

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


# youssef 
import paramiko
import winrm
from .models import RemoteEvidence
from django.utils.timezone import now
import subprocess
import hashlib
import time
import os




from django.contrib.auth.models import User  # Assure-toi d'importer le modèle User de Django

def collect_evidence_linux(host, username, password, remote_file_path, user):
    # Connexion SSH
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, username=username, password=password)

    # Télécharger le fichier
    sftp = ssh.open_sftp()
    local_file_path = f"local_path/{remote_file_path.split('/')[-1]}"  # Chemin local
    sftp.get(remote_file_path, local_file_path)

     # Calculer le hash du fichier téléchargé
    hash_value = calculate_file_hash(local_file_path)
    # Enregistrer l'évidence dans la base de données
    remote_evidence = RemoteEvidence.objects.create(
        user=user,  # L'utilisateur associé
        remote_host=host,
        file=local_file_path,
        hash_value=hash_value,  # Ajouter le hash ici
        collected_at=now()
    )

    sftp.close()
    ssh.close()
    
    return remote_evidence


# Fonction pour collecter les preuves sur Windows via PowerShell
def collect_evidence_windows(host, username, password, remote_file_path):
    # Connexion PowerShell via winrm
    session = winrm.Session(host, auth=(username, password), transport='ntlm')
    
    # Exécuter une commande PowerShell pour récupérer le fichier
    command = f"Copy-Item -Path {remote_file_path} -Destination C:\\temp\\{remote_file_path.split('/')[-1]}"
    session.run_ps(command)

        # Chemin local où le fichier a été copié
    local_file_path = f"C:\\temp\\{remote_file_path.split('/')[-1]}"

    # Calculer le hash du fichier copié
    hash_value = calculate_file_hash(local_file_path)

    # Enregistrer l'évidence dans la base de données
    remote_evidence = RemoteEvidence.objects.create(
        user=None,  # L'utilisateur peut être ajouté selon les besoins
        remote_host=host,
        file=f"C:\\temp\\{remote_file_path.split('/')[-1]}",
        hash_value=hash_value,  # Ajouter le hash ici
        collected_at=now()
    )
    
    return remote_evidence

def calculate_file_hash(file_path):
    """
    Calcule le hash SHA256 d'un fichier donné.
    """
    sha256_hash = hashlib.sha256()

    with open(file_path, "rb") as f:
        # Lire le fichier par blocs de 4096 octets pour ne pas tout charger en mémoire
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    
    return sha256_hash.hexdigest()

#capture local pour linux  
def capture_disk_forensic_linux(disk_name, output_file):
    """Capture l'image forensique d'un disque sur un système Linux et calcule son hash."""
    # Exécution de la commande dd pour créer l'image du disque
    command = ["dd", f"if={disk_name}", f"of={output_file}", "bs=64K", "conv=noerror,sync"]
    subprocess.run(command, check=True)

    # Générer le hash pour l'intégrité du fichier
    hash_value =  calculate_file_hash(output_file)
    return hash_value

#capture distant pour linux
def capture_disk_forensic_ssh(host, username, password, disk_name, output_dir, local_output_dir):
    """Capture l'image forensique d'un disque à distance via SSH avec téléchargement et hashage."""
    print(f"🟢 Connexion à {host} via SSH...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(host, username=username, password=password, timeout=10, look_for_keys=False, allow_agent=False)

        print("✅ Connexion SSH réussie.")

        # Vérifier si le dossier de destination existe sur la machine distante
        check_dir_command = f"mkdir -p {output_dir}"
        print(f"📂 Vérification du dossier de destination: {output_dir}")
        ssh.exec_command(check_dir_command)

        # Commande dd à exécuter à distance
        command = f"echo {password} | sudo -S dd if={disk_name} of={output_dir}/image_{disk_name.replace('/', '_')}.dd bs=64K conv=noerror,sync 2> {output_dir}/dd_error.log"
        print(f"⚙️ Exécution de la commande: {command}")

        stdin, stdout, stderr = ssh.exec_command(command)
        stdout_data = stdout.read().decode()
        stderr_data = stderr.read().decode()

        print(f"stdout: {stdout_data}")
        print(f"stderr: {stderr_data}")

        if stderr_data:
            print(f"❌ Erreur: {stderr_data}")
            return {"error": stderr_data}

        start_time = time.time()
        while not stdout.channel.exit_status_ready():
            line = stdout.readline().strip()
            if line:
                print(f"📊 Progression: {line}")
            time.sleep(1)

        end_time = time.time()
        print(f"✅ Capture terminée en {round(end_time - start_time, 2)} secondes.")

        # Télécharger l'image disque depuis la machine distante vers la machine locale
        remote_image_path = f"{output_dir}/image_{disk_name.replace('/', '_')}.dd"
        local_image_path = os.path.join(local_output_dir, f"image_{disk_name.replace('/', '_')}.dd")
        print(f"🔽 Téléchargement de l'image disque vers le répertoire local: {local_image_path}")

        sftp = ssh.open_sftp()
        sftp.get(remote_image_path, local_image_path)
        sftp.close()

        # Vérification de l'intégrité du fichier téléchargé
        print(f"🔍 Vérification de l'intégrité du fichier : {local_image_path}")
        hash_value = calculate_file_hash(local_image_path)
        print(f"✅ Hash SHA-256: {hash_value}")
        return {"message": "Forensic capture completed successfully.", "hash": hash_value}

    except Exception as e:
        print(f"🚨 Erreur lors de la capture forensique: {str(e)}")
        return {"error": str(e)}

#capture local pour windows
def capture_disk_forensic_windows(disk_name, output_file):
    """Capture l'image forensique d'un disque local sur un système Windows via PowerShell et calcule son hash."""
    command = f"powershell New-Item -Path '{output_file}' -ItemType File; dd if={disk_name} of={output_file} bs=64K"
    subprocess.run(command, check=True, shell=True)

    # Générer le hash pour l'intégrité du fichier
    hash_value = calculate_file_hash(output_file)
    return hash_value

#capture distant pour windows
def capture_disk_forensic_ssh_windows(host, username, password, disk_name, output_file):
    """Capture l'image forensique d'un disque à distance via SSH et PowerShell pour Windows."""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, username=username, password=password)

    # Commande PowerShell pour capturer l'image du disque
    command = f"powershell New-Item -Path '{output_file}' -ItemType File; dd if={disk_name} of={output_file} bs=64K"
    stdin, stdout, stderr = ssh.exec_command(command)
    stdout.channel.recv_exit_status()  # Attendre la fin de la commande
    ssh.close()

    # Générer le hash pour l'intégrité du fichier
    hash_value = calculate_file_hash(output_file)
    return hash_value


