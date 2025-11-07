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

