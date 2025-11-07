from django.db import models

class Victime(models.Model):
    # champs du modèle
    pass
from django.db import models
from django.contrib.auth.models import User

class HostEvidence(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)  # Utilisateur ayant collecté la preuve
    file = models.FileField(upload_to='host_evidences/')  # Fichier collecté
    file_path = models.CharField(max_length=500)  # Chemin du fichier original
    hash_value = models.CharField(max_length=64, blank=True)  # Hash du fichier pour intégrité
    status = models.CharField(max_length=50, default='Pending')  # Statut de l’analyse
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Host Evidence {self.id} by {self.user.username}"

class RemoteEvidence(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    remote_host = models.CharField(max_length=255)  # Adresse IP ou nom d’hôte distant
    file = models.FileField(upload_to='remote_evidences/')
    hash_value = models.CharField(max_length=64, blank=True)
    collected_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Remote Evidence {self.id} from {self.remote_host}"

class NetworkCapture(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    capture_file = models.FileField(upload_to='network_captures/')  # Fichier .pcap
    start_time = models.DateTimeField(auto_now_add=True)
    end_time = models.DateTimeField(null=True, blank=True)
    filter_used = models.CharField(max_length=255, blank=True)  # Exemple : "port 80"
    status = models.CharField(max_length=50, default='Pending')
    hash_value = models.CharField(max_length=64, blank=True)

    def __str__(self):
        return f"Capture {self.id} by {self.user.username}"

class ForensicImage(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    disk_name = models.CharField(max_length=255)  # Nom du disque/partition analysé
    image_file = models.FileField(upload_to='forensic_images/')  # Image forensique (.dd, .E01)
    hash_value = models.CharField(max_length=256, blank=True)  # Vérification d'intégrité
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Forensic Image {self.id} from {self.disk_name}"

class Analysis(models.Model):
    ANALYSIS_TYPE_CHOICES = [
        ('host', 'Host Evidence'),
        ('remote', 'Remote Evidence'),
        ('network', 'Network Capture'),
        ('forensic', 'Forensic Image'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    analysis_type = models.CharField(max_length=50, choices=ANALYSIS_TYPE_CHOICES)  
    host_evidence = models.ForeignKey(HostEvidence, on_delete=models.CASCADE, null=True, blank=True)
    remote_evidence = models.ForeignKey(RemoteEvidence, on_delete=models.CASCADE, null=True, blank=True)
    network_capture = models.ForeignKey(NetworkCapture, on_delete=models.CASCADE, null=True, blank=True)
    forensic_image = models.ForeignKey(ForensicImage, on_delete=models.CASCADE, null=True, blank=True)
    
    tool_used = models.CharField(max_length=100)  # Exemple : FTK Imager, Wireshark
    result = models.TextField()  # Résultats détaillés de l’analyse
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Analysis {self.id} - {self.analysis_type} using {self.tool_used}"

# models.py

from django.db import models
from django.contrib.auth.models import User

class FileHash(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)  # Lien avec l'utilisateur
    file_path = models.CharField(max_length=255)  # Chemin du fichier
    file_hash = models.CharField(max_length=64)  # Hachage du fichier (SHA-256)
    status = models.CharField(max_length=20, choices=[('clean', 'Clean'), ('infected', 'Infected')], default='clean')
    created_at = models.DateTimeField(auto_now_add=True)  # Date de création automatique

    def __str__(self):
        return f"Hash: {self.file_hash} - Status: {self.status} - User: {self.user.username}"
from django.db import models
from django.contrib.auth.models import User

class FileAnalysis(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)  # Permet les valeurs nulles si l'utilisateur est anonyme
    file_hash = models.CharField(max_length=64)
    
    fichier_status = models.CharField(
        max_length=20,
        choices=[('clean', 'Clean'), ('infected', 'Infected')],
        default='clean'
    )
    
    fichier_status_details = models.TextField(null=True, blank=True)  # ✅ Ajout pour les détails supplémentaires (facultatif)
    
    created_at = models.DateTimeField(auto_now_add=True)
    analysis_id = models.CharField(max_length=255, null=True, blank=True)
    virus_details = models.JSONField(null=True, blank=True)

    def __str__(self):
        return f"Hash: {self.file_hash} - Status: {self.fichier_status} - User: {self.user.username if self.user else 'Anonymous'} - Date: {self.created_at}"

from django.db import models
from django.contrib.auth.models import User

class TrafficAnalysis(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    file_path = models.CharField(max_length=255)
    suspicious_ips = models.JSONField()  # Pour stocker une liste d'IPs suspectes
    open_ports = models.JSONField()  # Pour stocker une liste de ports ouverts
    hash = models.CharField(max_length=64)  # Hachage du fichier
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Analysis by {self.user.username} on {self.created_at}"
# youssef

from django.db import models
from django.contrib.auth.models import User

class HostEvidence(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)  # Utilisateur ayant collecté la preuve
    file = models.FileField(upload_to='host_evidences/')  # Fichier collecté
    file_path = models.CharField(max_length=500)  # Chemin du fichier original
    hash_value = models.CharField(max_length=64, blank=True)  # Hash du fichier pour intégrité
    status = models.CharField(max_length=50, default='Pending')  # Statut de l’analyse
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Host Evidence {self.id} by {self.user.username}"

class RemoteEvidence(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    remote_host = models.CharField(max_length=255)  # Adresse IP ou nom d’hôte distant
    file = models.FileField(upload_to='remote_evidences/')
    hash_value = models.CharField(max_length=64, blank=True)
    collected_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Remote Evidence {self.id} from {self.remote_host}"

class NetworkCapture(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    capture_file = models.FileField(upload_to='network_captures/')  # Fichier .pcap
    start_time = models.DateTimeField(auto_now_add=True)
    end_time = models.DateTimeField(null=True, blank=True)
    filter_used = models.CharField(max_length=255, blank=True)  # Exemple : "port 80"
    status = models.CharField(max_length=50, default='Pending')
    hash_value = models.CharField(max_length=64, blank=True)

    def __str__(self):
        return f"Capture {self.id} by {self.user.username}"

class ForensicImage(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    disk_name = models.CharField(max_length=255)  # Nom du disque/partition analysé
    image_file = models.FileField(upload_to='forensic_images/')  # Image forensique (.dd, .E01)
    hash_value = models.CharField(max_length=256, blank=True)  # Vérification d'intégrité
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Forensic Image {self.id} from {self.disk_name}"

class Analysis(models.Model):
    ANALYSIS_TYPE_CHOICES = [
        ('host', 'Host Evidence'),
        ('remote', 'Remote Evidence'),
        ('network', 'Network Capture'),
        ('forensic', 'Forensic Image'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    analysis_type = models.CharField(max_length=50, choices=ANALYSIS_TYPE_CHOICES)  
    host_evidence = models.ForeignKey(HostEvidence, on_delete=models.CASCADE, null=True, blank=True)
    remote_evidence = models.ForeignKey(RemoteEvidence, on_delete=models.CASCADE, null=True, blank=True)
    network_capture = models.ForeignKey(NetworkCapture, on_delete=models.CASCADE, null=True, blank=True)
    forensic_image = models.ForeignKey(ForensicImage, on_delete=models.CASCADE, null=True, blank=True)
    
    tool_used = models.CharField(max_length=100)  # Exemple : FTK Imager, Wireshark
    result = models.TextField()  # Résultats détaillés de l’analyse
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Analysis {self.id} - {self.analysis_type} using {self.tool_used}"
