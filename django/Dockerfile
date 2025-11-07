FROM python:3.9-slim

WORKDIR /scanner

# Installer les dépendances système
RUN apt-get update && apt-get install -y wget build-essential libffi-dev clamav clamav-daemon
RUN apt-get update && apt-get install -y yara libyara-dev
ENV LD_LIBRARY_PATH=/usr/local/lib
RUN ldconfig

# Créer le répertoire temp pour les fichiers téléchargés
RUN mkdir -p /scanner/temp

# Mettre à jour la base de données ClamAV
RUN freshclam
RUN service clamav-daemon start

# Installer cffi et pyclamd pour interagir avec ClamAV en Python
RUN pip install cffi pyclamd

# Copier les fichiers du projet dans l'image
COPY . .

# Installer les dépendances Python
RUN pip install --upgrade pip && pip install -r requirements.txt
RUN wget https://github.com/REMnux/docker.git
# Exposer le port pour Django
EXPOSE 8000

# Lancer le serveur Django
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
