# Victime/admin.py

from django.contrib import admin
from .models import FileHash, TrafficAnalysis

admin.site.register(FileHash)
from django.contrib import admin
from .models import FileAnalysis

admin.site.register(FileAnalysis)
admin.site.register(TrafficAnalysis)