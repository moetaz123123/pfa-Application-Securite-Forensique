from django.urls import path
from .views import CollectRemoteEvidence, ForensicCaptureAPIView,  analyze_all,analyze_traffic , scan_docker_files,analyze_file ,get_file_hashes,  get_traffic_analysis,get_detailed_report ,add_file_hash# Importer la nouvelle vue
from django.conf import settings
from django.conf.urls.static import static

from .views import scan_docker_files 


urlpatterns = [
     path('analyze_traffic/', analyze_traffic, name='analyze_traffic'), 
     path('analyze_file/', analyze_file, name='analyze_file'),
     path('get_detailed_report/<str:analysis_id>/', get_detailed_report, name='get_detailed_report'),
     path('add_file_hash/', add_file_hash, name='add_file_hash'),
     path('get_file_hashes/', get_file_hashes, name='get_file_hashes'),
     path('traffic-analysis/', get_traffic_analysis, name='traffic-analysis'),
     path('scan_docker/', scan_docker_files, name='scan_docker_files'),
     path('collect-remote-evidence/', CollectRemoteEvidence.as_view(), name='collect_remote_evidence'),
     path('forensic-capture/', ForensicCaptureAPIView.as_view(), name = 'forensic_capture'),
     path('analyze_all/', analyze_all, name='analyze_all'),
 ]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
