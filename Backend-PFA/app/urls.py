from django.urls import path
from .views import CollectRemoteEvidence , ForensicCaptureAPIView , analyze_traffic , analyze_file , get_detailed_report
from django.conf import settings
from django.conf.urls.static import static


urlpatterns = [
    path('collect-remote-evidence/', CollectRemoteEvidence.as_view(), name='collect_remote_evidence'),
    path('forensic-capture/', ForensicCaptureAPIView.as_view(), name = 'forensic_capture'),
    path('analyze_traffic/', analyze_traffic, name='analyze_traffic'), 
    path('analyze_file/', analyze_file, name='analyze_file'),
    path('get_detailed_report/<str:analysis_id>/', get_detailed_report, name='get_detailed_report'),

]
