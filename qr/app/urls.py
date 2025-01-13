from django.urls import path, include
from . import views
from rest_framework.routers import DefaultRouter
from .views import CompanyViewSet, BranchViewSet, StaffViewSet, TransactionHistoryViewSet, AssignBranchesViewSet
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

router = DefaultRouter()
router.register('companies', CompanyViewSet)
router.register('branches', BranchViewSet)  
router.register(r'staff', StaffViewSet, basename='staff')
router.register('transactions', TransactionHistoryViewSet)
router.register(r'assign-branches', AssignBranchesViewSet, basename='assign-branches')

schema_view = get_schema_view(
    openapi.Info(
        title="QRJUMP API Documentation",
        default_version='v1',
        description="QRJUMP API documentation",
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    path('', views.home, name='index'),
    path('usd-transaction/', views.usd_transaction_page, name='usd_transaction_page'),
    path('change-usd-transaction/', views.change_usd_transaction, name='change_usd_transaction'),
    path('khr-transaction/', views.khr_transaction_page, name='khr_transaction_page'),
    path('confirm-transaction/', views.confirm_transaction, name='confirm_transaction_page'),
    path('qr-generate/<str:method>/<str:amount>/<str:currency>/', views.qr_generate_page, name='qr_generate_page'),
    path('generate_qr/<str:method>/<str:amount>/<str:currency>/', views.qr_generate, name='generate_qr'),
    path('transaction-history/', views.transaction_history, name='transaction-history'),
    path('create-pin/', views.create_pin, name='create-pin'),
    path('logout/', views.logout_view, name='logout'),
    path('api/', include(router.urls)),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
]

