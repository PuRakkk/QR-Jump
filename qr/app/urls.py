from django.urls import path, include
from . import views
from rest_framework.routers import DefaultRouter
from .views import CompanyViewSet, BranchViewSet, StaffViewSet, TransactionHistoryViewSet, AssignBranchesViewSet, StaticPaymentViewSet, BotUsersStorageViewSet
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from .views import fetch_all_users
from django.contrib.auth.decorators import login_required


from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

router = DefaultRouter()
router.register(r'companies', CompanyViewSet)
router.register(r'branches', BranchViewSet)  
router.register(r'staff', StaffViewSet, basename='staff')
router.register(r'transactions', TransactionHistoryViewSet)
router.register(r'assign-branches', AssignBranchesViewSet, basename='assign-branches')
router.register(r'static-payment',StaticPaymentViewSet ,basename='static-payment')
router.register(r'bot-users',BotUsersStorageViewSet, basename='bot-users')

schema_view = get_schema_view(
    openapi.Info(
        title="QRJUMP API Documentation",
        default_version='v1',
        description="QRJUMP API documentation",
    ),
    public=True,
    permission_classes=[],
)

urlpatterns = [
    path('', views.home, name='home'),
    path('check_login/', views.check_login, name='check_login'),
    path('success-pin/',views.success_pin, name='success-pin'),
    path('select-branchs/', login_required(views.select_branchs), name='select_branchs'),
    path('usd-transaction/', login_required(views.usd_transaction_page), name='usd_transaction_page'),
    path('storing-credentials/', login_required(views.storing_credentials), name='storing_credentials'),
    path('khr-transaction/', login_required(views.khr_transaction_page), name='khr_transaction_page'),
    path('confirm-transaction/', login_required(views.confirm_transaction), name='confirm_transaction_page'),
    path('aba-qr-generate/<str:method>/<str:amount>/<str:currency>/', login_required(views.aba_qr_generate), name='aba_qr_generate'),
    path('payment_callback/', views.payment_callback, name='payment_callback'),
    path('payment_success/', views.payment_success, name='payment_success'),
    path('qr-generate/<str:method>/<str:amount>/<str:currency>/', login_required(views.qr_generate_page), name='qr_generate_page'),
    path('generate_qr/<str:method>/<str:amount>/<str:currency>/', login_required(views.qr_generate), name='generate_qr'),
    path('transaction-history/', login_required(views.transaction_history), name='transaction-history'),
    path('logout/', views.logout_user, name='logout_user'),
    path('api/v1/', include(router.urls)),
    path('api/v1/get-users/', fetch_all_users, name='fetch_all_users'),
    path('api/v1/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/v1/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/v1/check_token_status/', views.check_token_status, name='check_token_status'),
    path('update-session/', views.update_session, name='update_session'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
    ]

