from datetime import datetime
import pytz
from django.utils.timezone import now
from django.http import Http404, HttpResponse, JsonResponse
from django.shortcuts import redirect, render
from django.contrib.auth import logout
import qrcode
from io import BytesIO
from django.views.decorators.csrf import csrf_protect, csrf_exempt
from django.http import HttpResponseBadRequest
import logging
from rest_framework import viewsets, views
from .models import Company, Branch, Staff, TransactionHistory
from .serializers import CompanySerializer, BranchSerializer, StaffSerializer, TransactionHistorySerializer
from django_filters import rest_framework as filters
from rest_framework import status, viewsets
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend
from django.db.models import Q
from rest_framework.permissions import IsAdminUser


logger = logging.getLogger(__name__)

def home(request):
    telegram_id = request.GET.get('telegram_id') or request.POST.get('telegram_id')

    if not telegram_id:
        logger.warning("Missing telegram_id parameter.")
        return HttpResponseBadRequest("Missing telegram_id parameter.")

    try:
        user = Staff.objects.get(staff_telegram_id=telegram_id)
        if user.staff_user_pin:
            return render(request, "app/index.html")
        else:
            return render(request, "app/create-pin.html")
    except Staff.DoesNotExist:
        return render(request, "app/create-pin.html")

@csrf_exempt
def create_pin(request):
    error_message = None
    if request.method == 'POST':

        telegram_id = request.POST.get('telegram_id')
        username = request.POST.get('telegram_username')
        user_pin = request.POST.get('create-pin')
        if not user_pin:
            error_message = "Please input PIN"
        
        elif user_pin:
            lengthPin = len(user_pin)

            if lengthPin < 4:
                error_message = "PIN must be at least 4 digits"
            
            elif lengthPin > 8:
                error_message = "PIN can be a maximum of 8 digits"
            
            elif not username or not telegram_id:
                error_message = "Please use in Telegram Bot"

        if username and not error_message:
            Staff.objects.filter(staff_telegram_username=username).update(
                staff_user_pin=user_pin,
                staff_telegram_id=telegram_id
            )
            return render(request, "app/index.html")
    return render(request, 'app/create-pin.html',  {'error_message': error_message})

def khr_transaction_page(request):
    if not request.session.get('authenticated'):
        return redirect('index') 
    return render(request, "app/khr-transaction.html")

def change_usd_transaction(request):
    if not request.session.get('authenticated'):
        return redirect('index')
    return render(request, "app/usd-transaction.html")

def confirm_transaction(request):
    if not request.session.get('authenticated'):
        return redirect('index')

    currency = request.GET.get('currency')
    amount = request.GET.get('amount')

    server_time = now()
    return render(request, 'app/confirm-transaction.html', {
        'currency': currency,
        'amount': amount,
        'server_time': server_time,
    })

def usd_transaction_page(request):
    error_message = None

    if request.method == 'POST':
        telegram_username = request.POST.get('telegram_username')
        telegram_id = request.POST.get('telegram_id')
        pin = request.POST.get('pin')

        if not pin:
            error_message = "Please input PIN"
        
        elif not telegram_username or not telegram_id:
            error_message = "Please use in Telegram Bot"

        else:
            try:
                telegram_id = int(telegram_id)

                user = Staff.objects.get(
                    staff_telegram_id=telegram_id,
                    staff_telegram_username=telegram_username,
                    staff_user_pin=pin
                )

                request.session['authenticated'] = True
                request.session['staff_id'] = user.staff_id
                return redirect('change_usd_transaction')

            except ValueError:
                error_message = "Invalid data format. Please try again."
            except Staff.DoesNotExist:
                error_message = "Invalid PIN."

    return render(request, 'app/index.html', {'error_message': error_message})

def qr_generate(request, method, amount, currency):
    qr_data = f'Comming soon>>@{method}>>Payment Gateway>>{currency} {amount}'
    qr = qrcode.make(qr_data)

    qr_image = BytesIO()
    qr.save(qr_image)
    qr_image.seek(0)

    response = HttpResponse(qr_image, content_type='image/png')
    return response

@csrf_protect
def qr_generate_page(request, method, amount, currency):
    if request.method == 'POST':
        telegram_id = request.POST.get('telegram_id')
        username = request.POST.get('telegram_username')
        branch_ids = 1


        if not telegram_id or not username:
            return HttpResponse("Telegram ID or Username is missing", status=400)
        
        try:
            company = Company.objects.get(com_id=1)
            branch = Branch.objects.filter(id=branch_ids).first()

            staff = Staff.objects.filter(staff_telegram_id=telegram_id).first()

            if not branch:
                return HttpResponse("Branch not found", status=400)

            # Create the transaction record
            transaction_id = str(datetime.now().strftime("%Y%m%d%H%M%S"))

            new_transaction = TransactionHistory.objects.create(
                th_id=transaction_id,
                th_telegram_id=telegram_id,
                th_datetime=datetime.now().strftime("%Y%m%d%H%M%S"),
                th_amount=amount,
                th_currency=currency,
                th_payment_type=method,
                com_id=company,
                br_id=branch,
                staff_id=staff,
            )

            print("Transaction successfully saved!")
            print(f"Saved Transaction ID: {new_transaction.th_id}")

        except Company.DoesNotExist:
            return HttpResponse("Company not found", status=400)
        except Staff.DoesNotExist:
            print("No matching staff found for this Telegram ID, but continuing with the transaction.")
            new_transaction = TransactionHistory.objects.create(
                th_id=transaction_id,
                th_telegram_id=telegram_id,
                th_datetime=datetime.now().strftime("%Y%m%d%H%M%S"),
                th_amount=amount,
                th_currency=currency,
                th_payment_type=method,
                com_id=company,
                br_id=branch,
                staff_id=staff, 
            )

            print("Transaction saved without staff info.")
        except Exception as e:
            print(f"Error saving transaction: {e}")
            return HttpResponse(f"Error saving transaction: {e}", status=500)

        # Render the QR code page with transaction details
        return render(request, 'app/qr-generate.html', {
            'method': method,
            'amount': amount,
            'currency': currency,
        })

    # If GET request, simply render the page with the method, amount, and currency
    return render(request, 'app/qr-generate.html', {
        'method': method,
        'amount': amount,
        'currency': currency,
    })

def transaction_history(request):
    if request.method == "GET":
        telegram_id = request.GET.get("telegram_id")
        
        if telegram_id:
            try:
                history = TransactionHistory.objects.filter(th_telegram_id=telegram_id).order_by('-th_datetime')
                cambodia_timezone = pytz.timezone('Asia/Phnom_Penh')

                formatted_history = []
                for record in history:
                    cambodia_time = record.th_datetime.astimezone(cambodia_timezone)
                    formatted_history.append({
                        'th_datetime': cambodia_time.strftime('%b. %d, %Y, %H:%M'),
                        'th_id': record.th_id,
                        'th_amount':record.th_amount,
                        'th_currency':record.th_currency,
                        'th_payment_type':record.th_payment_type,
                    })
                return render(request, 'app/transaction-history.html', {'history': formatted_history})
            except TransactionHistory.DoesNotExist:
                return render(request, 'app/transaction-history.html', {'error': 'No transaction history found.'})
        else:
            return render(request, 'app/transaction-history.html', {'error': 'Telegram ID is required.'})

def logout_view(request):
    if request.method == 'POST':
            
        logout(request)
        request.session.flush()
        return render(request,'app/index.html')

class CompanyFilter(filters.FilterSet):
    com_id = filters.NumberFilter(field_name='com_id', lookup_expr='exact')
    com_name = filters.CharFilter(field_name='com_name', lookup_expr='icontains')
    com_email = filters.CharFilter(field_name='com_email', lookup_expr='icontains')
    com_contact = filters.CharFilter(field_name='com_contact', lookup_expr='icontains')
    com_status = filters.BooleanFilter(field_name='com_status', lookup_expr='exact')

    class Meta:
        model = Company
        fields = ['com_id', 'com_name', 'com_email', 'com_contact', 'com_status']

class CompanyViewSet(viewsets.ModelViewSet):
    queryset = Company.objects.all()
    serializer_class = CompanySerializer
    filter_backends = [DjangoFilterBackend]
    filterset_class = CompanyFilter
    lookup_field = 'com_name'

    def get_permissions(self):
        self.permission_classes = [IsAdminUser]
        return super().get_permissions()
            
    def list(self, request, *args, **kwargs):
        """
        Get a list of companies.

        Query Parameters:
        - `com_id` (int): Filter by company ID.
        - `com_name` (str): Filter by partial or full company name.
        - `com_email` (str): Filter by partial or full email.
        - `com_contact` (str): Filter by partial or full contact info.
        - `com_status` (bool): Filter by true/false that mean active or inactive status.
        - `https://ezzecore1.mobi:444/api/companies/`:This is example of how to fetch all companies.
        - `https://ezzecore1.mobi:444/api/companies/?com_name=Company`:This is an example of how to fetch a specific company.

        Returns:
        - `200 OK`: A list of companies.
        - `400 Bad Request`: If a query parameter is invalid.
        - `404 Not Found`: If no companies match the query.
        """
        try:

            for param, value in request.query_params.items():
                if not value.strip():
                    return Response({
                        "success": False,
                        "code": 400,
                        "message": f"Invalid parameter"
                    }, status=status.HTTP_400_BAD_REQUEST)

            queryset = self.filter_queryset(self.get_queryset())

            if request.query_params and not queryset.exists():
                return Response({
                    "success": False,
                    "code": 404,
                    "message": "Company not found",
                    "data": []
                }, status=status.HTTP_404_NOT_FOUND)

            serializer = self.get_serializer(queryset, many=True)
            return Response({
                "success": True,
                "code": 200,
                "message": "Company list fetched successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "success": False,
                "code": 500,
                "message": "An error occurred while fetching company list",
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def create(self, request, *args, **kwargs):
        """
        Create a company.

        Query Parameters:
        - `com_name`: Name of the company.
        - `com_email`: Email of the company.
        - `com_contact`: Contact number of the company.
        - `com_status`: Boolean (true/false or 1/0).
        - `telegram_id`: Telegram ID of the company owner.
        - `telegram_username`: Telegram username of the company owner.
        - `com_password`: Password of the company.
        - `https://ezzecore1.mobi:444/api/companies/`:This is an example of how to create a company.
        """
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "success": True,
                "code": 201,
                "message": "Company created successfully",
                "data": serializer.data
            }, status=status.HTTP_201_CREATED)
        return Response({
            "success": False,
            "code": 400,
            "message": "Invalid data provided",
            "errors": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, *args, **kwargs):  

        com_name = request.query_params.get('com_name', None)
        com_id = request.query_params.get('com_id', None)

        if not com_id and not com_name:
            return Response({
                "success": False,
                "code": 400,
                "message": "No params provided"
            }, status=status.HTTP_400_BAD_REQUEST)

        company = Company.objects.filter(Q(com_id=com_id) | Q(com_name=com_name)).first()
        if not company:
            return Response({
                "success": False,
                "code": 404,
                "message": "Company not found"
            }, status=status.HTTP_404_NOT_FOUND)

        for attr, value in request.data.items():
            setattr(company, attr, value)

        company.save()
        return Response({
            "success": True,
            "code": 200,
            "message": "Company updated successfully"
        },status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        """
        Update the company.

        Query Parameters:
        - `com_id`:ID of company to update.
        - `com_name`:You can also update by using the name of company.
        - `https://ezzecore1.mobi:444/api/companeis/?com_id`: Here is the example.
        
        """
        com_name = request.query_params.get('com_name', None)
        com_id = request.query_params.get('com_id', None)

        if not com_id and not com_name:
            return Response({
                "success": False,
                "code": 400,
                "message": "No params provided"
            }, status=status.HTTP_400_BAD_REQUEST)

        company = Company.objects.filter(Q(com_id=com_id) | Q(com_name=com_name)).first()
        if not company:
            return Response({
                "success": False,
                "code": 404,
                "message": "Company not found"
            }, status=status.HTTP_404_NOT_FOUND)

        serializer = CompanySerializer(company, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "success": True,
                "code": 200,
                "message": "Company updated successfully"
            },status=status.HTTP_200_OK)
        
        return Response({
            "success": False,
            "code": 400,
            "message": "Invalid data provided",
        },status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, *args, **kwargs):
        com_name = request.query_params.get('com_name')

        if not com_name:
            return Response({
                "success": False,
                "code": 400,
                "message": "No param provided"
            }, status=status.HTTP_400_BAD_REQUEST)

        company = Company.objects.filter(com_name=com_name).first()
        if not company:
            return Response({
                "success": False,
                "code": 404,
                "message": "Company not found"
            }, status=status.HTTP_404_NOT_FOUND)
        
        company.delete()
        return Response({
            "success": True,
            "code": 200,
            "message": "Company deleted successfully"
        },status=status.HTTP_200_OK)

class BranchFilter(filters.FilterSet):
    com_id = filters.NumberFilter(field_name='com_id', lookup_expr='exact')
    br_id = filters.NumberFilter(field_name='id', lookup_expr='exact')
    br_kh_name = filters.CharFilter(field_name='br_kh_name', lookup_expr='icontains')
    br_en_name = filters.CharFilter(field_name='br_en_name', lookup_expr='icontains')
    br_email = filters.CharFilter(field_name='br_email', lookup_expr='icontains')
    br_contact = filters.CharFilter(field_name='br_contact', lookup_expr='icontains')
    br_status = filters.BooleanFilter(field_name='br_status', lookup_expr='exact')

    class Meta:
        model = Branch
        fields = ['com_id', 'br_id', 'br_kh_name', 'br_en_name', 'br_email', 'br_contact', 'br_status']

class BranchViewSet(viewsets.ModelViewSet):
    queryset = Branch.objects.all()
    serializer_class = BranchSerializer
    filter_backends = [DjangoFilterBackend]
    filterset_class = BranchFilter

    def get_permissions(self):
        self.permission_classes = [IsAdminUser]
        return super().get_permissions()

    def list(self, request, *args, **kwargs):
        
        try:

            for param, value in request.query_params.items():
                if not value.strip():
                    return Response({
                        "success": False,
                        "code": 400,
                        "message": f"Invalid parameter"
                    }, status=status.HTTP_400_BAD_REQUEST)

            queryset = self.filter_queryset(self.get_queryset())

            if request.query_params and not queryset.exists():
                return Response({
                    "success": False,
                    "code": 404,
                    "message": "Branch not found",
                    "data": []
                }, status=status.HTTP_404_NOT_FOUND)

            serializer = self.get_serializer(queryset, many=True)
            return Response({
                "success": True,
                "code": 200,
                "message": "Branch fetched successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "success": False,
                "code": 500,
                "message": "An error occurred while fetching branch data",
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "success": True,
                "code": 201,
                "message": "Branch created successfully",
                "data": serializer.data
            }, status=status.HTTP_201_CREATED)
        return Response({
            "success": False,
            "code": 400,
            "message": "Invalid data provided",
            "data": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, *args, **kwargs):
        branch_en_name = request.query_params.get('br_en_name', None)
        br_id = request.query_params.get('br_id', None)

        if not br_id and not branch_en_name:
            return Response({
                "success": False,
                "code": 400,
                "message": "No params provided"
            }, status=status.HTTP_400_BAD_REQUEST)

        branch = Branch.objects.filter(Q(id=br_id) | Q(br_en_name=branch_en_name)).first()
        if not branch:
            return Response({
                "success": False,
                "code": 404,
                "message": "Branch not found"
            }, status=status.HTTP_404_NOT_FOUND)

        serializer = BranchSerializer(branch, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "success": True,
                "code": 200,
                "message": "Branch updated successfully"
            },status=status.HTTP_200_OK)
        
        return Response({
                "success": False,
                "code": 400,
                "message": "Invalid data provided",
                "data": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, *args, **kwargs):
        branch_en_name = request.query_params.get('br_en_name', None)
        br_id = request.query_params.get('br_id', None)

        if not br_id and not branch_en_name:
            return Response({
                "success": False,
                "code": 400,
                "message": "No params provided"
            }, status=status.HTTP_400_BAD_REQUEST)

        branch = Branch.objects.filter(Q(id=br_id) | Q(br_en_name=branch_en_name)).first()
        if not branch:
            return Response({
                "success": False,
                "code": 404,
                "message": "Branch not found"
            }, status=status.HTTP_404_NOT_FOUND)

        for attr, value in request.data.items():
            setattr(branch, attr, value)

        branch.save()

        return Response({
            "success": True,
            "code": 200,
            "message": "Branch updated successfully"
        },status=status.HTTP_200_OK)
    
    def delete(self, request, *args, **kwargs):
        branch_en_name = request.query_params.get('br_en_name')
        br_id = request.query_params.get('br_id')

        if not branch_en_name:
            return Response({
                "success": False,
                "code": 400,
                "message": "No branch name provided"
            }, status=status.HTTP_400_BAD_REQUEST)

        branch = Branch.objects.filter(Q(br_en_name=branch_en_name) or Q(br_id=br_id)).first()
        if not branch:
            return Response({
                "success": False,
                "code": 404,
                "message": "Branch not found"
            }, status=status.HTTP_404_NOT_FOUND)
        
        branch.delete()
        return Response({
            "success": True,
            "code": 200,
            "message": "Branch deleted successfully"
        },status=status.HTTP_200_OK)
 
        
class StaffFilter(filters.FilterSet):
    com_id = filters.NumberFilter(field_name='com_id', lookup_expr='exact')
    br_id = filters.NumberFilter(field_name='br_id', lookup_expr='exact')
    staff_id = filters.NumberFilter(field_name='staff_id', lookup_expr='exact')
    staff_name = filters.CharFilter(field_name='staff_name', lookup_expr='icontains')
    staff_telegram_username = filters.CharFilter(field_name='staff_telegram_username', lookup_expr='icontains')
    class Meta:
        model = Staff
        fields = ['com_id', 'br_id', 'staff_id', 'staff_name', 'staff_telegram_username']

class StaffViewSet(viewsets.ModelViewSet):
    queryset = Staff.objects.all()
    serializer_class = StaffSerializer
    filter_backends = [DjangoFilterBackend]
    filterset_class = StaffFilter
    lookup_field = 'staff_id'

    def get_permissions(self):
        self.permission_classes = [IsAdminUser]
        return super().get_permissions()

    def list(self, request, *args, **kwargs):
        try:

            for param, value in request.query_params.items():
                if not value.strip():
                    return Response({
                        "success": False,
                        "code": 400,
                        "message": f"Invalid parameter"
                    }, status=status.HTTP_400_BAD_REQUEST)

            queryset = self.filter_queryset(self.get_queryset())

            if request.query_params and not queryset.exists():
                return Response({
                    "success": False,
                    "code": 404,
                    "message": "Staff not found",
                    "data": []
                }, status=status.HTTP_404_NOT_FOUND)

            serializer = self.get_serializer(queryset, many=True)
            return Response({
                "success": True,
                "code": 200,
                "message": "Staff fetched successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "success": False,
                "code": 500,
                "message": "An error occurred while fetching staff data",
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "success": True,
                "code": 201,
                "message": "Staff created successfully",
                "data": serializer.data
            }, status=status.HTTP_201_CREATED)
        return Response({
            "success": False,
            "code": 400,
            "message": "Invalid data provided",
            "data": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, *args, **kwargs):
        staff_name = request.query_params.get('staff_name', None)
        staff_id = request.query_params.get('staff_id', None)

        if not staff_id and not staff_name:  
            return Response({
                "success": False,
                "code": 400,
                "message": "No params provided"
            }, status=status.HTTP_400_BAD_REQUEST)
        
        staff = Staff.objects.filter(Q(staff_id=staff_id) | Q(staff_name=staff_name)).first()

        if not staff:
            return Response({
                "success": False,
                "code": 404,
                "message": "Staff not found"
            }, status=status.HTTP_404_NOT_FOUND)

        for attr, value in request.data.items():
            setattr(staff, attr, value)

        staff.save()

        return Response({
            "success": True,
            "code": 200,
            "message": "Staff updated successfully"
        },status=status.HTTP_200_OK)

    def patch(self, request, *args, **kwargs):
        staff_name = request.query_params.get('staff_name', None)
        staff_id = request.query_params.get('staff_id', None)

        if not staff_id and not staff_name:
            return Response({
                "success": False,
                "code": 400,
                "message": "No params provided"
            }, status=status.HTTP_400_BAD_REQUEST)

        staff = Staff.objects.filter(Q(staff_id=staff_id) | Q(staff_name=staff_name)).first()
        if not staff:
            return Response({
                "success": False,
                "code": 404,
                "message": "Staff not found"
            }, status=status.HTTP_404_NOT_FOUND)

        for attr, value in request.data.items():
            setattr(staff, attr, value)

        staff.save()

        return Response({
            "success": True,
            "code": 200,
            "message": "Staff updated successfully"
        },status=status.HTTP_200_OK)
    
    def delete(self, request, *args, **kwargs):
        staff_name = request.query_params.get('staff_name')
        staff_id = request.query_params.get('staff_id')

        if not staff_name and not staff_id:
            return Response({
                "success": False,
                "code": 400,
                "message": "No params provided"
            }, status=status.HTTP_400_BAD_REQUEST)
        
        staff = Staff.objects.filter(Q(staff_name=staff_name) | Q(staff_id=staff_id)).first()

        if not staff:
            return Response({
                "success": False,
                "code": 404,
                "message": "Staff not found"
            }, status=status.HTTP_404_NOT_FOUND)

        staff.delete()
        return Response({
            "success":True,
            "code":200,
            "message":"Staff deleted successfully"
        },status=status.HTTP_200_OK)

class AssignBranchesViewSet(viewsets.ModelViewSet):
    
    queryset = Staff.objects.all()
    serializer_class = StaffSerializer
    filter_backends = [DjangoFilterBackend]
    filterset_class = StaffFilter
    lookup_field = 'staff_id'

    def get_permissions(self):
        self.permission_classes = [IsAdminUser]
        return super().get_permissions()

    def create(self, request, *args, **kwargs):
        return Response({
            "success": False,
            "code": 405,
            "message": "POST method not allowed"
        }, status=status.HTTP_405_METHOD_NOT_ALLOWED)
    
    def patch(self, request, *args, **kwargs):
        return Response({
            "success": False,
            "code": 405,
            "message": "PATCH method not allowed"
        }, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def list(self, request, *args, **kwargs):
        try:

            for param, value in request.query_params.items():
                if not value.strip():
                    return Response({
                        "success": False,
                        "code": 400,
                        "message": f"Invalid parameter"
                    }, status=status.HTTP_400_BAD_REQUEST)

            queryset = self.filter_queryset(self.get_queryset())

            if request.query_params and not queryset.exists():
                return Response({
                    "success": False,
                    "code": 404,
                    "message": "AssignBranches not found",
                    "data": []
                }, status=status.HTTP_404_NOT_FOUND)

            serializer = self.get_serializer(queryset, many=True)
            return Response({
                "success": True,
                "code": 200,
                "message": "AssignBranches fetched successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "success": False,
                "code": 500,
                "message": "An error occurred while fetching AssignBranches data",
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request, *args, **kwargs):
        staff_name = request.data.get('staff_name')
        staff_id = request.data.get('staff_id')
        if not staff_name and not staff_id:
            staff_name = request.query_params.get('staff_name')
            staff_id = request.query_params.get('staff_id')
        
        if not staff_name and not staff_id:
            return Response({
                "success": False,
                "code": 400,
                "message": "No params provided"
            }, status=status.HTTP_400_BAD_REQUEST)

        staff = Staff.objects.filter(Q(staff_name=staff_name) | Q(staff_id=staff_id)).first()

        if not staff:
            return Response({
                "success": False,
                "code": 404,
                "message": "Staff not found"
            }, status=status.HTTP_404_NOT_FOUND)

        branch_ids_str = request.data.get('branch_ids', None)
        if not branch_ids_str:
            return Response({
                "success": False,
                "code": 400,
                "message": "No Branch IDs provided"
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            branch_ids = [int(id_str) for id_str in branch_ids_str.split(',')]
        except ValueError:
            return Response({
                "success": False,
                "code": 400,
                "message": "Invalid branch IDs provided"
            }, status=status.HTTP_400_BAD_REQUEST)

        branches = Branch.objects.filter(id__in=branch_ids)
        if not branches:
            return Response({
                "success": False,
                "code": 404,
                "message": "No valid branches found"
            }, status=status.HTTP_404_NOT_FOUND)

        staff.branches.add(*branches)
        staff.save()

        # Custom response
        response_data = {
            "success": True,
            "code": 200,
            "message": "OK",
            "data": StaffSerializer(staff).data,
        }

        return Response(response_data, status=status.HTTP_200_OK)

    def delete(self, request, *args, **kwargs):
        staff_name = request.query_params.get('staff_name')
        staff_id = request.query_params.get('staff_id')
        branch_ids = request.data.get('branch_ids', [])

        if not staff_name and not staff_id:
            return Response({
                "success": False,
                "code": 400,
                "message": "No params provided"
            }, status=status.HTTP_400_BAD_REQUEST)

        staff = Staff.objects.filter(Q(staff_name=staff_name) | Q(staff_id=staff_id)).first()
        if not staff:
            return Response({
                    "success": False,
                    "code": 404,
                    "message": "Staff not found"
                }, status=status.HTTP_404_NOT_FOUND)

        if not branch_ids:
            return Response({
                "success": False,
                "code": 400,
                "message": "No Branch IDs provided"
            }, status=status.HTTP_400_BAD_REQUEST)

        branches = Branch.objects.filter(id__in=branch_ids)

        if not branches.exists():
            return Response({
                "success": False,
                "code": 404,
                "message": "Branch not found"
            }, status=status.HTTP_404_NOT_FOUND)

        staff.branches.remove(*branches)
        staff.save()

        return Response({
            "success": True,
            "code": 200,
            "message": "Branches removed successfully"
        }, status=status.HTTP_200_OK)

class TransactionHistoryFilter(filters.FilterSet):
    th_id = filters.CharFilter(field_name='th_id', lookup_expr='exact')
    th_telegram_id = filters.NumberFilter(field_name='th_telegram_id', lookup_expr='exact')
    com_id = filters.NumberFilter(field_name='com_id', lookup_expr='exact')
    br_id = filters.NumberFilter(field_name='br_id', lookup_expr='exact')
    staff_id = filters.NumberFilter(field_name='staff_id', lookup_expr='exact')
    th_datetime = filters.DateTimeFilter(field_name='th_datetime', lookup_expr='exact')
    th_amount = filters.NumberFilter(field_name='th_amount', lookup_expr='exact')
    th_currency = filters.CharFilter(field_name='th_currency', lookup_expr='exact')
    th_payment_type = filters.CharFilter(field_name='th_payment_type', lookup_expr='exact')

    class Meta:
        model = TransactionHistory
        fields = ['th_id', 'th_telegram_id', 'com_id', 'br_id', 'staff_id', 'th_datetime', 'th_amount', 'th_currency', 'th_payment_type']

class TransactionHistoryViewSet(viewsets.ModelViewSet):
    queryset = TransactionHistory.objects.all()
    serializer_class = TransactionHistorySerializer
    filter_backends = [DjangoFilterBackend]
    filterset_class = TransactionHistoryFilter
    lookup_field = 'th_id'

    def get_permissions(self):
        self.permission_classes = [IsAdminUser]
        return super().get_permissions()

    def create(self, request, *args, **kwargs):
        data = request.data

        required_fields = ['th_id', 'th_telegram_id', 'th_amount', 'th_currency', 'th_payment_type', 'com_id', 'br_id']
        missing_fields = [field for field in required_fields if field not in data]

        if missing_fields:
            return Response({
                "success": False,
                "code": 400,
                "message": "The following fields are required",
                "missing_fields": missing_fields,
                "data": []
            }, status=status.HTTP_400_BAD_REQUEST)

        serializer = self.get_serializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "success": True,
                "code": 201,
                "message": "Transaction history created successfully.",
                "data": serializer.data
            }, status=status.HTTP_201_CREATED)
        else:
            return Response({
                "success": False,
                "code": 400,
                "message": "Validation error",
                "errors": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        
    def put(self, request, *args, **kwargs):
        return Response({
            "success": False,
            "code": 405,
            "message": "PUT method not allowed"
        })
    
    def patch(self, request, *args, **kwargs):
        return Response({
            "success": False,
            "code": 405,
            "message": "PATCH method not allowed"
        })
    
    def delete(self, request, *args, **kwargs):
        return Response({
            "success": False,
            "code": 405,
            "message": "DELETE method not allowed"})

    def list(self, request, *args, **kwargs):
        try:
            for param, value in request.query_params.items():
                if not value.strip(): 
                    return Response({
                        "success": False,
                        "code": 400,
                        "message": "Invalid parameter"
                    }, status=status.HTTP_400_BAD_REQUEST)

            queryset = self.filter_queryset(self.get_queryset())

            if request.query_params and not queryset.exists():
                return Response({
                    "success": False,
                    "code": 404,
                    "message": "No transactions found matching the provided query parameters",
                    "data": []
                }, status=status.HTTP_404_NOT_FOUND)

            page = self.paginate_queryset(queryset)
            if page is not None:
                serializer = self.get_serializer(page, many=True)
                return self.get_paginated_response({
                    "success": True,
                    "code": 200,
                    "message": "Transaction history fetched successfully.",
                    "data": serializer.data
                })

            serializer = self.get_serializer(queryset, many=True)
            return Response({
                "success": True,
                "code": 200,
                "message": "Transaction history fetched successfully.",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "success": False,
                "code": 500,
                "message": "An error occurred while fetching transaction history",
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
