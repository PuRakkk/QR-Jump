from datetime import datetime, timezone
import pytz
from django.utils.timezone import now
from django.http import HttpResponse
from django.shortcuts import redirect, render
import qrcode
from io import BytesIO
from django.views.decorators.csrf import csrf_protect
import logging
from rest_framework import viewsets
from .models import Company, Branch, Staff, TransactionHistory, StaticPayment, BotUsersStorage, BankCredentials
from .serializers import CompanySerializer, BranchSerializer, StaffSerializer, TransactionHistorySerializer, StaticPaymentSerializer, BotUsersStorageSerializer, BankCredentialsSerializer
from django_filters import rest_framework as filters
from rest_framework import status, viewsets
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend
from django.db.models import Q
from rest_framework.permissions import IsAdminUser,IsAuthenticated
from rest_framework.decorators import api_view, permission_classes
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import Permission
import requests
import hashlib
import base64
import time
import jwt
from django.http import JsonResponse
from django.contrib.auth import login
from django.contrib.auth.models import User
import hmac

logger = logging.getLogger(__name__)

TELEGRAM_BOT_TOKEN = "7301149253:AAFN0bx9UjNYrHNHvcqaB3PeNaxnUeySzA8"

#TestingGit

def send_telegram_message(chat_id, message, parse_mode):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": chat_id, "text": message, "parse_mode": "HTML"}
    response = requests.post(url, json=payload)
    return response.json()

def check_login(request):
    error_message = None
    if request.method == 'POST':
        telegram_username = request.POST.get('telegram_username')
        telegram_id = request.POST.get('telegram_id')
        pin = request.POST.get('pin')

        if not pin:
            error_message = "Please input PIN"
        elif len(pin) < 4:
            error_message = "PIN must be at least 4 characters long"
        elif not telegram_username or not telegram_id:
            error_message = "Please use Telegram Bot"

        else:
            try:
                user_pin = request.POST.get('pin')
                user_pass = user_pin

                hashed_pass = hashlib.sha256(user_pass.encode('utf-8')).hexdigest()
                password = base64.b64encode(hashed_pass.encode('utf-8')).decode('utf-8')

                api = "http://127.0.0.1:8000/api/v1/token/"

                data = {
                    'username':telegram_username,
                    'password':password
                }

                response = requests.post(api, data=data)

                if response.status_code == 200:
                    access_token = response.json().get('access')
                    refresh_token = response.json().get('refresh')

                    request.session['access_token'] = access_token
                    request.session['refresh_token'] = refresh_token
                    request.session.save()
                    try:
                        api = f"http://127.0.0.1:8000/api/v1/staff/?staff_telegram_username={telegram_username}"

                        data = {
                            'staff_telegram_id': telegram_id,}
                         
                        headers = {
                             'Authorization': f'Bearer {access_token}',
                             'Content-Type': 'application/json'
                         }
                        
                        response = requests.put(api, json=data,headers=headers)
                    except requests.exceptions.RequestException as e:
                        error_message = f"Error fetching staff information: {str(e)}"

                    try:
                        api = f"http://127.0.0.1:8000/api/v1/staff/?staff_telegram_username={telegram_username}"
                         
                        headers = {
                             'Authorization': f'Bearer {access_token}',
                             'Content-Type': 'application/json'
                         }
                        
                        response = requests.get(api, headers=headers)

                        if response.status_code == 200:
                            data = response.json()
                            if 'data' in data and data['data']:
                                staff_user_pin = data['data'][0]['staff_user_pin']
                                staff_status = data['data'][0]['staff_status']
                                if staff_user_pin == user_pin and staff_status is True:
                                    user, created = User.objects.get_or_create(username=telegram_username)
                                    login(request, user)
                                    return redirect(f'/select-branchs/?telegram_username={telegram_username}&staff_user_pin={staff_user_pin}') 
                                elif not staff_user_pin and staff_status is True:
                                    return render(request, 'app/setup-pin.html')
                        else:
                            error_message = "Your account is inactive. Please contact admin"
                    except requests.exceptions.RequestException as e:
                        error_message = f"Error fetching staff information: {str(e)}"
                else:
                    error_message = "Invalid PIN or not yet registered"

            except Exception as e:
                print(f"Error: {str(e)}")

    return render(request, 'app/index.html', {'error_message': error_message})

def success_pin(request):
    error_message = None
    if request.method == 'POST':
        telegram_username = request.POST.get('telegram_username')
        telegram_id = request.POST.get('telegram_id')
        pin = request.POST.get('pin')

        if not pin:
            error_message = "Please input PIN"
        elif len(pin) < 4:
            error_message = "PIN must be at least 4 characters long"
        elif not telegram_username or not telegram_id:
            error_message = "Please use Telegram Bot"
        else:
            try:
                access_token = request.session.get('access_token')
                api = f"http://127.0.0.1:8000/api/v1/staff/?staff_telegram_id={telegram_id}"

                headers = {
                    'Authorization': f'Bearer {access_token}',
                    'Content-Type': 'application/json'
                }
                
                data = {
                    'staff_user_pin':pin
                }

                response = requests.put(api, json=data ,headers=headers)
                
                if response.status_code == 200:
                    data = response.json()
                    return render(request, 'app/success-pin.html')

            except requests.exceptions.RequestException as e:                
                error_message = f"Connection Error"
    return render(request, 'app/setup-pin.html', {'error_message': error_message})

def select_branchs(request):
    telegram_username = request.GET.get('telegram_username')
    refresh_token = request.session.get('refresh_token')
    access_token = request.session.get('access_token')

    if not refresh_token:
        return redirect('/')

    try:
        api = f"http://127.0.0.1:8000/api/v1/staff/?staff_telegram_username={telegram_username}"
        headers = {'Authorization': f'Bearer {access_token}'}
        response = requests.get(api, headers=headers)

        if response.status_code == 200:
            data = response.json()
            if 'data' in data and data['data']:
                branches = data['data'][0].get('branches', [])
                staff_id = data['data'][0]['staff_id']

                if branches:
                    com_id = branches[0].get('com_id', None)
                    branch_id = branches[0]['id']
                    br_en_name = branches[0]['br_en_name']
                    bank_credentials = {}
                    payment_types = {}
                    
                    for item in branches[0]['bank_credentials'] + branches[0]['payment_types']:
                        if isinstance(item, dict):
                            if 'bank_name' in item:
                                bank_name = item['bank_name'].lower()
                                bank_credentials[bank_name] = {
                                    'api_key': item['api_key'],
                                    'public_key': item['public_key'],
                                    'merchant_id': item['merchant_id']
                                }
                        elif isinstance(item, str):
                            payment_name = item.lower()
                            payment_types[payment_name] = payment_name
                                            
                if len(branches) == 1:
                    request.session['staff_id'] = staff_id
                    request.session['com_id'] = com_id
                    request.session['branch_id'] = branch_id
                    request.session['br_en_name'] = br_en_name
                    request.session['bank_credentials'] = bank_credentials
                    request.session['payment_types'] = payment_types
                    context = {
                        'br_en_name':br_en_name
                    }
                    return render(request, 'app/usd-transaction.html', context=context)
                
                elif len(branches) > 1:
                    return render(request, 'app/select-branchs.html', {
                        'branches': branches,
                        'br_en_name':br_en_name,
                        'staff_id': staff_id,
                        'com_id': com_id,
                        'telegram_username': telegram_username,
                        'bank_credentials': bank_credentials,
                        'payment_types': payment_types
                    })
                
                else:
                    return HttpResponse("Branch not found", status=400)
            else:
                return redirect('/')
        else:
            return HttpResponse(f"Error fetching staff information: {response.status_code}", status=400)

    except requests.exceptions.RequestException as e:
        return HttpResponse(f"Error fetching staff information: {str(e)}", status=500)

def storing_credentials(request):
    refresh_token = request.session.get('refresh_token')
    access_token = request.session.get('access_token')
    staff_id = request.GET.get('staff_id')
    com_id = request.GET.get('com_id')
    telegram_username = request.GET.get('telegram_username')
    branch_id = request.GET.get('branch_id')
    br_en_name = request.GET.get('br_en_name')
    payment_type = request.GET.get('payment_types')
    print("This is Payment Type:",payment_type)

    bank_credentials = {}
    payment_types = {}
    try:
        api = f"http://127.0.0.1:8000/api/v1/staff/?branches={branch_id}"
        headers = {'Authorization': f'Bearer {access_token}'}
        response = requests.get(api, headers=headers)

        if response.status_code == 200:
            data = response.json()
            if 'data' in data and data['data']:
                branches = data['data'][0].get('branches', [])
                staff_id = data['data'][0]['staff_id']

                if branches:
                    com_id = branches[0].get('com_id', None)
                    branch_id = branches[0]['id']
                    # bank_credentials_list = branches[0].get('bank_credentials', [])
                    # payment_types_list = branches[0].get('payment_types', [])
                    
                    for item in branches[0]['bank_credentials'] + branches[0]['payment_types']:
                        if isinstance(item, dict):
                            if 'bank_name' in item:
                                bank_name = item['bank_name'].lower()
                                bank_credentials[bank_name] = {
                                    'api_key': item['api_key'],
                                    'public_key': item['public_key'],
                                    'merchant_id': item['merchant_id']
                                }
                        elif isinstance(item, str):
                            payment_name = item.lower()
                            payment_types[payment_name] = payment_name

    except Branch.DoesNotExist:
        return redirect('/')

    api = "http://127.0.0.1:8000/api/v1/token/refresh/"
    data = {'refresh': refresh_token}

    try:
        response = requests.post(api, data=data)
        if response.status_code == 200:
            new_access_token = response.json().get('access')
            new_refresh_token = response.json().get('refresh')

            request.session['access_token'] = new_access_token
            request.session['refresh_token'] = new_refresh_token
            request.session.save()
        else:
            return redirect('/')
    except Exception as e:
        print(f"Error refreshing token: {str(e)}")
        return redirect('/')

    if not staff_id or not com_id or not telegram_username or not branch_id:
        return redirect('/')
    else:
        request.session['staff_id'] = staff_id
        request.session['com_id'] = com_id
        request.session['telegram_username'] = telegram_username
        request.session['branch_id'] = branch_id
        request.session['br_en_name'] = br_en_name
        request.session['bank_credentials'] = bank_credentials
        request.session['payment_types'] = payment_types

    return render(request, 'app/usd-transaction.html')

def update_session(request):
    message = None
    access_token = request.session.get('access_token')
    refresh_token = request.session.get('refresh_token')

    if not access_token or not refresh_token:
        return redirect('/')

    try:
        decoded_token = jwt.decode(access_token, options={"verify_signature": False})
        exp_timestamp = decoded_token.get('exp')
        if not exp_timestamp:
            return redirect('/')

        exp_time = datetime.fromtimestamp(exp_timestamp, tz=timezone.utc)
        remaining_time = (exp_time - datetime.now(timezone.utc)).total_seconds()

        if remaining_time > 15:
            return HttpResponse(message)

    except jwt.ExpiredSignatureError:
        pass
    except Exception as e:
        print(f"{str(e)}")
        return redirect('/')

    api = "http://127.0.0.1:8000/api/v1/token/refresh/"
    data = {'refresh': refresh_token}

    try:
        response = requests.post(api, data=data)
        if response.status_code == 200:
            new_access_token = response.json().get('access')
            new_refresh_token = response.json().get('refresh')

            request.session['access_token'] = new_access_token
            request.session['refresh_token'] = new_refresh_token
            request.session.save()
        else:
            return redirect('/')
    except Exception as e:
        print(f"{str(e)}")
        return redirect('/')

    return HttpResponse(message)

def home(request):
    
    return render(request, 'app/index.html')

def khr_transaction_page(request):
    refresh_token = request.session.get('refresh_token')
    br_en_name = request.session.get('br_en_name')
    if not refresh_token:
        return redirect('/')

    api = "http://127.0.0.1:8000/api/v1/token/refresh/"
    data = {'refresh': refresh_token}

    try:
        response = requests.post(api, data=data)
        if response.status_code == 200:
            new_access_token = response.json().get('access')
            new_refresh_token = response.json().get('refresh')

            request.session['access_token'] = new_access_token
            request.session['refresh_token'] = new_refresh_token
            request.session.save()
        else:
            return redirect('/')
    except Exception as e:
        print(f"Error refreshing token: {str(e)}")
        return redirect('/')
    context = {
            'br_en_name':br_en_name
        }

    return render(request, "app/khr-transaction.html", context=context)

def usd_transaction_page(request):
    refresh_token = request.session.get('refresh_token')
    br_en_name = request.session.get('br_en_name')
    if not refresh_token:
        return redirect('/')

    api = "http://127.0.0.1:8000/api/v1/token/refresh/"
    data = {'refresh': refresh_token}

    try:
        response = requests.post(api, data=data)
        if response.status_code == 200:
            new_access_token = response.json().get('access')
            new_refresh_token = response.json().get('refresh')

            request.session['access_token'] = new_access_token
            request.session['refresh_token'] = new_refresh_token
            request.session.save()
        else:
            return redirect('/')
    except Exception as e:
        print(f"Error refreshing token: {str(e)}")
        return redirect('/')
    
    context = {
        'br_en_name':br_en_name
    }

    return render(request, "app/usd-transaction.html", context=context)

def confirm_transaction(request):
    refresh_token = request.session.get('refresh_token')
    bank_credentials = request.session.get('bank_credentials')
    payment_types = request.session.get('payment_types')
    if not refresh_token:
        return redirect('/')

    api = "http://127.0.0.1:8000/api/v1/token/refresh/"
    data = {'refresh': refresh_token}

    try:
        response = requests.post(api, data=data)
        if response.status_code == 200:
            new_access_token = response.json().get('access')
            new_refresh_token = response.json().get('refresh')

            request.session['access_token'] = new_access_token
            request.session['refresh_token'] = new_refresh_token
            request.session.save()
        else:
            return redirect('/')
    except Exception as e:
        print(f"Error refreshing token: {str(e)}")
        return redirect('/')

    currency = request.GET.get('currency')
    amount = request.GET.get('amount')

    server_time = now()
    return render(request, 'app/confirm-transaction.html', {
        'currency': currency,
        'amount': amount,
        'server_time': server_time,
        'bank_credentials': bank_credentials,
        'payment_types':payment_types
    })
    
def check_token_status(request):
    access_token = request.session.get('access_token')
    if not access_token:
        return JsonResponse({"redirect_required": True})

    # try:
    #     api = "http://127.0.0.1:8000/api/v1/staff/"

    #     headers = {
    #         'Authorization': f'Bearer {access_token}'
    #     }
    #     Response = requests.get(api, headers=headers)

    #     if Response.status_code == 403:
    #         return JsonResponse({"redirect_required": True})

    # except Exception as e:
    #     return JsonResponse({"redirect_required": True})

    try:
        payload = jwt.decode(access_token, options={"verify_signature": False}, algorithms=["HS256"])
        expiration_time = payload.get("exp")
        current_time = int(time.time())

        if current_time >= expiration_time:
            return JsonResponse({"redirect_required": True})
        else:
            return JsonResponse({"redirect_required": False})

    except jwt.ExpiredSignatureError:
        return JsonResponse({"redirect_required": True})
    except jwt.DecodeError:
        return JsonResponse({"redirect_required": True})
    except Exception as e:
        print(f"Error in token check: {str(e)}")
        return JsonResponse({"redirect_required": True})

def logout_user(request):
    request.session.flush()
    return redirect('/')

@api_view(['GET'])
@permission_classes([IsAuthenticated, IsAdminUser])
def fetch_all_users(request):
    if request.method == 'GET':
        username = request.query_params.get('username', None)
        
        if username:
            users = User.objects.filter(username=username).values('username', 'is_staff')
        else:
            users = User.objects.values('username', 'is_staff')
        
        if not users:
            return Response({'error': 'No users found'}, status=status.HTTP_404_NOT_FOUND)
        
        return Response({
            'users': list(users),
        }, status=status.HTTP_200_OK)
    
def payment_success(request):
    return render(request, 'app/payment-success.html')

def payment_callback(request):
    if request.method == 'POST':
        transaction_id = request.POST.get('tran_id')
        payment_status = request.POST.get('status')
        
        logger.info(f"Transaction ID: {transaction_id}, Status: {payment_status}")

        if payment_status == 00:
            logger.info(f"Transaction {transaction_id} successfully validated.")
        else:
            logger.error(f"Payment failed for transaction {transaction_id}.")

        return JsonResponse({"message": "Payment callback received."})
    return JsonResponse({"error": "Invalid request"}, status=400)

def aba_qr_generate(request, method, amount, currency):
    refresh_token = request.session.get('refresh_token')
    if not refresh_token:
        return redirect('/')

    api = "http://127.0.0.1:8000/api/v1/token/refresh/"
    data = {'refresh': refresh_token}

    try:
        response = requests.post(api, data=data)
        if response.status_code == 200:
            new_access_token = response.json().get('access')
            new_refresh_token = response.json().get('refresh')

            request.session['access_token'] = new_access_token
            request.session['refresh_token'] = new_refresh_token
            request.session.save()
        else:
            return redirect('/')
    except Exception as e:
        print(f"Error refreshing token: {str(e)}")
        return redirect('/')
    utc_now = datetime.now(pytz.utc)
    formatted_time = utc_now.strftime('%Y%m%d%H%M%S')
    success_url = "https://ccfa-167-179-41-221.ngrok-free.app/payment_success/"
    bank_credentials = request.session.get('bank_credentials')
    for bank_name, creds in bank_credentials.items():
        if bank_name == 'aba':
            merchant_id = creds['merchant_id']
            api_key = creds['api_key']
            public_key = creds['public_key']
    
    API_KEY = api_key
    MERCHANT_ID = merchant_id
    PUBLIC_KEY = public_key
    REQ_TIME = formatted_time
    TRAN_ID = formatted_time
    AMOUNT = amount
    CURRENCY = currency
    CONTINUE_SUCCESS_URL = success_url
    PAYMENT_OPTION = 'abapay'
    STR_DATA = f'{REQ_TIME}{MERCHANT_ID}{TRAN_ID}{AMOUNT}{PAYMENT_OPTION}{CONTINUE_SUCCESS_URL}{CURRENCY}'
    HASH = base64.b64encode(hmac.new(PUBLIC_KEY.encode(), STR_DATA.encode(), hashlib.sha512).digest()).decode()

    context = {
        'api_key': API_KEY,
        'req_time': REQ_TIME,
        'merchant_id': MERCHANT_ID,
        'tran_id': TRAN_ID,
        'amount': AMOUNT,
        'payment_option': PAYMENT_OPTION,
        'currency': CURRENCY,
        'continue_success_url': CONTINUE_SUCCESS_URL,
        'hash': HASH,
    }
    return render (request, 'app/aba-qr-generate.html',context=context)

def qr_generate(request, method, amount, currency):
    refresh_token = request.session.get('refresh_token')
    if not refresh_token:
        return redirect('/')

    api = "http://127.0.0.1:8000/api/v1/token/refresh/"
    data = {'refresh': refresh_token}

    try:
        response = requests.post(api, data=data)
        if response.status_code == 200:
            new_access_token = response.json().get('access')
            new_refresh_token = response.json().get('refresh')

            request.session['access_token'] = new_access_token
            request.session['refresh_token'] = new_refresh_token
            request.session.save()
        else:
            return redirect('/')
    except Exception as e:
        print(f"Error refreshing token: {str(e)}")
        return redirect('/')
    
    qr_data = f'Comming soon>>@{method}>>Payment Gateway>>{currency} {amount}'
    qr = qrcode.make(qr_data)

    qr_image = BytesIO()
    qr.save(qr_image)
    qr_image.seek(0)

    response = HttpResponse(qr_image, content_type='image/png')
    return response

@csrf_protect
def qr_generate_page(request, method, amount, currency):
    refresh_token = request.session.get('refresh_token')
    com_id = request.session.get('com_id')
    branch_ids = request.session.get('branch_id')
    staff_id = request.session.get('staff_id')
    if not com_id or not branch_ids or not staff_id or not method or not amount or not currency:
        return redirect('/')
    if not refresh_token:
        return redirect('/')

    api = "http://127.0.0.1:8000/api/v1/token/refresh/"
    data = {'refresh': refresh_token}

    try:
        response = requests.post(api, data=data)
        if response.status_code == 200:
            new_access_token = response.json().get('access')
            new_refresh_token = response.json().get('refresh')

            request.session['access_token'] = new_access_token
            request.session['refresh_token'] = new_refresh_token
            request.session.save()
        else:
            return redirect('/')
    except Exception as e:
        print(f"Error refreshing token: {str(e)}")
        return redirect('/')
    if request.method == 'POST':
        telegram_id = request.POST.get('telegram_id')
        username = request.POST.get('telegram_username')
        access_token = request.session.get('access_token')

        if not telegram_id or not username:
            return HttpResponse("Telegram ID or Username is missing", status=400)
    try:
        if not com_id:
            return HttpResponse("Company not found", status=400)
        elif not branch_ids:
            return HttpResponse("Branch not found", status=400)
        
        try:
            transaction_id = str(datetime.now().strftime("%Y%m%d%H%M%S"))
            transaction_datetime = datetime.now().strftime("%Y%m%d%H%M%S")

            api = ("http://127.0.0.1:8000/api/v1/transactions/")

            data = {
                'th_id': transaction_id,
                'th_telegram_id': telegram_id,
                'th_datetime': transaction_datetime,
                'th_amount': amount,
                'th_currency': currency,
                'th_payment_type': method,
                'com_id': com_id,
                'br_id': branch_ids,
                'staff_id': staff_id,
            }
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            response = requests.post(api, headers=headers, json=data)

            if response.status_code == 201:
                return render(request, 'app/qr-generate.html', {
                        'method': method,
                        'amount': amount,
                        'currency': currency,
                    })
            else:
                return redirect('/')

        except Exception as e:
            return redirect('/')

    except Company.DoesNotExist:
        return HttpResponse("Company not found", status=400)

def transaction_history(request):
    refresh_token = request.session.get('refresh_token')
    if not refresh_token:
        return redirect('/')

    api = "http://127.0.0.1:8000/api/v1/token/refresh/"
    data = {'refresh': refresh_token}

    try:
        response = requests.post(api, data=data)
        if response.status_code == 200:
            new_access_token = response.json().get('access')
            new_refresh_token = response.json().get('refresh')

            request.session['access_token'] = new_access_token
            request.session['refresh_token'] = new_refresh_token
            request.session.save()
        else:
            return redirect('/')
    except Exception as e:
        print(f"Error refreshing token: {str(e)}")
        return redirect('/')
    if request.method == "GET":
        telegram_id = request.GET.get("telegram_id")
        
        if telegram_id:
            try:
                api_url = f"http://127.0.0.1:8000/api/v1/transactions/?th_telegram_id={telegram_id}"
                headers = {
                    'Authorization': f'Bearer {new_access_token}',
                }

                response = requests.get(api_url, headers=headers)

                if response.status_code == 200:
                    response_data = response.json()

                    if 'data' in response_data and isinstance(response_data['data'], list):
                        history = response_data['data']
                        history.sort(key=lambda x: x['th_datetime'], reverse=True)
                        cambodia_timezone = pytz.timezone('Asia/Phnom_Penh')
                        formatted_history = []
                        for record in history:
                            th_datetime = pytz.utc.localize(
                                datetime.strptime(record['th_datetime'], '%Y-%m-%dT%H:%M:%S.%fZ')
                            ).astimezone(cambodia_timezone)
                            
                            formatted_history.append({
                                'th_datetime': th_datetime.strftime('%b. %d, %Y, %H:%M'), 
                                'th_id': record['th_id'],
                                'th_amount': record['th_amount'],
                                'th_currency': record['th_currency'],
                                'th_payment_type': record['th_payment_type'],
                            })

                        return render(request, 'app/transaction-history.html', {'history': formatted_history})
                    else:
                        return render(request, 'app/transaction-history.html', {'error': 'Invalid API response format.'})
                elif response.status_code == 404:
                    return render(request, 'app/transaction-history.html')
                else:
                    return redirect('/')
            except Exception as e:
                return render(request, 'app/transaction-history.html', {'error': f'An error occurred: {str(e)}'})
        else:
            return render(request, 'app/transaction-history.html', {'error': 'Telegram ID is required.'})

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

        username = request.data.get('com_email')
        password = request.data.get('com_password')

        if not username and not password:
            return Response({
                    "success": False,
                    "code": 400,
                    "message": "Staff_telegram_username are required.",
                }, status=status.HTTP_400_BAD_REQUEST)

        if serializer.is_valid():
            hashed_pin = hashlib.sha256(password.encode('utf-8')).hexdigest()
            base64_encoded_pin = base64.b64encode(hashed_pin.encode('utf-8')).decode('utf-8')

            user = User.objects.create_user(
                username=username,
                password=base64_encoded_pin
            )
            user.is_staff = True

            try:
                per = [
                    Permission.objects.get(codename='add_staff'),
                    Permission.objects.get(codename='change_staff'),
                    Permission.objects.get(codename='delete_staff'),
                    Permission.objects.get(codename='view_staff'),
                    Permission.objects.get(codename='view_branch'),
                    Permission.objects.get(codename='add_transactionhistory'),
                    Permission.objects.get(codename='view_transactionhistory'),
                    Permission.objects.get(codename='add_branch'),
                    Permission.objects.get(codename='delete_branch'),
                    Permission.objects.get(codename='change_branch'),
                    Permission.objects.get(codename='view_company'),
                ]
                user.user_permissions.add(*per)
            except Permission.DoesNotExist:
                return Response({
                    'error': 'Permission not found.'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            user.save()

            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)

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
    queryset = Branch.objects.all().prefetch_related('bank_credentials')
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
    staff_telegram_id = filters.CharFilter(field_name='staff_telegram_id',lookup_expr='icontains')
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
    
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            staff_user_pin = "12345"
            staff_telegram_username = serializer.validated_data.get('staff_telegram_username')
            staff_role = serializer.validated_data.get('staff_position')
            branch_ids = request.data.get('branch_ids', [])

            if not staff_telegram_username:
                return Response({
                    "success": False,
                    "code": 400,
                    "message": "Staff_telegram_username are required.",
                }, status=status.HTTP_400_BAD_REQUEST)
            
            if not branch_ids:
                return Response({
                    "success": False,
                    "code": 400,
                    "message": "branch_ids are required.",
                }, status=status.HTTP_400_BAD_REQUEST)

            hashed_pin = hashlib.sha256(staff_user_pin.encode('utf-8')).hexdigest()
            base64_encoded_pin = base64.b64encode(hashed_pin.encode('utf-8')).decode('utf-8')

            user = User.objects.create_user(
                username=staff_telegram_username,
                password=base64_encoded_pin
            )
            user.is_staff = True

            try:
                if staff_role == "staff":
                    per = [
                        Permission.objects.get(codename='view_transactionhistory'),
                        Permission.objects.get(codename='add_transactionhistory'),
                        Permission.objects.get(codename='add_staff'),
                        Permission.objects.get(codename='view_staff'),

                    ]
                    user.user_permissions.add(*per)
                elif staff_role == "manager":
                    per = [
                        Permission.objects.get(codename='add_staff'),
                        Permission.objects.get(codename='change_staff'),
                        Permission.objects.get(codename='delete_staff'),
                        Permission.objects.get(codename='view_staff'),
                        Permission.objects.get(codename='view_branch'),
                        Permission.objects.get(codename='add_transactionhistory'),
                        Permission.objects.get(codename='view_transactionhistory')
                    ]
                    user.user_permissions.add(*per)
                elif staff_role == "admin":
                    per = [
                        Permission.objects.get(codename='add_staff'),
                        Permission.objects.get(codename='change_staff'),
                        Permission.objects.get(codename='delete_staff'),
                        Permission.objects.get(codename='view_staff'),
                        Permission.objects.get(codename='view_branch'),
                        Permission.objects.get(codename='add_transactionhistory'),
                        Permission.objects.get(codename='view_transactionhistory'),
                        Permission.objects.get(codename='add_branch'),
                        Permission.objects.get(codename='delete_branch'),
                        Permission.objects.get(codename='change_branch'),
                        Permission.objects.get(codename='view_company')
                    ]
                    user.user_permissions.add(*per)
            except Permission.DoesNotExist:
                return Response({
                    'error': 'Permission not found.'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            try:
                bot_user = BotUsersStorage.objects.get(username=staff_telegram_username)
                if bot_user.message_id:
                    bot_user.user_status = "Active"
                    bot_user.save()
                    if bot_user.user_choose_language == "English":
                        message = f"Congratulations <strong>{staff_telegram_username}</strong>, you have been approved. You can use QR Jump now."
                    elif bot_user.user_choose_language == "Khmer":
                        message = f"សូមអបអរសាទរ <strong>{staff_telegram_username}</strong> គណនរបស់អ្នកត្រូវបានដាក់អោយដំណើរការ។ អ្នកអាចប្រើ QR Jump ឥឡូវនេះបាន។"
                    elif bot_user.user_choose_language is None:
                        message = f"Congratulations <strong>{staff_telegram_username}</strong>, you have been approved. You can use QR Jump now."
                    send_telegram_message(bot_user.message_id, message, parse_mode='HTML')
            except BotUsersStorage.DoesNotExist:
                return Response({
                    "success": False,
                    "code": 404,
                    "message": "Bot user not found. Cannot send Telegram message."
                }, status=status.HTTP_404_NOT_FOUND)

            user.save()

            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)

            serializer.save(staff_status=True)

            staff = Staff.objects.filter(Q(staff_telegram_username=staff_telegram_username)).first()
            if branch_ids:
                branch_ids = [int(branch_id) for branch_id in branch_ids.split(',')]    
                branches = Branch.objects.filter(id__in=branch_ids) 

                staff.branches.set(branches) 
                staff.save()

            return Response({
                    "success": True,
                    "code": 200,
                    "message": "Staff and branches created successfully",
                    "data": {
                        "staff_id": staff.staff_id,
                        "staff_name": staff.staff_name,
                        "branches": [branch.br_kh_name for branch in branches]
                    }
                }, status=status.HTTP_200_OK)
                
        return Response({
            "success": False,
            "code": 400,
            "message": "Invalid data provided",
            "data": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


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

    def put(self, request, *args, **kwargs):
        staff_name = request.query_params.get('staff_name', None)
        staff_id = request.query_params.get('staff_id', None)
        staff_username = request.query_params.get('staff_telegram_username', None)
        staff_telegram_id = request.query_params.get('staff_telegram_id', None)
        branch_ids = request.data.get('branch_ids', [])


        if not staff_id and not staff_name and not staff_username and not staff_telegram_id:
            return Response({
                "success": False,
                "code": 400,
                "message": "No params provided"
            }, status=status.HTTP_400_BAD_REQUEST)

        staff = Staff.objects.filter(Q(staff_id=staff_id) | Q(staff_name=staff_name) | Q(staff_telegram_username=staff_username) | Q(staff_telegram_id=staff_telegram_id)).first()

        if not staff:
            return Response({
                "success": False,
                "code": 404,
                "message": "Staff not found"
            }, status=status.HTTP_404_NOT_FOUND)

        for attr, value in request.data.items():
            setattr(staff, attr, value)

        staff.save()

        if 'staff_status' in request.data:

            try:
                staff_status_value = bool(int(request.data['staff_status']))

                user = User.objects.filter(username=staff.staff_telegram_username).first()

                try:
                    if staff_status_value == 0:
                        bot_user = BotUsersStorage.objects.get(username=staff_username)
                        if bot_user.message_id:
                            bot_user.user_status = "Inactive"
                            bot_user.save()
                    elif staff_status_value == 1:
                        bot_user = BotUsersStorage.objects.get(username=staff_username)
                        if bot_user.message_id:
                            bot_user.user_status = "Active"
                            bot_user.save()
                            if bot_user.user_choose_language == "English":
                                message = f"Congratulations <strong>{staff_username}</strong>, you have been approved. You can use QR Jump now. Please use defualt with defualt PIN:12345"
                            elif bot_user.user_choose_language == "Khmer":
                                message = f"សូមអបអរសាទរ <strong>{staff_username}</strong> គណនរបស់អ្នកត្រូវបានដាក់អោយដំណើរការ។ អ្នកអាចប្រើ QR Jump ឥឡូវនេះបាន។សូមប្រើប្រាស់លេខកូដ:12345"
                            elif bot_user.user_choose_language is None:
                                message = f"Congratulations <strong>{staff_username}</strong>, you have been approved. You can use QR Jump now. Please use defualt with defualt PIN:12345"
                            send_telegram_message(bot_user.message_id, message, parse_mode='HTML')
                except BotUsersStorage.DoesNotExist:
                    return Response({
                        "success": False,
                        "code": 404,
                        "message": "User not found."
                    }, status=status.HTTP_404_NOT_FOUND)

                if user:
                    user.is_staff = staff_status_value
                    user.save()
                else:
                    return Response({
                        "success": False,
                        "code": 404,
                        "message": "Staff user not found"
                    }, status=status.HTTP_404_NOT_FOUND)

            except ValueError:
                return Response({
                    "success": False,
                    "code": 400,
                    "message": "Invalid staff_status value provided"
                }, status=status.HTTP_400_BAD_REQUEST)

        if 'staff_user_pin' in request.data:
            new_pin = request.data['staff_user_pin']

            try:
                # Hash the new pin
                hashed_pin = hashlib.sha256(new_pin.encode('utf-8')).hexdigest()
                base64_encoded_pin = base64.b64encode(hashed_pin.encode('utf-8')).decode('utf-8')

                user = User.objects.filter(username=staff.staff_telegram_username).first()

                if user:
                    user.set_password(base64_encoded_pin)
                    user.save()
                else:
                    return Response({
                        "success": False,
                        "code": 404,
                        "message": "Staff user not found"
                    }, status=status.HTTP_404_NOT_FOUND)

            except Exception as e:
                return Response({
                    "success": False,
                    "code": 400,
                    "message": f"Error while updating pin: {str(e)}"
                }, status=status.HTTP_400_BAD_REQUEST)

        if 'staff_position' in request.data:  
            new_role = request.data['staff_position']

            try:
                user = User.objects.filter(username=staff.staff_telegram_username).first()

                if user:
                    user.user_permissions.clear()

                    if new_role == "staff":
                        per = [
                            Permission.objects.get(codename='view_transactionhistory'),
                            Permission.objects.get(codename='add_transactionhistory')
                        ]
                    elif new_role == "manager":
                        per = [
                            Permission.objects.get(codename='add_staff'),
                            Permission.objects.get(codename='change_staff'),
                            Permission.objects.get(codename='delete_staff'),
                            Permission.objects.get(codename='view_staff'),
                            Permission.objects.get(codename='view_branch'),
                            Permission.objects.get(codename='add_transactionhistory'),
                            Permission.objects.get(codename='view_transactionhistory')
                        ]
                    elif new_role == "admin":
                        per = [
                            Permission.objects.get(codename='add_staff'),
                            Permission.objects.get(codename='change_staff'),
                            Permission.objects.get(codename='delete_staff'),
                            Permission.objects.get(codename='view_staff'),
                            Permission.objects.get(codename='view_branch'),
                            Permission.objects.get(codename='add_transactionhistory'),
                            Permission.objects.get(codename='view_transactionhistory'),
                            Permission.objects.get(codename='add_branch'),
                            Permission.objects.get(codename='delete_branch'),
                            Permission.objects.get(codename='change_branch'),
                            Permission.objects.get(codename='view_company')
                        ]
                    else:
                        return Response({
                            "success": False,
                            "code": 400,
                            "message": "Invalid staff role provided"
                        }, status=status.HTTP_400_BAD_REQUEST)

                    user.user_permissions.add(*per)
                    user.save()

                else:
                    return Response({
                        "success": False,
                        "code": 404,
                        "message": "Staff user not found"
                    }, status=status.HTTP_404_NOT_FOUND)

            except Permission.DoesNotExist:
                return Response({
                    "success": False,
                    "code": 500,
                    "message": "Permission not found for the given role"
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
        staff = Staff.objects.filter(Q(staff_telegram_username=staff_username)).first()
        if branch_ids:
            branch_ids = [int(branch_id) for branch_id in branch_ids.split(',')]    
            branches = Branch.objects.filter(id__in=branch_ids) 

            staff.branches.set(branches) 
            staff.save()

        return Response({
            "success": True,
            "code": 200,
            "message": "Staff updated successfully"
        }, status=status.HTTP_200_OK)

    
    def delete(self, request, *args, **kwargs):
        staff_name = request.query_params.get('staff_name')
        staff_id = request.query_params.get('staff_id')
        staff_username = request.query_params.get('staff_telegram_username', None)

        staff = Staff.objects.filter(Q(staff_id=staff_id) | Q(staff_name=staff_name) | Q(staff_telegram_username=staff_username)).first()

        if not staff_name and not staff_id and not staff_username:
            return Response({
                "success": False,
                "code": 400,
                "message": "No params provided"
            }, status=status.HTTP_400_BAD_REQUEST)
        
        if not staff:
            return Response({
                "success": False,
                "code": 404,
                "message": "Staff not found"
            }, status=status.HTTP_404_NOT_FOUND)

        user = User.objects.filter(username=staff.staff_telegram_username).first()
        if user:
            user.delete()

        staff.delete()
        return Response({
            "success": True,
            "code": 200,
            "message": "Staff deleted successfully"
        }, status=status.HTTP_200_OK)

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
        staff_name = request.query_params.get('staff_name', None)
        staff_id = request.query_params.get('staff_id', None)
        branch_ids = request.data.get('branch_ids', [])

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

        if branch_ids:
        # Convert branch_ids to a list if it's a comma-separated string
            branch_ids = [int(branch_id) for branch_id in branch_ids.split(',')]
            branches = Branch.objects.filter(id__in=branch_ids)  # Use the correct field for filtering (e.g., `id`)

            staff.branches.set(branches) 
            staff.save()

            return Response({
                "success": True,
                "code": 200,
                "message": "Staff and branches updated successfully",
                "data": {
                    "staff_id": staff.staff_id,
                    "staff_name": staff.staff_name,
                    "branches": [branch.br_kh_name for branch in branches]
                }
            }, status=status.HTTP_200_OK)


        if 'staff_status' in request.data:
            try:
                user = User.objects.filter(username=staff.staff_telegram_username).first()

                if user:
                    # Convert staff_status to a proper boolean value
                    new_is_staff_value = bool(int(request.data.get('staff_status')))
                    user.is_staff = new_is_staff_value
                    user.save()

                    print(f"Updated User {user.username}: is_staff set to {new_is_staff_value}")

                    refreshed_user = User.objects.get(username=user.username)
                    print(f"Confirmed: User {refreshed_user.username} is_staff is now {refreshed_user.is_staff}")
                else:
                    print(f"No User found for staff_telegram_username: {staff.staff_telegram_username}")
            except ValueError as e:
                print(f"Error converting staff_status to boolean: {e}")
                return Response({
                    "success": False,
                    "code": 400,
                    "message": "Invalid staff_status value"
                }, status=status.HTTP_400_BAD_REQUEST)

        return Response({
            "success": True,
            "code": 200,
            "message": "Staff updated successfully"
        }, status=status.HTTP_200_OK)

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

class StaticPaymentFilter(filters.FilterSet):
    payment_type = filters.CharFilter(field_name='payment_type', lookup_expr='exact')
    br_id = filters.NumberFilter(field_name='br_id', lookup_expr='exact')
    sp_created_at = filters.DateTimeFilter(field_name='sp_created_at', lookup_expr='exact')

    class Meta:
        model = StaticPayment
        fields = ['payment_type','br_id','sp_created_at']

class StaticPaymentViewSet(viewsets.ModelViewSet):
    queryset = StaticPayment.objects.all()
    serializer_class = StaticPaymentSerializer
    filter_backends = [DjangoFilterBackend]
    filterset_class = StaticPaymentFilter

    def create(self, request, *args, **kwargs):
        payment_type = request.data.get('payment_type')
        branch_ids = request.data.get('branch_ids', []) 
        if not payment_type:
            return Response({
                "success": False,
                "code": 400,
                "message": "The payment_type field is required",
                "data": []
            }, status=status.HTTP_400_BAD_REQUEST)

        branches = Branch.objects.filter(id__in=branch_ids)
        if not branches.exists():
            return Response({
                "success": False,
                "code": 400,
                "message": "The branch not found",
                "data": []
            }, status=status.HTTP_400_BAD_REQUEST)

        static_payment = StaticPayment.objects.create(payment_type=payment_type)
        static_payment.branch.set(branches)
        serializer = StaticPaymentSerializer(static_payment)
        return Response({
            "success": True,
            "code": 200,
            "message": "Successfull created Static Payment",
            "data":[serializer.data]
        })
    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        serializer = self.get_serializer(queryset, many=True)

        return Response({
            "success": True,
            "code": 200,
            "message": "Successfully retrieved Static Payments",
            "data": serializer.data
        }, status=status.HTTP_200_OK)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        payment_type = request.data.get('payment_type', instance.payment_type)
        branch_ids = request.data.get('branch_ids', [])

        branches = Branch.objects.filter(id__in=branch_ids)
        if not branches.exists() and branch_ids:
            return Response({
                "success": False,
                "code": 400,
                "message": "The branch not found",
                "data": []
            }, status=status.HTTP_400_BAD_REQUEST)

        instance.payment_type = payment_type
        instance.save()
        if branch_ids:
            instance.branch.set(branches)

        serializer = StaticPaymentSerializer(instance)
        return Response({
            "success": True,
            "code": 200,
            "message": "Successfully updated Static Payment",
            "data": [serializer.data]
        }, status=status.HTTP_200_OK)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()

        return Response({
            "success": True,
            "code": 200,
            "message": "Successfully deleted Static Payment",
            "data": []
        }, status=status.HTTP_200_OK)
    
class BankCredentialsFilter(filters.FilterSet):
    bank_name = filters.CharFilter(field_name='bank_name', lookup_expr='exact')
    branch_ids = filters.CharFilter(field_name='branch_ids', lookup_expr='exact')
    merchant_id = filters.NumberFilter(field_name='merchant_id', lookup_expr='exact') 

    class Meta:
        model = BankCredentials
        fields = ['bank_name', 'branch_ids', 'merchant_id']

class BankCredentialsViewSet(viewsets.ModelViewSet):
    queryset = BankCredentials.objects.all()
    serializer_class = BankCredentialsSerializer
    filter_backends = [DjangoFilterBackend]
    filterset_class = BankCredentialsFilter

    def create(self, request, *args, **kwargs):
        data = request.data.copy()  
        branch_ids = data.pop('branch_ids', []) 

        new_branch_ids = []
        for branch_id in branch_ids:
            if isinstance(branch_id, str) and ',' in branch_id:
                new_branch_ids.extend(int(id_) for id_ in branch_id.split(','))
            else:
                new_branch_ids.append(int(branch_id))

        branch_ids = new_branch_ids

        branches = Branch.objects.filter(id__in=branch_ids)
        if len(branches) != len(branch_ids):
            return Response({
                "success": False,
                "code": 400,
                "message": "Some branch IDs are invalid",
                "invalid_branch_ids": list(set(branch_ids) - set(branches.values_list('id', flat=True))),
                "data": []
            }, status=status.HTTP_400_BAD_REQUEST)

        serializer = self.get_serializer(data=data)
        if serializer.is_valid():
            bank_credentials = serializer.save()
            bank_credentials.branch.set(branches) 
            return Response({
                "success": True,
                "code": 201,
                "message": "Bank credentials created successfully.",
                "data": serializer.data
            }, status=status.HTTP_201_CREATED)
        else:
            return Response({
                "success": False,
                "code": 400,
                "message": "Validation error",
                "errors": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
    
    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        serializer = self.get_serializer(queryset, many=True)

        return Response({
            "success": True,
            "code": 200,
            "message": "Successfully retrieved Bank Credentials",
            "data": serializer.data
        }, status=status.HTTP_200_OK)
    
    def put(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = BankCredentialsSerializer(instance, data=request.data, partial=True)  # Allow partial updates

        if serializer.is_valid():
            serializer.save()
            return Response({
                "success": True,
                "code": 200,
                "message": "Successfully updated Bank Credentials",
                "data": serializer.data  # No need to wrap in a list
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                "success": False,
                "code": 400,
                "message": "Validation error",
                "errors": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()

        return Response({
            "success": True,
            "code": 200,
            "message": "Successfully deleted Bank Credentials",
            "data": []
        }, status=status.HTTP_200_OK)
    
class BotUsersStorageFilter(filters.FilterSet):
    telegram_id = filters.NumberFilter(field_name='telegram_id', lookup_expr='exact')
    first_name = filters.CharFilter(field_name='first_name', lookup_expr='exact')
    last_name = filters.CharFilter(field_name='last_name', lookup_expr='exact')
    full_name = filters.CharFilter(field_name='full_name', lookup_expr='exact')
    username = filters.CharFilter(field_name='username', lookup_expr='exact')
    telegram_language = filters.CharFilter(field_name='telegram_language', lookup_expr='exact')
    user_choose_language = filters.CharFilter(field_name='user_choose_language', lookup_expr='exact')
    user_status = filters.CharFilter(field_name='user_status', lookup_expr='exact')
    created_at = filters.DateTimeFilter(field_name='created_at', lookup_expr='exact')
    visiter = filters.CharFilter(field_name='visiter', lookup_expr='exact')
    phone_number = filters.NumberFilter(field_name='phone_number', lookup_expr='exact')

    class Meta:
        model = BotUsersStorage
        fields = ['telegram_id','first_name','last_name','full_name','username','telegram_language','user_choose_language','user_status','created_at','visiter','phone_number']


class BotUsersStorageViewSet(viewsets.ModelViewSet):
    queryset = BotUsersStorage.objects.all()
    serializer_class = BotUsersStorageSerializer
    filter_backends = [DjangoFilterBackend]
    filterset_class = BotUsersStorageFilter

    def get_permissions(self):
        self.permission_classes = [IsAdminUser]
        return super().get_permissions()
    
    def create(self, request, *args, **kwargs):
        required_fields = ["telegram_id", "first_name", "username", "user_status"]
        missing_fields = [field for field in required_fields if not request.data.get(field)]

        if missing_fields:
            return Response({
                "success": False,
                "code": 400,
                "message": f"The following fields are required: {', '.join(missing_fields)}",
                "data": []
            }, status=status.HTTP_400_BAD_REQUEST)
        telegram_id = request.data.get("telegram_id")
        first_name = request.data.get("first_name")
        last_name = request.data.get("last_name", "")
        full_name = request.data.get("full_name", f"{first_name} {last_name}".strip())
        username = request.data.get("username")
        telegram_language = request.data.get("telegram_language", "en")
        user_choose_language = request.data.get("user_choose_language", telegram_language)
        user_status = request.data.get("user_status")
        visiter = request.data.get("visiter", None)
        phone_number = request.data.get("phone_number", None)

        if BotUsersStorage.objects.filter(telegram_id=telegram_id).exists():
            return Response({
                "success": False,
                "code": 400,
                "message": "A user with this Telegram ID already exists",
                "data": []
            }, status=status.HTTP_400_BAD_REQUEST)

        user = BotUsersStorage.objects.create(
            telegram_id=telegram_id,
            first_name=first_name,
            last_name=last_name,
            full_name=full_name,
            username=username,
            telegram_language=telegram_language,
            user_choose_language=user_choose_language,
            user_status=user_status,
            visiter=visiter,
            phone_number=phone_number,
        )

        serializer = self.get_serializer(user)
        return Response({
            "success": True,
            "code": 201,
            "message": "User created successfully",
            "data": serializer.data
        }, status=status.HTTP_201_CREATED)
        
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
                    "message": "User not found",
                    "data": []
                }, status=status.HTTP_404_NOT_FOUND)

            serializer = self.get_serializer(queryset, many=True)
            return Response({
                "success": True,
                "code": 200,
                "message": "User fetched successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "success": False,
                "code": 500,
                "message": "An error occurred while fetching users data",
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def put(self, request, *args, **kwargs):
        try:
            username = request.query_params.get("username")
            first_name = request.query_params.get("first_name")
            telegram_id = request.query_params.get("telegram_id")

            if not any([username, first_name, telegram_id]):
                return Response({
                    "success": False,
                    "code": 400,
                    "message": "At least one of username, first_name, or telegram_id is required as a query parameter",
                    "data": []
                }, status=status.HTTP_400_BAD_REQUEST)

            user = self.get_queryset().filter(
                Q(username=username) | Q(first_name=first_name) | Q(telegram_id=telegram_id)
            ).first()

            if not user:
                return Response({
                    "success": False,
                    "code": 404,
                    "message": "User not found",
                    "data": []
                }, status=status.HTTP_404_NOT_FOUND)

            for field in request.data:
                setattr(user, field, request.data[field])

            user.save()
            serializer = self.get_serializer(user)
            return Response({
                "success": True,
                "code": 200,
                "message": "User updated successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "success": False,
                "code": 500,
                "message": "An error occurred while updating user data",
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request, *args, **kwargs):
        try:
            username = request.query_params.get("username")
            first_name = request.query_params.get("first_name")
            telegram_id = request.query_params.get("telegram_id")

            if not any([username, first_name, telegram_id]):
                return Response({
                    "success": False,
                    "code": 400,
                    "message": "At least one of username, first_name, or telegram_id is required as a query parameter",
                    "data": []
                }, status=status.HTTP_400_BAD_REQUEST)

            user = self.get_queryset().filter(
                Q(username=username) | Q(first_name=first_name) | Q(telegram_id=telegram_id)
            ).first()

            if not user:
                return Response({
                    "success": False,
                    "code": 404,
                    "message": "User not found",
                    "data": []
                }, status=status.HTTP_404_NOT_FOUND)

            user.delete()
            return Response({
                "success": True,
                "code": 200,
                "message": "User deleted successfully",
                "data": []
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "success": False,
                "code": 500,
                "message": "An error occurred while deleting the user",
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
