from datetime import datetime
import json
from xml.etree.ElementTree import Comment
from django.http import HttpResponse,Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.http import JsonResponse,HttpResponseNotFound, HttpResponseBadRequest,HttpResponseServerError
from furniture_app.models import Defect, Furniture, Type, State
from django.views.decorators.csrf import csrf_exempt, csrf_protect
import logging
import re
from django.db import IntegrityError
from django.contrib.auth import authenticate, login, logout
from rest_framework_simplejwt.tokens import Token
from rest_framework import serializers
from rest_framework_simplejwt.views import TokenObtainPairView
from django.contrib.auth.models import User
import jwt 
from django.conf import settings
from django.core.serializers import serialize

logger = logging.getLogger(__name__)

class CustomTokenSerializer(serializers.Serializer):
    token = serializers.CharField()
    username = serializers.CharField(source='user.username')
    is_admin = serializers.SerializerMethodField()

    def get_is_admin(self, obj):
        return obj.user.is_staff

class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenSerializer


@csrf_exempt
def signup_user(request):
    if request.method == 'POST':
        print("signup")
        data = json.loads(request.body)
        username = data['username']
        password = data['password']
        email = data['email']

        if User.objects.filter(username=username).exists():
            return JsonResponse({'error': 'Username is already taken.'}, status=400)

        if User.objects.filter(email=email).exists():
            return JsonResponse({'error': 'Email is already taken.'}, status=400)

        user = User.objects.create_user(username=username, email=email, password=password)

        payload = {
            'username': user.username,
            'email': user.email,
        }

        token = jwt.encode(payload, settings.SECRET_KEY_FOR_JWT, algorithm='HS256') 

        login(request, user)

        return JsonResponse({'success': True, 'user': username, 'token': token, 'admin': user.is_staff}, status=200)
    else:
        return JsonResponse({'error': 'Method not allowed.'}, status=405)

@csrf_exempt
def login_user(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        username = data['username']
        password = data['password']

        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            payload = {
            'username': user.username,
            'email': user.email,
            'admin': user.is_staff
            #"exp": datetime.utcnow() + timedelta(hours=1)
        } 
            token = jwt.encode(payload, settings.SECRET_KEY_FOR_JWT, algorithm='HS256')  # Use a secure secret key
            login(request, user)
            return JsonResponse({'success': True, 'token': token, 'admin': user.is_staff}, status=200)
        else:
            return JsonResponse({'error': 'Neteisingas prisijungimo vardas arba slaptažodis'}, status=401)
    else:
        return JsonResponse({'error': 'Method not allowed.'}, status=405)


def home(request):
    return HttpResponse("Hello, Django!")

@csrf_exempt
def get_types(request):
    token = request.headers.get('Authorization')    
    if not token:
        return JsonResponse({'success': False, 'error': 'Unauthorized'}, status=401)
    try:
        payload = jwt.decode(token, settings.SECRET_KEY_FOR_JWT, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return JsonResponse({'success': False, 'error': 'Token has expired'}, status=401)
    except jwt.InvalidTokenError:
        return JsonResponse({'success': False, 'error': 'Invalid token'}, status=401)
    if request.method == 'GET':
        try:
            types = Type.objects.all().values('id', 'title')
            types_list = list(types)
            return JsonResponse(types_list, safe=False, status=200)
        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'error': 'Invalid JSON data'}, status=400)
    else:
        return JsonResponse({'error': 'Method not allowed.'}, status=405)

@csrf_exempt
def get_furniture(request):
    token = request.headers.get('Authorization')    
    if not token:
        return JsonResponse({'success': False, 'error': 'Unauthorized'}, status=401)
    try:
        payload = jwt.decode(token, settings.SECRET_KEY_FOR_JWT, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return JsonResponse({'success': False, 'error': 'Token has expired'}, status=401)
    except jwt.InvalidTokenError:
        return JsonResponse({'success': False, 'error': 'Invalid token'}, status=401)
    if request.method == 'GET':
        try:
            furniture = Furniture.objects.all().values('id', 'title', 'code')
            furniture_list = list(furniture)
            return JsonResponse(furniture_list, safe=False, status=200)
        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'error': 'Invalid JSON data'}, status=400)
    else:
        return JsonResponse({'error': 'Method not allowed.'}, status=405)

@csrf_exempt
def post_defect(request):
    token = request.headers.get('Authorization') 
    if not token:
        return JsonResponse({'success': False, 'error': 'Unauthorized'}, status=401)  
    try:
        # Verify and decode the token
        payload = jwt.decode(token, settings.SECRET_KEY_FOR_JWT, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return JsonResponse({'success': False, 'error': 'Token has expired'}, status=401)
    except jwt.InvalidTokenError:
        return JsonResponse({'success': False, 'error': 'Invalid token'}, status=401)

    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            furniture_id = data['furniture']
            description = data['description']
            level = data['level']
            type_id = data['type']        
            date = datetime.now().date()
            username = payload['username']
            user = User.objects.get(username=username)
            state = State.objects.get(title="Nepradėta")

            if not furniture_id or not description or not level or not type_id:
                return JsonResponse({'success': False, 'error': 'All fields are required'}, status=422)

            furniture = Furniture.objects.get(pk=furniture_id)
            type = Type.objects.get(pk=type_id)

            defect = Defect(date=date, description=description, level=level, type=type, user_reported=user, furniture=furniture, state=state)
            defect.save()
            return JsonResponse({'success': True, "id" : defect.pk}, status = 201)
           

        except (json.JSONDecodeError, KeyError, Type.DoesNotExist, Furniture.DoesNotExist) as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=400)

@csrf_exempt
def get_defects(request):
    token = request.headers.get('Authorization')    
    if not token:
        return JsonResponse({'success': False, 'error': 'Unauthorized'}, status=401)
    try:
        payload = jwt.decode(token, settings.SECRET_KEY_FOR_JWT, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return JsonResponse({'success': False, 'error': 'Token has expired'}, status=401)
    except jwt.InvalidTokenError:
        return JsonResponse({'success': False, 'error': 'Invalid token'}, status=401)
    if request.method == 'GET':
        try:
            defects = Defect.objects.all()
            defects_list = []
            for defect in defects:
                defect_data = {
                    'id': defect.id,
                    'description': defect.description,
                    'date': defect.date,
                    'level': defect.level,
                    'user_assigned': defect.user_assigned.username if defect.user_assigned else None,
                    'user_reported': defect.user_reported.username if defect.user_reported else None,
                    'furniture_title': defect.furniture.title if defect.furniture else None,
                    'type_title': defect.type.title if defect.type else None,
                    'state': defect.state.title if defect.state else None,
                }
                defects_list.append(defect_data)
            return JsonResponse(defects_list, safe=False, status=200)
        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'error': 'Invalid JSON data'}, status=400)
    else:
        return JsonResponse({'error': 'Method not allowed.'}, status=405)

@csrf_exempt
def get_states(request):
    token = request.headers.get('Authorization')    
    if not token:
        return JsonResponse({'success': False, 'error': 'Unauthorized'}, status=401)
    try:
        payload = jwt.decode(token, settings.SECRET_KEY_FOR_JWT, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return JsonResponse({'success': False, 'error': 'Token has expired'}, status=401)
    except jwt.InvalidTokenError:
        return JsonResponse({'success': False, 'error': 'Invalid token'}, status=401)
    if request.method == 'GET':
        try:
            states = State.objects.all().values('id', 'title')
            states_list = list(states)
            return JsonResponse(states_list, safe=False, status=200)
        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'error': 'Invalid JSON data'}, status=400)
    else:
        return JsonResponse({'error': 'Method not allowed.'}, status=405)


@csrf_exempt
def handle_defect(request, pk):
    token = request.headers.get('Authorization')
    
    if not token:
        return JsonResponse({'success': False, 'error': 'Unauthorized'}, status=401)
    try:
        payload = jwt.decode(token, settings.SECRET_KEY_FOR_JWT, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return JsonResponse({'success': False, 'error': 'Token has expired'}, status=401)
    except jwt.InvalidTokenError:
        return JsonResponse({'success': False, 'error': 'Invalid token'}, status=401)

    if request.method == 'GET':
        try:
            defect = Defect.objects.get(pk=pk)
        except Defect.DoesNotExist:
            return HttpResponseNotFound("Defect not found")
        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'error': 'Invalid JSON data'}, status=400)

        data = {
            'description': defect.description,
            'date' : defect.date,
            'furniture' : defect.furniture.title,
            'state' : defect.state.id,
            'level' : defect.level,
            'type' : defect.type.title
        }
        return JsonResponse(data, status=200)

    elif request.method == 'DELETE':        
        try:
            defect = Defect.objects.get(pk=pk)
        except Defect.DoesNotExist:
            return HttpResponseNotFound("Defect not found")
        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'error': 'Invalid JSON data'}, status=400)       

        defect.delete()
        return HttpResponse(status=204)

    elif request.method == 'PUT':
            try:
                defect = Defect.objects.get(pk=pk)
            except Defect.DoesNotExist:
                return HttpResponseNotFound("Defect not found")

            try:
                data = json.loads(request.body.decode('utf-8'))
            except json.JSONDecodeError:
                return JsonResponse({'success': False, 'error': 'Invalid JSON data'}, status=400)

            new_state = data.get("state")

            if not new_state:
                return JsonResponse({'success': False, 'error': 'All fields are required'}, status=422)
            state = State.objects.get(pk=new_state)
            defect.state = state
            user_assigned = User.objects.get(username=payload['username'])
            defect.user_assigned = user_assigned

            try:
                defect.save()
                return JsonResponse({'success': True, "id" : defect.pk}, status=200)
            except Exception as e:
                return JsonResponse({'success': False, 'error': str(e)}, status=500) 
    else:
        return JsonResponse({'error': 'Method not allowed.'}, status=405)  
