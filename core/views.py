from datetime import datetime
from django.shortcuts import render, redirect
from .models import Doctor, ExcelFile, ExcelAccess
import pandas as pd
import os
from django.contrib import messages
from django.http import HttpResponseRedirect
from django.urls import reverse
import os
from pytz import timezone
from django.utils.timezone import localtime

def login_view(request):
    if request.method == 'POST':
        doctor_id = request.POST['doctor_id']
        password = request.POST['password']

        try:
            doctor = Doctor.objects.get(doctor_id=doctor_id)
            if doctor.password == password:
                request.session['doctor_id'] = doctor.id
                request.session['is_admin'] = doctor.is_admin

                if doctor.is_admin:
                    return redirect('admin_dashboard')
                else:
                    return redirect('doctor_dashboard')
            else:
                return render(request, 'login.html', {'error': 'Incorrect password'})
        except Doctor.DoesNotExist:
            return render(request, 'login.html', {'error': 'Doctor not found'})

    return render(request, 'login.html')


def admin_dashboard(request):
    doctor = Doctor.objects.get(id=request.session['doctor_id'])
    files = ExcelFile.objects.filter(uploaded_by=doctor)
    return render(request, 'admin_dashboard.html', {'files': files})

def upload_excel(request):
    if request.method == 'POST':
        file = request.FILES['file']
        doc = Doctor.objects.get(id=request.session['doctor_id'])
        ExcelFile.objects.create(file=file, uploaded_by=doc)
        return redirect('admin_dashboard')
    return render(request, 'upload.html')

from django.db.models import Q

def publish_excel(request, file_id):
    if not request.session.get('is_admin'):
        return redirect('login')

    excel_file = get_object_or_404(ExcelFile, id=file_id)

    # Handle POST request to save access
    if request.method == 'POST':
        for doctor in Doctor.objects.filter(is_admin=False):
            col_key = f'doctor_{doctor.id}_columns'
            selected_columns = request.POST.getlist(col_key)

            if selected_columns:
                access, created = ExcelAccess.objects.get_or_create(
                    doctor=doctor,
                    excel_file=excel_file
                )
                access.allowed_columns = selected_columns
                access.save()
            else:
                ExcelAccess.objects.filter(doctor=doctor, excel_file=excel_file).delete()

        excel_file.is_published = True
        excel_file.save()
        messages.success(request, "Access saved successfully.")
        return redirect('admin_dashboard')

    # Load Excel columns
    try:
        df = pd.read_excel(excel_file.file.path)
        all_columns = list(df.columns)
    except Exception as e:
        messages.error(request, f"Error reading file: {e}")
        return redirect('admin_dashboard')

    # Doctor search filter
    search_query = request.GET.get('search', '').strip().lower()
    doctors = Doctor.objects.filter(is_admin=False)
    if search_query:
        doctors = doctors.filter(doctor_id__icontains=search_query)

    # Access map
    access_data = {
        doctor.id: ExcelAccess.objects.filter(doctor=doctor, excel_file=excel_file).first()
        for doctor in doctors
    }

    return render(request, 'publish.html', {
        'excel_file': excel_file,
        'columns': all_columns,
        'doctors': doctors,
        'access_data': access_data,
        'search_query': search_query
    })



from .models import AuditLog

def doctor_dashboard(request):
    doc = Doctor.objects.get(id=request.session['doctor_id'])
    results = []
    used_columns = set()
    error = None
    query = ""

    sensitive_fields = ['Social Security Number', 'Driver\'s License', 'Credit Card Number', 'Policy Amount']

    if request.method == 'POST':
        query = request.POST['query'].strip().lower()

        AuditLog.objects.create(
            doctor=doc,
            query=query
        )

        total_matches = 0
        accesses = ExcelAccess.objects.filter(doctor=doc)

        for access in accesses:
            try:
                df = pd.read_excel(access.excel_file.file.path).fillna("")

                required_columns = ['Full Name', 'Email', 'Phone Number', 'Patient Card Number']
                if not all(col in df.columns for col in required_columns):
                    error = f"The file '{access.excel_file.file.name}' is missing required patient columns."
                    continue

                df_filtered = df[
                    df['Full Name'].astype(str).str.contains(query, case=False) |
                    df['Email'].astype(str).str.contains(query, case=False) |
                    df['Phone Number'].astype(str).str.contains(query, case=False) |
                    df['Patient Card Number'].astype(str).str.contains(query, case=False)
                ]

                allowed = access.allowed_columns
                df_filtered = df_filtered[allowed]

                # 🔒 Mask sensitive fields
                for col in sensitive_fields:
                    if col in df_filtered.columns:
                        df_filtered[col] = df_filtered[col].apply(mask_sensitive_value)

                # 🧮 Convert DOB to Age
                if 'Date of Birth' in df_filtered.columns:
                    try:
                        current_year = datetime.now().year
                        df_filtered['Age'] = df_filtered['Date of Birth'].astype(str).str[:4].astype(int)
                        df_filtered['Age'] = df_filtered['Age'].apply(lambda y: current_year - y if 1900 <= y <= current_year else "")
                        df_filtered.drop(columns=['Date of Birth'], inplace=True)
                    except Exception as e:
                        error = f"Error calculating Age from DOB: {str(e)}"


                # ✅ Only add non-empty columns
                for col in df_filtered.columns:
                    if df_filtered[col].astype(str).str.strip().replace("nan", "").any():
                        used_columns.add(col)

                total_matches += len(df_filtered)
                results.extend(df_filtered.to_dict(orient='records'))

            except Exception as e:
                error = f"Error loading file: {str(e)}"
                continue

        if not results and not error:
            error = "No matching records found."

    # Prioritize key columns
    priority = ['Patient Card Number', 'Full Name', 'DOB', 'Address', 'Phone Number', 'Email']
    ordered_columns = [col for col in priority if col in used_columns]
    other_columns = sorted(used_columns - set(ordered_columns))
    final_columns = ordered_columns + other_columns

    return render(request, 'doctor_dashboard.html', {
        'results': results,
        'columns': final_columns,
        'error': error,
        'query': query
    })



from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.shortcuts import redirect, get_object_or_404
import os

def delete_excel(request, file_id):
    print("SESSION DATA:", request.session.items())

    doctor_id = request.session.get('doctor_id')
    is_admin = request.session.get('is_admin')

    if doctor_id is None:
        messages.error(request, "You are not logged in.")
        return redirect('login')

    if not is_admin:
        messages.error(request, "You are not authorized to delete files.")
        return redirect('admin_dashboard')

    try:
        file = ExcelFile.objects.get(id=file_id)

        # Delete related access rules
        ExcelAccess.objects.filter(excel_file=file).delete()

        # Delete actual file
        file_path = file.file.path
        if os.path.exists(file_path):
            os.remove(file_path)

        # Delete DB record
        file.delete()

        messages.success(request, "File deleted successfully.")
    except Exception as e:
        messages.error(request, f"Failed to delete file: {str(e)}")

    return redirect('admin_dashboard')

def audit_logs(request):
    if not request.session.get('is_admin'):
        return redirect('login')

    logs = AuditLog.objects.select_related('doctor').order_by('-searched_at')

    doctor_search = request.GET.get('doctor_id', '').strip().lower()
    query_search = request.GET.get('query', '').strip().lower()

    if doctor_search:
        logs = logs.filter(doctor__doctor_id__icontains=doctor_search)

    if query_search:
        logs = logs.filter(query__icontains=query_search)

    coral_harbour = timezone('America/Coral_Harbour')
    for log in logs:
        log.local_time = localtime(log.searched_at, coral_harbour).strftime("%Y-%m-%d %H:%M:%S")

    return render(request, 'audit_logs.html', {
        'logs': logs,
        'doctor_search': doctor_search,
        'query_search': query_search
    })

def patient_detail(request, patient_id):
    doctor = Doctor.objects.get(id=request.session['doctor_id'])
    patient_data = []

    sensitive_fields = ['Social Security Number', 'Driver\'s License', 'Credit Card Number']

    accesses = ExcelAccess.objects.filter(doctor=doctor)

    for access in accesses:
        try:
            df = pd.read_excel(access.excel_file.file.path).fillna("")

            if 'Patient Card Number' not in df.columns:
                continue

            df_patient = df[df['Patient Card Number'].astype(str) == patient_id]

            if df_patient.empty:
                continue

            df_patient = df_patient[access.allowed_columns]

            # 🔒 Mask sensitive fields
            for col in sensitive_fields:
                if col in df_patient.columns:
                    df_patient[col] = df_patient[col].apply(mask_sensitive_value)

            df_patient['source_file'] = access.excel_file.file.name
            patient_data.extend(df_patient.to_dict(orient='records'))

        except Exception:
            continue

    return render(request, 'patient_detail.html', {
        'patient_id': patient_id,
        'patient_data': patient_data,
    })


def mask_sensitive_value(value):
    if not isinstance(value, str):
        value = str(value)

    if len(value) <= 4:
        return value
    return 'X' * (len(value) - 4) + value[-4:]

from django.contrib import messages
from django.shortcuts import redirect

def clear_audit_logs(request):
    doctor = Doctor.objects.get(id=request.session['doctor_id'])
    
    if not doctor.is_admin:
        messages.error(request, "You are not authorized to clear audit logs.")
        return redirect('admin_dashboard')

    AuditLog.objects.all().delete()
    messages.success(request, "Audit logs cleared successfully.")
    return redirect('admin_dashboard')

from django.shortcuts import render, redirect, get_object_or_404
from core.models import Doctor
from django.contrib import messages

def manage_users(request):
    if not request.session.get('is_admin'):
        return redirect('login')

    search = request.GET.get('search', '').strip()
    if search:
        users = Doctor.objects.filter(doctor_id__icontains=search).order_by('doctor_id')
    else:
        users = Doctor.objects.all().order_by('doctor_id')

    return render(request, 'manage_users.html', {
        'users': users,
        'search': search
    })


def add_user(request):
    if not request.session.get('is_admin'):
        return redirect('login')

    if request.method == 'POST':
        doctor_id = request.POST['doctor_id'].strip().upper()
        password = request.POST['password'].strip().lower()
        is_admin = request.POST.get('is_admin') == 'on'

        if Doctor.objects.filter(doctor_id=doctor_id).exists():
            messages.error(request, "User already exists.")
        else:
            Doctor.objects.create(doctor_id=doctor_id, password=password, is_admin=is_admin)
            messages.success(request, f"{doctor_id} added successfully.")
        return redirect('manage_users')

    return render(request, 'add_user.html')

def delete_user(request, user_id):
    if not request.session.get('is_admin'):
        return redirect('login')

    doctor = get_object_or_404(Doctor, id=user_id)
    if doctor.doctor_id.lower() == 'admin1':
        messages.error(request, "Default admin cannot be deleted.")
    else:
        doctor.delete()
        messages.success(request, f"{doctor.doctor_id} deleted.")
    return redirect('manage_users')
