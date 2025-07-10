from django.db import models

class Doctor(models.Model):
    doctor_id = models.CharField(max_length=100, unique=True)
    password = models.CharField(max_length=128)
    is_admin = models.BooleanField(default=False)

    def __str__(self):
        return self.doctor_id

class ExcelFile(models.Model):
    file = models.FileField(upload_to='uploads/')
    uploaded_by = models.ForeignKey(Doctor, on_delete=models.CASCADE)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    is_published = models.BooleanField(default=False)

class ExcelAccess(models.Model):
    doctor = models.ForeignKey(Doctor, on_delete=models.CASCADE)
    excel_file = models.ForeignKey(ExcelFile, on_delete=models.CASCADE)
    allowed_columns = models.JSONField(default=list)
    class Meta:
        unique_together = ('doctor', 'excel_file')

from django.utils import timezone
class AuditLog(models.Model):
    doctor = models.ForeignKey(Doctor, on_delete=models.CASCADE)
    query = models.CharField(max_length=255)
    searched_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.doctor.doctor_id} searched '{self.query}' at {self.searched_at}"
