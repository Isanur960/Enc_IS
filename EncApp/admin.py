from django.contrib import admin
from EncApp.models import tempfiles, CustomVal

# Register your models here.
admin.site.register(tempfiles)
admin.site.register(CustomVal)

admin.site.site_header = ("Enc_IS Administration")
admin.site.site_title = ("Enc_IS Admin")