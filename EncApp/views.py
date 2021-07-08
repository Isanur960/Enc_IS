from django.shortcuts import render, HttpResponse
from EncApp import classes
from EncApp.models import tempfiles , CustomVal
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken
import sys


# Create your views here.



# .........FUNCTIONS........

#file handler which is not in use ...
"""
def handle_uploaded_file(f):
    with open('name.txt', 'wb+') as destination:
        for chunk in f.chunks():
            destination.write(chunk)
"""

def FileNameWithoutExt(f):
    in_fn = str(f)
    l = len(in_fn)
    n = -1
    f_ext = ''
    while True:
        letter = in_fn[n]
        if letter == '.':
            break
        f_ext = f_ext + letter
        n = n - 1
    f_w_ext = ''
    n1 = 0
    while n1 < l + n:
        letter = in_fn[n1]
        f_w_ext = f_w_ext + letter
        n1 = n1 + 1
    return f_w_ext



def FileExtRev(f):
    in_fn = str(f)
    l = len(in_fn)
    n = -1
    f_ext = ''
    while True:
        letter = in_fn[n]
        if letter == '.':
            break
        f_ext = f_ext + letter
        n = n - 1
    return f_ext

def StringRev(stt):
    st = str(stt)
    l = len(st)
    n = -1
    f_ext = ''
    pos_n = 0
    while True:
        letter = st[n]
        f_ext = f_ext + letter
        if pos_n == l:
            break
        n = n - 1
        pos_n = n * (- 1)
    return f_ext

def FileExt(f):
    ext = StringRev(FileExtRev(f))
    return ext

def EncFileNameGen(f, key):
    ext = FileExt(f)
    new_f_name = str(key) + '.' + ext + '.enc_is'
    return new_f_name





def pwdtokey(in_pwd):
    #print(in_pwd)
    password = in_pwd.encode()  # Converting to type bytes
    salt = b'salt_' 
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    genrtd_key = base64.urlsafe_b64encode(kdf.derive(password))
    #print(genrtd_key)
    return genrtd_key


def encrypt(in_f, key):
    #print(key, 'enc1 ok...')
    key = key
    #data = in_f
    #input_file = in_f
    #f = open(in_f, 'r+b')
    #print('opening done....')
    data = in_f.read()  # Reading the bytes of the input file
    #print('reading done....')
    fernet = Fernet(key)
    #print('key ok....')
    encrypted = fernet.encrypt(data)
    #print('enc2 ok....')
    return encrypted

def decrypt(in_f, key):
    data = in_f.read()  # Read the bytes of the encrypted file

    fernet = Fernet(key)
    try:
        decrypted = fernet.decrypt(data)
        return decrypted
    except InvalidToken as e:
        return 0



#.........views.........


def index(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')

    context = {
        'ip': ip
    }
    return render(request, 'index.html', context)


def privacy(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')

    context = {
        'ip': ip
    }
    return render(request, 'privacy_policy.html', context)

def encryption(request):
    #print(request.method)
    MaxFS_obj =  CustomVal.objects.get(ValName = 'MaxFileSize')
    MaxFS =  MaxFS_obj.val
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')

    if request.method == 'POST':
        csr = request.POST.get('csrfmiddlewaretoken')
        key = request.POST.get('in_key')
        try:
            Uploadedfiles = request.FILES
            #print("lets see---",Uploadedfiles)
            UPfiles = Uploadedfiles['myfile']
            file_size = UPfiles.size
            max_file_size = MaxFS*1024*1024
            #print(file_size)
            if file_size > max_file_size:
                return render(request , 'encryption.html' , {
                    'ip': ip,
                    'fi': "You forget to upload file",
                    'key': key,
                    'msg': "We are currently unable to take more than 10 MB due to limited processing time",
                })
            filename = str(UPfiles) + '.enc_is'
            if key == '':
                key = csr[:10]
                filename = EncFileNameGen(UPfiles, key)
            #handle_uploaded_file(UPfiles)
            #print('generating key....')
            final_key = pwdtokey(key)
            #print('key genrtd....')
            #print('encrypting files....')
            enc_f = encrypt(UPfiles, final_key)
            #print('file encrypted....')
            response = HttpResponse(enc_f, content_type='application/force-download')
            response['Content-Disposition'] = "attachment; filename=%s" % filename
            #print('response ok.........')
            context = {
                'ip': ip,
                'fi': UPfiles,
                'key': key,
                'msg': "SUCCESS...... FILE WILL BE DOWNLOADED SOON",
                }
            return response

        except:
            if key == '':
                key = request.POST.get('csrfmiddlewaretoken')
            context = {
                'ip': ip,
                'fi': "You forget to upload file",
                'key': key,
                'msg': "FAILED",
                }
            return render(request , 'encryption.html' , context)
    else:
        context = {
            'ip': ip,
            'fi': "no file uploaded",
            'key': "no key is given or generated",
            'msg': "Upload your file",
            }
        return render(request , 'encryption.html' , context)



def decryption(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')

    if request.method == 'POST':
        key = request.POST.get('in_key_d')
        try:
            Uploadedfiles = request.FILES
            #print("lets see---",Uploadedfiles)
            UPfiles = Uploadedfiles['myfile_d']
            #print(type(UPfiles))
            UploadedFileName = str(UPfiles)
            print(UploadedFileName)
            filename = FileNameWithoutExt(UploadedFileName)
            if key == '':
                key = FileNameWithoutExt(FileNameWithoutExt(UploadedFileName))
                filename = FileNameWithoutExt(UploadedFileName)
            #handle_uploaded_file(UPfiles)
            print('generating key....')
            final_key = pwdtokey(key)
            print('key genrtd....')
            print('decrypting files....')
            enc_f = decrypt(UPfiles, final_key)
            print('file decrypted....')
            response = HttpResponse(enc_f, content_type='application/force-download')
            response['Content-Disposition'] = "attachment; filename=%s" % filename
            print('response ok.........')
            context = {
                'ip': ip,
                'fi': UPfiles,
                'key': key,
                'msg': "SUCCESS...... FILE WILL BE DOWNLOADED SOON",
                }
            return response

        except:
            if key == '':
                key = request.POST.get('csrfmiddlewaretoken')

            final_key = pwdtokey(key)
            context = {
                'ip': ip,
                'fi': "You forget to upload file",
                'key': final_key,
                'msg': "FAILED",
                }
            return render(request , 'decryption.html' , context)
    else:
        context = {
            'ip': ip,
            'fi': "no file uploaded",
            'key': "no key is given or generated",
            'msg': "Upload your file",
            }
        return render(request , 'decryption.html' , context)

