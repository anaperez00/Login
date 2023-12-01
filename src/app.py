from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager, login_user, logout_user, login_required
from datetime import datetime, timedelta 
import pytz
import time
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, IntegerField
from wtforms.validators import DataRequired

from matplotlib import pyplot as plt
import io
import base64
import unicodedata
#---------
#from flask import Flask, redirect, request
#-----

# Models:
from models.ModelUser import ModelUser

# Entities:
from models.entities.User import User
from config import config

app = Flask(__name__)
csrf = CSRFProtect(app)

def validar_texto(texto):
    valid_chars = "ABCDEFGHIJKLMNÑOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz "
    return all(c in valid_chars for c in texto) and len(texto) >= 90

valor_letra = {
    'A': 0, 
    'B': 1, 
    'C': 2, 
    'D': 3, 
    'E': 4,
    'F': 5, 
    'G': 6, 
    'H': 7, 
    'I': 8, 
    'J': 9,
    'K': 10, 
    'L': 11, 
    'M': 12, 
    'N': 13, 
    'Ñ': 14,
    'O': 15, 
    'P': 16,   
    'Q': 17, 
    'R': 18, 
    'S': 19,
    'T': 20,   
    'U': 21, 
    'V': 22, 
    'W': 23, 
    'X': 24,
    'Y': 25, 
    'Z': 26
}
valor_letraC = {
    'A': 0, 
    'B': 1, 
    'C': 2, 
    'D': 3, 
    'E': 4,
    'F': 5, 
    'G': 6, 
    'H': 7, 
    'I': 8, 
    'J': 9,
    'K': 10, 
    'L': 11, 
    'M': 12, 
    'N': 13, 
    'Ñ': 14,
    'O': 15, 
    'P': 16,   
    'Q': 17, 
    'R': 18, 
    'S': 19,
    'T': 20,   
    'U': 21, 
    'V': 22, 
    'W': 23, 
    'X': 24,
    'Y': 25, 
    'Z': 26,
    ' ': 27
}

def asignar_valores(texto):
    valores = [valor_letra[char] for char in texto]
    return valores

def asignar_valoresCifrado(texto):
    # Diccionario para asignar valores a letras
    valor_letra = {
        'A': 0, 
        'B': 1, 
        'C': 2, 
        'D': 3, 
        'E': 4,
        'F': 5, 
        'G': 6, 
        'H': 7, 
        'I': 8, 
        'J': 9,
        'K': 10, 
        'L': 11, 
        'M': 12, 
        'N': 13, 
        'Ñ': 14,
        'O': 15, 
        'P': 16,   
        'Q': 17, 
        'R': 18, 
        'S': 19,
        'T': 20,   
        'U': 21, 
        'V': 22, 
        'W': 23, 
        'X': 24,
        'Y': 25, 
        'Z': 26,
        ' ': 27
    }
    
    valores = [valor_letra[char] for char in texto]
    return valores

def contar_caracteres(texto):
    contador = {}
    total_caracteres = len(texto)

    for char in texto:
        if char in contador:
            contador[char] += 1
        else:
            contador[char] = 1

    return contador

def calcular_inversa_modulo27(valor):
    for inversa in range(27):
        if (valor * inversa) % 27 == 1:
            return inversa
    return None

def limpiar_texto(texto):
    texto = texto.replace('\r', '').replace('\n', '')

    # Remover caracteres especiales y números, excepto la 'Ñ'
    caracteres_especiales = '''!"#$%&'()*+,-./0123456789:;<=>?@[\]^_`{|}~'''
    caracteres_no_remover = ['ñ']  # Lista de caracteres que no se eliminarán
    texto_limpio = ''.join([char for char in texto if char not in caracteres_especiales or char in caracteres_no_remover])
    
    return texto_limpio.upper() 
def asignar_letra(valor):
    for letra, val in valor_letra.items():
        if val == valor:
            return letra
    return ''

csrf = CSRFProtect()
db = MySQL(app)#en esta variable tengo la conexion con la bd
login_manager_app = LoginManager(app)


@login_manager_app.user_loader
def load_user(id):
    return ModelUser.get_by_id(db, id)


@app.route('/')# se encarga de redirigirme hacia la respuesta que nos da la vista login 
def index():
    # redirecciona a la vista login 
    # como  esta accedida desde el metodo get, va a acceder desde el else de login()
    # cuando el formulario sea enviado ahi si vamos a acceder al if de login() con el metodo POST
    return redirect(url_for('login'))

# ...



@app.route('/login', methods=['GET', 'POST'])
def login():
    # Verificamos si la solicitud es una solicitud POST (enviada desde un formulario).
    if request.method == 'POST':
        # Comprobamos si ya hay un contador de intentos de inicio de sesión en la sesión.
        if 'login_attempts' in session:
            login_attempts = session['login_attempts']
        else:
            login_attempts = 0

        now = time.time()

        # Verificar si ha pasado el período de bloqueo anterior.
        if 'last_login_attempt' in session:
            last_attempt_time = session['last_login_attempt']
            if now - last_attempt_time < 10 * (login_attempts - 2):
                # Calcular el tiempo de bloqueo escalonado.
                time_remaining = int(10 * (login_attempts - 2) - (now - last_attempt_time))
                flash(f'Intentos de inicio de sesión bloqueados durante {time_remaining} segundos.')
                return render_template('auth/login.html')

        # Intentamos iniciar sesión con las credenciales proporcionadas por el usuario.
        username = request.form['username']
        password = request.form['password']
        usuario = User(0, username, password)

        # Imprimir credenciales inválidas y hora en la consola.
        print(f'Intento de inicio de sesión con credenciales inválidas: Usuario={username}, Contraseña={password}, Hora={time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(now))}')

        usuario_logueado = ModelUser.login(db, usuario)

        if usuario_logueado is not None and usuario_logueado.password:
            # Si las credenciales son válidas, el usuario ha iniciado sesión con éxito.
            login_user(usuario_logueado)
            session.pop('last_login_attempt', None)  # Eliminar la marca de tiempo del último intento fallido.
            session.pop('login_attempts', None)  # Restablecer los intentos fallidos.
            return redirect(url_for('seguridad'))
        else:
            # Si las credenciales son incorrectas, se registra un intento fallido.
            session['last_login_attempt'] = now  # Registrar la hora del intento fallido.
            login_attempts += 1  # Aumentar el contador de intentos fallidos.
            session['login_attempts'] = login_attempts  # Almacenar el contador en la sesión.

            if login_attempts >= 3:
                # Calcular el tiempo de bloqueo escalonado.
                block_time = 10 * (login_attempts - 2)
                flash(f'Demasiados intentos fallidos. Su cuenta está bloqueada durante {block_time} segundos.')

            else:
                flash("Usuario o contraseña no válidos.")

            return render_template('auth/login.html')
    else:
        # Si la solicitud no es POST, se muestra la página de inicio de sesión.
        return render_template('auth/login.html')

# ...
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))
    
    
@app.route("/descifrar", methods=['POST'])
@login_required
def descifrar():
    texto_cifrado = request.form['textocifrado'] 


    texto_cifrado = texto_cifrado.upper()
    resultados = []  # Lista para almacenar los resultados
    resultados2 = []
    
    if validar_texto(texto_cifrado):
        texto_sin_espacios = texto_cifrado.replace(" ", "")
        valores = asignar_valores(texto_sin_espacios)
        valores2 = asignar_valores(texto_sin_espacios)
        valores3= asignar_valores(texto_sin_espacios)
        valores4= asignar_valores(texto_sin_espacios)
        conteo_caracteres = contar_caracteres(texto_sin_espacios)

        for char, count in conteo_caracteres.items():
            porcentaje = (count / len(texto_sin_espacios)) * 100
            valor = valores[ord(char) - ord('A')]
            resultados.append((char, count, porcentaje, valor))  
            # Agregar resultados a la lista

        resultados.sort(key=lambda x: x[1], reverse=False) # Ordenar en función de la cantidad de repeticiones en orden descendente

        variable_mejor = max(valores, key=valores.count)
        valores_sin_mejor = sorted(set(valores), key=valores.count, reverse=True)
        variable_b = valores_sin_mejor[1]
        consE = valor_letra["E"]
        consA = valor_letra["A"]
        valores_del_texto = valores
        resta = variable_mejor - variable_b
        inversa_consE = calcular_inversa_modulo27(consE)
        mul = resta * inversa_consE
        a = mul % 27
        inversaFinal = calcular_inversa_modulo27(a)
        
        variable_mejor2 = valores_sin_mejor[1]
        variable_b2 = max(valores, key=valores.count)
        resta2 = variable_mejor2-variable_b2
        valores_del_texto2 = valores2
        inversa_consE2= calcular_inversa_modulo27(consE)
        mul2 = resta2 * inversa_consE2
        a2= mul2 % 27
        inversaFinal2= calcular_inversa_modulo27(a2)

 

        for i in range(len(valores_del_texto)):
            valores_del_texto[i] = ((valores_del_texto[i] - variable_b) * calcular_inversa_modulo27(a)) % 27
            caracteres_asociados = [None] * len(valores_del_texto)

        for i in range(len(valores_del_texto2)):
            valores_del_texto2[i] = ((valores_del_texto2[i] - variable_b2) * calcular_inversa_modulo27(a2)) % 27
            caracteres_asociados2 = [None] * len(valores_del_texto2)
                

        for i, valor in enumerate(valores_del_texto):
            for char, val in valor_letra.items():
                if val == valor:
                    caracteres_asociados[i] = char
                    break

        for i, valor in enumerate(valores_del_texto2):
            for char, val in valor_letra.items():
                if val == valor:
                    caracteres_asociados2[i] = char
                    break



        resultado = {}
        output = f'el texto es valido{resultado}'
        constante = f'constantes y variables contanteE:{consE}, consA{consA}, variablemejor{variable_mejor}, variableb{variable_b}'
        etiquetas = [char for char, _, _, _ in resultados]
        # Crear una lista para las repeticiones de cada carácter
        repeticiones = [count for _, count, _, _ in resultados]

            # Generar el gráfico de barras
        plt.figure(figsize=(8, 6))
        plt.barh(etiquetas, repeticiones, color='skyblue')
        plt.xlabel('Repeticiones')
        plt.ylabel('Carácter')
        plt.title('Repeticiones de Caracteres en el Texto Cifrado')
        plt.tight_layout()

        # Convertir el gráfico a una imagen base64
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png')
        buffer.seek(0)
        imagen_base64 = base64.b64encode(buffer.read()).decode('utf-8')

    else: 
        output = "el texto es invalido"

    return render_template('index2.html', resultado=f'el textoes impresionantemente largo {output}', resultados=resultados, constante=constante, caracteres_asociados="".join(caracteres_asociados), caracteres_asociados2="".join(caracteres_asociados2),grafico=imagen_base64)

@app.route('/seguridad')
@login_required
def seguridad():
   return render_template('index2.html')

@app.route("/cifrar", methods=['POST','GET'])
@login_required
def cifrar():
    texto_claro = request.form['textoclaro']
    texto_procesado = limpiar_texto(texto_claro)
    decimacionA = int(request.form['decimacionA'])  # Convertir a entero
    desplazamientoB = int(request.form['desplazamientoB'])  # Convertir a entero
   
    texto_valores = asignar_valoresCifrado(texto_procesado)

    # Realizar la operación de multiplicación por decimacionA a los elementos numéricos de texto_valores    
    operacion = [val if val == 27 else (val * decimacionA + desplazamientoB) % 27 for val in texto_valores]       
    texto_letras = [list(valor_letraC.keys())[list(valor_letraC.values()).index(valor)] if valor in valor_letraC.values() else valor for valor in operacion]
    texto_cifrado = ''.join(map(str, texto_letras))
    return render_template('index2.html',texto_valores_procesados=texto_cifrado)

def status_401(error):
    return redirect(url_for('login'))


def status_404(error):
    return "<h1>Página no encontrada</h1>", 404
#----------------------
#@app.before_request
#def before_request():
 #   if not request.is_secure and request.headers.get('X-Forwarded-Proto', 'http') != 'https':
  #      url = request.url.replace('http://', 'https://', 1)
   #     return redirect(url, code=301)
#------------------------
if __name__ == '__main__':
    app.config.from_object(config['development'])
    csrf.init_app(app)
    app.register_error_handler(401, status_401)
    app.register_error_handler(404, status_404)
    #app.run(ssl_context=('/etc/ssl/certs/certi.crt', '/etc/ssl/private/certi.key'))
  #  app.run(host='127.0.0.1', port=80)
   # app.run(host="0.0.0.0" , port=80, ssl_context=('/etc/ssl/certs/certi.crt', '/etc/ssl/private/certi.key'))
    #app.run()
    app.run(host="0.0.0.0", port=443, ssl_context=('/etc/ssl/certs/certi.crt', '/etc/ssl/private/certi.key'))
    #app.run(host="0.0.0.0", port=443, ssl_context=('/etc/letsencrypt/live/perez-ana.tech/fullchain.pem', '/etc/letsencrypt/live/perez-ana.tech/privkey.pem'))