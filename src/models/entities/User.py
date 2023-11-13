from werkzeug.security import check_password_hash# para comprobar mediante esta funcion el hash con el pasword a ver si coinciden o no

#from werkzeug.security import generate_password_hash #crea un hash
from flask_login import UserMixin

class User(UserMixin):
    # esta clase es un reflejo de la bd
    def __init__(self, id, username, password, fullname="") -> None:
        self.id = id
        self.username = username
        self.password = password
        self.fullname = fullname

    @classmethod #hashed_password es el dato que va a ser guardado en la bd y el password en texto plano
    def check_password(self, hashed_password, password):
        return check_password_hash(hashed_password, password)# retorno lo que me devuelva la funcion check passoword hash  pasandole los dos valores
    
#print (generate_password_hash("holamundo"))
#Yacasisiu-2023
#scrypt:32768:8:1$Or0kMxZkmBaZCHzn$5ac705cb6053ce539a76a45b2c78ff65ff4f2dfee4757b604816a67f617257005bb22f04ad64b7c62acfb3f9bfdccdf7e44992a990e238fc5beaab807acae900
#holamundo
#scrypt:32768:8:1$TjC50CbfC6Achnwe$4c3e8e2f46abd8f6e8b4c091a33b17471b0ef9b9e59eacdc8ec65f941cb3ce205d326ef7c8e5e5c03aef9621faac699ba96943f35f9f178b1006a2e0f88b2b95