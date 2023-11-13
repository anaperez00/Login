from .entities.User import User # importo la clase user
#aqui es para hacer la autenticación

class ModelUser():

    @classmethod
    def login(self, db, user):
        try:
            cursor = db.connection.cursor()# para interactuar con la bd 
            # las tres comillas son para manejarlo en dos renglones
            sql = """SELECT id, username, password, fullname FROM user 
                    WHERE username = '{}'""".format(user.username)# obtengo el username para sabe si el usuario existe en la bd
            cursor.execute(sql)# se ejecuta la sentencia que se tiene en esa variable
            row = cursor.fetchone()
            if row != None:# si tengo un usuario que existe
                # aqui obtengo un tupla de el sql anterior
                # User.check_password(row[2] verdadero o falso
                # si el valor de hash guardado en la bd coincide mediante la funcion chec_passowrod_hash
                #propia del paquete wwekzeug.security si el password coincide
                user = User(row[0], row[1], User.check_password(row[2], user.password), row[3])
                return user
            else:#si mo mando una exception
                return None
        except Exception as ex:
            raise Exception(ex)

    @classmethod
    def get_by_id(self, db, id):
        try:
            cursor = db.connection.cursor()
            sql = "SELECT id, username, fullname FROM user WHERE id = {}".format(id)
            cursor.execute(sql)
            row = cursor.fetchone()
            if row != None:
                return User(row[0], row[1], None, row[2])
            else:
                return None
        except Exception as ex:
            raise Exception(ex)
