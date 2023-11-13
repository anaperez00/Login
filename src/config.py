class Config:
    SECRET_KEY = 'B!1w8NAt1T^%kvhUI*S^'


class DevelopmentConfig(Config):
    DEBUG = True #iniciar el servidor en modo de depuración
    MYSQL_HOST = 'localhost'
    MYSQL_USER = 'root'
    MYSQL_PASSWORD = 'Apocalipsis'
    MYSQL_DB = 'flask_login'


config = {
    'development': DevelopmentConfig
}
