import requests
from hashlib import md5, sha256


class Keenetic():

    def __init__(self, host, login, password):
        self.__session = requests.Session()
        self.__host = host
        self.authenticated = self.__auth(login, password)

    def __auth(self, login, password):
        response = self.get('/auth')
        if response.status_code == 401:
            realm = response.headers['X-NDM-Realm']
            password = md5(f'{login}:{realm}:{password}'.encode('utf-8'))
            password = response.headers['X-NDM-Challenge'] + password.hexdigest()
            password = sha256(password.encode('utf-8')).hexdigest()
            try:
                response = self.post('/auth', {'login': login, 'password': password})
                response.raise_for_status()
            except requests.exceptions as http_error:
                print(f'HTTP error occurred: {http_error}')
                return False
            except Exception as error:
                print(f'Other error occurred: {error}')
                return False
            return True
        else:
            return False

    def get(self, address, data_to_get={}):
        return self.__session.get(f'{self.__host}{address}', params=data_to_get)

    def post(self, address, data={}):
        return self.__session.post(f'{self.__host}{address}', json=data)

    def delete(self, address):
        return self.__session.delete(f'{self.__host}{address}')

