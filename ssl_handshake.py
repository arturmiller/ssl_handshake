import random
import json

import rsa
import caesar


class CertificateAuthority():
    def __init__(self):
        p = 17
        q = 19
        self.public_key, self.private_key = rsa.create_keys(p, q)
        self.name = 'Some Root CA'

    def check_server(self, certificate):
        print('CA: Check if server is credible')

        # Do background checks (E.g. valid name, adress ...)

        print('CA: The server is credible')
        return True

    def sign_certificate(self, certificate):
        if self.check_server(certificate):
            print('CA: Sign servers certificate')
            hash_value = rsa.calc_hash(json.dumps(certificate), self.public_key.N)
            return rsa.sign(hash_value, self.private_key)
        else:
            raise Exception('CA: Certificate could not be signed!')


class Server():
    def __init__(self, certificate_authority):
        self.certificate_authority = certificate_authority
        self.certificate = None
        self.signed_certificate = None
        self.domain_name = 'test.com'
        p = 19
        q = 23
        self.public_key, self.private_key = rsa.create_keys(p, q)

    def create_certificate(self):
        print('Server: Create certificate')
        self.certificate = {'domain_name': self.domain_name,
                            'valid_from': '01.01.2020',
                            'valid_to': '01.01.2025',
                            'public_key': self.public_key,
                            'company': 'Test Company',
                            'address': 'Testcountry, 12345 Testcity, Testroad 42',
                            'issuer': self.certificate_authority.name}

    def calc_master_secret(self, cipher):
        # Encrypt and decrypt is mathematically the same expression
        random_number = rsa.encrypt(cipher, self.private_key)
        print('Server: Decrypted random number: {}'.format(random_number))
        self.master_secret = random_number + 5
        print('Server: Calculate master secret: {}'.format(self.master_secret))

    def receive_encrypted_data(self, cipher):
        print('Server: Received data (cipher): {}'.format(cipher))
        decrypted = caesar.decrypt_bytes(cipher, server.master_secret).decode('ascii')
        print('Server: Decrypted data: {}'.format(decrypted))

    def receive_random_number(self, cipher):
        print('Server: Received random number (cipher): {}'.format(cipher))
        self.calc_master_secret(cipher)

    def send_certificate(self, client):
        print('Server: Send certificate')
        client.receive_certificate(self.certificate, self.signed_certificate)


class Client():
    def __init__(self, certificate_authority):
        self.certificate_authority = certificate_authority
        self.server_domain_name = None
        self.server_public_key = None
        self.master_secret = None

    def request_connection(self, server_domain_name, server):
        print('Client: Request connection to {}'.format(server_domain_name))
        self.server_domain_name = server_domain_name

    def check_certificate(self):
        print('Client: Check certificate')
        print('Client: Certificate: {}'.format(json.dumps(self.server_certificate)))
        hash_value = rsa.calc_hash(json.dumps(self.server_certificate), self.certificate_authority.public_key.N)
        print('Client: Certificate hash value: {}'.format(hash_value))
        is_signed = rsa.check_signed(hash_value, self.server_signed_certificate, self.certificate_authority.public_key)
        print('Client: Certificate is signed: {}'.format(is_signed))
        if not is_signed:
            return False
        if self.server_certificate['domain_name'] != self.server_domain_name:
            return False
        if self.server_certificate['issuer'] != self.certificate_authority.name:
            return False

        self.server_public_key = self.server_certificate['public_key']
        print('Client: Certificate is valid')
        return True

    def generate_random_number(self):
        random_number = random.randrange(0, 99)
        print('Client: Generate random number: {}'.format(random_number))
        return random_number

    def calc_master_secret(self, random_number):
        self.master_secret = random_number + 5
        print('Client: Calculate master secret: {}'.format(self.master_secret))

    def send_encrypted_data(self, data, server):
        print('Client: Send data (original): {}'.format(data))
        cipher = caesar.encrypt_bytes(data.encode('ascii'), client.master_secret)
        print('Client: Send encrypted data: {}'.format(cipher.decode('ascii')))
        server.receive_encrypted_data(cipher)

    def send_random_number(self, random_number, server):
        print('Client: Send random number (original): {}'.format(random_number))
        cipher = rsa.encrypt(random_number, self.server_public_key)
        print('Client: Send encrypted random number: {}'.format(cipher))
        server.receive_random_number(cipher)

    def receive_certificate(self, certificate, signed_certificate):
        print('Client: Receive certificate')
        self.server_certificate = certificate
        self.server_signed_certificate = signed_certificate


certificate_authority = CertificateAuthority()
server = Server(certificate_authority)
client = Client(certificate_authority)


def sign_certificate():
    print('------------ Create and sign the server certificate ------------')
    server.create_certificate()
    server.signed_certificate = certificate_authority.sign_certificate(server.certificate)
    print()


def ssl_handshake():
    print('------------ Perform a SSL handshake ------------')
    client.request_connection('test.com', server)
    # Client: Hello Server
    # Server: Hello Client
    server.send_certificate(client)
    if client.check_certificate():
        random_number = client.generate_random_number()
        client.calc_master_secret(random_number)
        client.send_random_number(random_number, server)
    else:
        raise Exception('Client: Certificate is not credible!')
    print()


def send_data():
    print('------------ Send encrypted data ------------')
    client.send_encrypted_data('Hello World', server)
    print()


if __name__ == '__main__':
    sign_certificate()
    ssl_handshake()
    send_data()
