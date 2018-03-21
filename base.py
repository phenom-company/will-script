import smtplib
import time
import settings
import json
from Crypto.Cipher import DES3
from passlib.hash import pbkdf2_sha256


class Des():

    @classmethod
    def _make_des3_encryptor(cls, key, iv=None):
        if iv is None:
            iv = key[:8]
        encryptor = DES3.new(key, DES3.MODE_CBC, iv)
        return encryptor

    @classmethod
    def des3_encrypt(cls, key, data_, iv=None):
        if isinstance(data_, str):
            data = str.encode(data_)
        else:
            data = data_
        encryptor = cls._make_des3_encryptor(key, iv)
        pad_len = 8 - len(data) % 8
        padding = chr(pad_len) * pad_len
        data += str.encode(padding)
        return encryptor.encrypt(data)

    @classmethod
    def des3_decrypt(cls, key, data, iv=None):
        encryptor = cls._make_des3_encryptor(key, iv)
        result = encryptor.decrypt(data)
        if isinstance(result[-1], str):
            pad_len = ord(result[-1])
        else:
            pad_len = result[-1]
        result = result[:-pad_len]
        return result


class ConfifHandler():

    def __init__(self, super_secret_key, super_secret_message):
        self.super_secret_key = super_secret_key
        self.super_secret_message = super_secret_message

    def encode_config(self, config):
        config.update({'validate_message': self.super_secret_message})
        return Des.des3_encrypt(self.super_secret_key, json.dumps(config))

    def decode_config(self, config):
        decode = Des.des3_decrypt(str.encode(self.super_secret_key), config)
        config = json.loads(decode)
        assert config['validate_message'] == self.super_secret_message, 'Bad condig'
        return config


class Will():
    def __init__(self, path_to_config, path_to_message, secret_key, secret_message,
                 delay_factory, mail_user, mail_password):
        self.path_to_config = path_to_config
        self.path_to_message = path_to_message
        self.secret_key = secret_key
        self.secret_message = secret_message
        self.delay_factory = delay_factory
        self.mail_user = mail_user
        self.mail_password = mail_password
        self.config_handler = ConfifHandler(self.secret_key, self.secret_message)
        self.debug = True

    def initialize(self):
        # TODO check pass len
        # TODO validate config
        with open(self.path_to_config, 'r') as f:
            config = json.loads(f.read())
        encode_key = config.pop('encode_key')
        self.import_message(self.path_to_message, encode_key)
        input_password = config.pop('input_password')
        config.update({'input_hash': pbkdf2_sha256.hash(input_password)})
        config.update({'time': time.time()})
        encode_config = self.config_handler.encode_config(config)
        if self.debug:
            path_to_config = self.path_to_config + '_debug'
        with open(path_to_config, 'wb') as f:
            f.write(encode_config)

    def import_message(self, path, user_key, static_key=settings.SUPER_SECRET_KEY):
        with open(path, 'r') as f:
            text = f.read()
        encode_text = self.encode_msg_by_user_key(text, str.encode(user_key))
        encode_text_ = self.encode_msg_by_key(encode_text, str.encode(static_key))
        if self.debug:
            path += '_debug'
        with open(path, 'wb') as f:
            f.write(encode_text_)

    @classmethod
    def encode_msg_by_user_key(cls, msg, password):
        return Des.des3_encrypt(password, msg)

    @classmethod
    def encode_msg_by_key(cls, msg, key=settings.SUPER_SECRET_KEY):
        output = {'message': msg.hex(), 'validate_message': settings.SUPER_SECRET_MESSAGE}
        return Des.des3_encrypt(key, json.dumps(output))

    def check_timeout(self):
        with open(self.path_to_config, 'rb') as f:
            config = f.read()
        config = self.config_handler.decode_config(config)
        if time.time() - config['time'] < config['time_delay'] * 24 * 60 * 60:
            with open(self.path_to_message, 'rb') as f:
                message = f.read()
                message = self.config_handler.decode_config(message)
            self._send_mail(self.mail_user, self.mail_password, config['to'], message['message'], config['subject'])

    def update_time(self):
        password = input("Enter password:\n")
        with open(self.path_to_config, 'rb') as f:
            config = f.read()
        config = self.config_handler.decode_config(config)
        if pbkdf2_sha256.verify(password, config['input_hash']):
            config.update({'time': time.time()})
            config = self.config_handler.encode_config(config)
            with open(self.path_to_config, 'wb') as f:
                f.write(config)
            print('OK!')
        else:
            print('WRONG PASSWORD')


    def _send_mail(self, user, password, to, body, subject):
        if to is str:
            to = [to]
        if to is not list:
            #TODO Exception
            print('Wrong email')

        email_text = """\  
        From: %s  
        To: %s  
        Subject: %s

        %s
        """ % (user, ", ".join(to), subject, body)

        try:
            server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
            server.ehlo()
            server.login(user, password)
            server.sendmail(user, to, email_text)
            server.close()
            print('Email sent!')
        except Exception as e:
            print(e)
            print('Something went wrong...')
