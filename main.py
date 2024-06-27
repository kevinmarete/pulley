import base64
import msgpack
import requests

from abc import ABC, abstractmethod


class Pulley:

    @classmethod
    def get_challenge(cls, input_param: str):
        request_url = f"https://ciphersprint.pulley.com/{input_param}"
        response = requests.get(request_url)
        return response.json() if response.status_code == 200 else None

    @classmethod
    def decrypt_path(cls, encrypted_path: str, encryption_method: str, level: str):
        encrypted_path = encrypted_path.replace("task_", "")
        decryption_method = DecryptionFactory.get_decryption_method(level)
        return decryption_method().decrypt(encrypted_path, encryption_method)

    @classmethod
    def get_param(cls, input_path: str or bytes):
        return f"task_{input_path.decode("utf-8") if isinstance(input_path, bytes) else input_path}"


class DecryptionMethod(ABC):
    @abstractmethod
    def decrypt(self, encryption_path: str, encryption_method: str):
        pass


class Nothing(DecryptionMethod):
    def decrypt(self, encryption_path: str, encryption_method: str):
        return encryption_path


class Base64(DecryptionMethod):
    def decrypt(self, encryption_path: str, encryption_method: str):
        return base64.b64decode(encryption_path)


class SwapEveryPairOfCharacters(DecryptionMethod):
    def decrypt(self, encryption_path: str, encryption_method: str):
        s = list(encryption_path)
        for i in range(0, len(s) - 1, 2):
            s[i], s[i + 1] = s[i + 1], s[i]

        return ''.join(s)


class CircularLeftRotate(DecryptionMethod):
    def decrypt(self, encryption_path: str, encryption_method: str):
        positions = int(encryption_method.split()[-1])
        return encryption_path[-positions % len(encryption_path):] + encryption_path[:-positions % len(encryption_path)]


class EncodeCustomHexChar(DecryptionMethod):
    def decrypt(self, encryption_path: str, encryption_method: str):
        custom_hex_set = encryption_method.split()[-1]

        hex_chars = '0123456789abcdef'
        hex_map = {custom_hex_set[i]: hex_chars[i] for i in range(len(hex_chars))}

        custom_encoded = ''.join(hex_map[char] for char in encryption_path)

        return custom_encoded


class ScrambledMsgPack(DecryptionMethod):
    def decrypt(self, encryption_path: str, encryption_method: str):
        message_pack = encryption_method.split(":")[-1].strip()
        decoded_message_pack = base64.b64decode(message_pack)

        positions = msgpack.unpackb(decoded_message_pack)
        scramble_map = {positions[i]: encryption_path[i] for i in range(len(positions))}
        sorted_scramble_map = dict(sorted(scramble_map.items()))

        return ''.join(list(sorted_scramble_map.values()))


class DecryptionFactory:
    @staticmethod
    def get_decryption_method(level: str):
        methods = {
            "0": Nothing,
            "1": Base64,
            "2": SwapEveryPairOfCharacters,
            "3": CircularLeftRotate,
            "4": EncodeCustomHexChar,
            "5": ScrambledMsgPack,
            "6": Nothing,
        }
        return methods.get(str(level))


if __name__ == "__main__":
    param = "kevinmmarete@gmail.com"

    while param:
        challenge = Pulley.get_challenge(param)

        if not challenge:
            break

        print("Challenge:", challenge)
        path = Pulley.decrypt_path(challenge["encrypted_path"], challenge["encryption_method"], challenge["level"])
        param = Pulley.get_param(path)
        print("Decrypted Path:", param)
