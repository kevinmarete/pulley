import base64
import msgpack
import unittest

from main import Pulley, DecryptionFactory, Nothing, Base64, SwapEveryPairOfCharacters, CircularLeftRotate, \
    EncodeCustomHexChar, ScrambledMsgPack
from unittest.mock import patch, MagicMock


class TestPulley(unittest.TestCase):

    @patch('requests.get')
    def test_get_challenge(self, mock_get):
        # Setup mock response
        mock_response = MagicMock()
        expected_json = {'encrypted_path': 'encrypted', 'encryption_method': 'method', 'level': '1'}
        mock_response.json.return_value = expected_json
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        result = Pulley.get_challenge('test_input')
        self.assertEqual(result, expected_json)

    def test_get_challenge_failure(self):
        with patch('requests.get') as mock_get:
            mock_get.return_value.status_code = 404

            result = Pulley.get_challenge('test_input')
            self.assertIsNone(result)

    def test_decrypt_path(self):
        with patch.object(DecryptionFactory, 'get_decryption_method') as mock_get_method:
            mock_method_instance = MagicMock()
            mock_method_instance.decrypt.return_value = 'decrypted_path'
            mock_get_method.return_value = lambda: mock_method_instance

            result = Pulley.decrypt_path('task_encrypted_path', 'method', '1')
            self.assertEqual(result, 'decrypted_path')

    def test_get_param(self):
        result = Pulley.get_param('test_path')
        self.assertEqual(result, 'task_test_path')

        result = Pulley.get_param(b'test_path')
        self.assertEqual(result, 'task_test_path')


class TestDecryptionMethods(unittest.TestCase):

    def test_nothing_decryption(self):
        decryption_method = Nothing()
        result = decryption_method.decrypt('encrypted', 'method')
        self.assertEqual(result, 'encrypted')

    def test_base64_decryption(self):
        decryption_method = Base64()
        encrypted = base64.b64encode(b'plaintext').decode('utf-8')
        result = decryption_method.decrypt(encrypted, 'method')
        self.assertEqual(result, b'plaintext')

    def test_swap_every_pair_decryption(self):
        decryption_method = SwapEveryPairOfCharacters()
        result = decryption_method.decrypt('badcfe', 'method')
        self.assertEqual(result, 'abcdef')

    def test_circular_left_rotate_decryption(self):
        decryption_method = CircularLeftRotate()
        result = decryption_method.decrypt('abcdef', 'rotate 2')
        self.assertEqual(result, 'efabcd')

    def test_encode_custom_hex_char_decryption(self):
        decryption_method = EncodeCustomHexChar()
        result = decryption_method.decrypt('f3e1', 'hex f3e1b2c4d5a67890')
        self.assertEqual(result, '0123')

    def test_scrambled_msgpack_decryption(self):
        decryption_method = ScrambledMsgPack()
        encryption_path = 'ecdnopm'
        positions = [4, 1, 5, 0, 3, 6, 2]
        packed_positions = base64.b64encode(msgpack.packb(positions)).decode('utf-8')
        encryption_method = f'msgpack: {packed_positions}'
        result = decryption_method.decrypt(encryption_path, encryption_method)
        self.assertEqual(result, 'ncmoedp')


class TestDecryptionFactory(unittest.TestCase):

    def test_get_decryption_method(self):
        self.assertIsInstance(DecryptionFactory.get_decryption_method('0')(), Nothing)
        self.assertIsInstance(DecryptionFactory.get_decryption_method('1')(), Base64)
        self.assertIsInstance(DecryptionFactory.get_decryption_method('2')(), SwapEveryPairOfCharacters)
        self.assertIsInstance(DecryptionFactory.get_decryption_method('3')(), CircularLeftRotate)
        self.assertIsInstance(DecryptionFactory.get_decryption_method('4')(), EncodeCustomHexChar)
        self.assertIsInstance(DecryptionFactory.get_decryption_method('5')(), ScrambledMsgPack)
        self.assertIsInstance(DecryptionFactory.get_decryption_method('6')(), Nothing)


if __name__ == '__main__':
    unittest.main()
