"""py -m unittest -v — логика и реальные криптографические тесты на Windows."""
import hashlib
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from model import Store, Session, new_user, password_error, expires_at, expired
from wincrypto import WindowsCrypto


class LogicCrypto:
    """Только заглушка для тестов правил. В программе не используется."""
    def digest(self, text):
        return hashlib.sha256(text.encode()).hexdigest()[:32]


class RulesTests(unittest.TestCase):
    def setUp(self):
        self.store = Store('unused', LogicCrypto(), 'test')
        self.store.data = {'version': 1, 'users': {'ADMIN': new_user(self.store.crypto)}}
        self.store.save = lambda: None
        self.session = Session(self.store)

    def test_variant_one(self):
        u = new_user(self.store.crypto)
        u['restricted'] = True
        for good in ('Aa+', 'Пароль+', 'aB*'):
            self.assertIsNone(password_error(good, u))
        for bad in ('abc+', 'ABC+', 'Aa1', '123+', ''):
            self.assertIsNotNone(password_error(bad, u))
        u.update(restricted=False, min_length=5)
        self.assertIsNotNone(password_error('Ab+', u))
        self.assertIsNone(password_error('abcde', u))

    def test_empty_password_first_login_and_confirmation(self):
        self.assertEqual(self.session.login('ADMIN', ''), 'first')
        with self.assertRaises(ValueError):
            self.session.change_password('', 'Aa+', 'Aa-')
        self.session.change_password('', '', '')
        self.assertTrue(self.store.users['ADMIN']['initialized'])
        self.assertEqual(self.session.login('ADMIN', ''), 'ok')

    def test_three_password_errors(self):
        self.assertEqual(self.session.login('absent', ''), 'unknown')
        self.assertEqual(self.session.failures, 0)
        self.assertEqual(self.session.login('ADMIN', 'bad'), 'wrong')
        self.assertEqual(self.session.login('ADMIN', 'bad'), 'wrong')
        self.assertEqual(self.session.login('ADMIN', 'bad'), 'locked')
        self.assertEqual(self.session.login('ADMIN', ''), 'locked')

    def test_roles_unique_names_and_blocking(self):
        with self.assertRaises(PermissionError):
            self.session.add_user('student')
        self.session.login('ADMIN', '')
        self.session.add_user('student')
        with self.assertRaises(ValueError):
            self.session.add_user('student')
        self.session.set_policy('student', True, True, 8, 1)
        self.assertEqual(Session(self.store).login('student', ''), 'blocked')
        with self.assertRaises(ValueError):
            self.session.set_policy('ADMIN', True, False, 0, 0)
        self.session.set_policy('student', False, True, 8, 1)
        student = Session(self.store)
        self.assertEqual(student.login('student', ''), 'first')
        with self.assertRaises(PermissionError):
            student.add_user('another')
        with self.assertRaises(PermissionError):
            student.set_policy('student', False, False, 0, 0)
        with self.assertRaises(ValueError):
            student.change_password('', 'short', 'short')
        student.change_password('', 'Student+1', 'Student+1')
        with self.assertRaises(ValueError):
            student.change_password('bad', 'Student+2', 'Student+2')

    def test_calendar_months(self):
        u = new_user(self.store.crypto)
        u.update(months=1, changed_at='2024-01-31T12:00:00+00:00')
        self.assertEqual(expires_at(u).isoformat(), '2024-02-29T12:00:00+00:00')
        self.assertFalse(expired(u, datetime(2024, 2, 29, 11, tzinfo=timezone.utc)))
        self.assertTrue(expired(u, datetime(2024, 2, 29, 12, tzinfo=timezone.utc)))
        u.update(months=0)
        self.assertIsNone(expires_at(u))

    def test_expiry_requires_different_password(self):
        self.session.login('ADMIN', '')
        self.session.change_password('', 'Admin+', 'Admin+')
        self.store.users['ADMIN'].update(months=1, changed_at='2020-01-01T00:00:00+00:00')
        self.assertEqual(self.session.login('ADMIN', 'Admin+'), 'expired')
        with self.assertRaises(ValueError):
            self.session.change_password('Admin+', 'Admin+', 'Admin+')
        self.session.change_password('Admin+', 'New+', 'New+')
        self.assertFalse(expired(self.store.users['ADMIN']))

    def test_failed_write_rolls_back(self):
        self.session.login('ADMIN', '')
        with patch.object(self.store, 'save', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                self.session.add_user('student')
        self.assertNotIn('student', self.store.users)


@unittest.skipUnless(os.name == 'nt', 'Реальный CryptoAPI доступен только на Windows')
class WindowsTests(unittest.TestCase):
    def setUp(self):
        self.crypto = WindowsCrypto()
        self.addCleanup(self.crypto.close)

    def test_md4_known_vectors(self):
        self.assertEqual(self.crypto.digest(''), '31d6cfe0d16ae931b73c59d7e0c089c0')
        self.assertEqual(self.crypto.digest('abc'), 'a448017aaf21d8525fc10ae87aa6729d')

    def test_des_roundtrip_and_ecb(self):
        salt = self.crypto.random()
        plain = b'12345678' * 2
        encrypted = self.crypto.transform(plain, 'Фраза+', salt, True)
        self.assertEqual(len(encrypted), 24)
        self.assertEqual(encrypted[:8], encrypted[8:16])  # Свойство ECB.
        self.assertEqual(self.crypto.transform(encrypted, 'Фраза+', salt, False), plain)
        other = self.crypto.transform(plain, 'Фраза+', self.crypto.random(), True)
        self.assertNotEqual(other, encrypted)

    def test_encrypted_store_and_wrong_phrase(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'accounts.dat'
            store = Store(path, self.crypto, 'phrase+')
            store.open()
            self.assertNotIn(b'password_hash', path.read_bytes())
            session = Session(store)
            session.login('ADMIN', '')
            session.change_password('', 'Admin+', 'Admin+')
            session.add_user('student')
            reloaded = Store(path, self.crypto, 'phrase+')
            reloaded.open()
            self.assertEqual(reloaded.data, store.data)
            self.assertEqual(Session(reloaded).login('ADMIN', 'Admin+'), 'ok')
            before = path.read_bytes()
            with self.assertRaises(ValueError):
                Store(path, self.crypto, 'wrong phrase').open()
            self.assertEqual(path.read_bytes(), before)
            with patch('model.os.replace', side_effect=OSError('write failure')):
                with self.assertRaises(OSError):
                    store.save()
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(list(Path(folder).iterdir()), [path])


if __name__ == '__main__':
    unittest.main()
