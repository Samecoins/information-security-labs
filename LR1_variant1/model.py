import calendar
import copy
import hmac
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path

MAGIC = b'IBLR1V1\x00'
ARITHMETIC = '+-*/='


def now():
    return datetime.now(timezone.utc)


def new_user(crypto):
    return dict(password_hash=crypto.digest(''), initialized=False,
                blocked=False, restricted=False, min_length=0,
                months=0, changed_at=None)


def password_error(password, user):
    if len(password) < user['min_length']:
        return f"Минимальная длина: {user['min_length']} символов."
    if user['restricted'] and not (
        any(c.islower() for c in password)
        and any(c.isupper() for c in password)
        and any(c in ARITHMETIC for c in password)
    ):
        return 'Нужны строчная буква, прописная буква и знак из + - * / =.'
    return None


def expires_at(user):
    if not user['months'] or not user['changed_at']:
        return None
    start = datetime.fromisoformat(user['changed_at'])
    month_index = start.year * 12 + start.month - 1 + user['months']
    year, month = divmod(month_index, 12)
    month += 1
    day = min(start.day, calendar.monthrange(year, month)[1])
    return start.replace(year=year, month=month, day=day)


def expired(user, moment=None):
    limit = expires_at(user)
    return limit is not None and (moment or now()) >= limit


def validate(data):
    if not isinstance(data, dict) or data.get('version') != 1:
        raise ValueError('Некорректная версия базы.')
    users = data.get('users')
    if not isinstance(users, dict) or 'ADMIN' not in users or users['ADMIN'].get('blocked'):
        raise ValueError('Не найдена действующая запись ADMIN.')
    for name, u in users.items():
        if not isinstance(name, str) or not name or not isinstance(u, dict):
            raise ValueError('Некорректная учётная запись.')
        if not re.fullmatch(r'[0-9a-f]{32}', u.get('password_hash', '')):
            raise ValueError('Некорректный хеш.')
        for key in ('initialized', 'blocked', 'restricted'):
            if type(u.get(key)) is not bool:
                raise ValueError('Некорректный флаг.')
        for key, upper in (('min_length', 1024), ('months', 1200)):
            if type(u.get(key)) is not int or not 0 <= u[key] <= upper:
                raise ValueError('Некорректный параметр.')
        if u['initialized']:
            stamp = datetime.fromisoformat(u['changed_at'])
            if stamp.tzinfo is None:
                raise ValueError('Некорректная дата.')
            expires_at(u)


class Store:
    def __init__(self, path, crypto, phrase):
        self.path, self.crypto, self.phrase = Path(path), crypto, phrase
        self.data = None

    @property
    def users(self):
        return self.data['users']

    def open(self):
        if not self.path.exists():
            self.data = {'version': 1, 'users': {'ADMIN': new_user(self.crypto)}}
            self.save()
            return
        blob = self.path.read_bytes()
        if not blob.startswith(MAGIC) or len(blob) < 32 or (len(blob) - 24) % 8:
            raise ValueError('Повреждён заголовок файла учётных записей.')
        try:
            raw = self.crypto.transform(blob[24:], self.phrase, blob[8:24], False)
            data = json.loads(raw.decode('utf-8'))
            validate(data)
        except (ValueError, OSError, TypeError, KeyError, AttributeError, OverflowError) as exc:
            raise ValueError('Неверная парольная фраза или повреждён файл учётных записей.') from exc
        self.data = data

    def save(self):
        validate(self.data)
        salt = self.crypto.random(16)
        raw = json.dumps(self.data, ensure_ascii=False).encode('utf-8')
        blob = MAGIC + salt + self.crypto.transform(raw, self.phrase, salt, True)
        # На диск попадает только шифротекст. Атомарная замена предотвращает
        # частичную перезапись исходного файла при сбое записи.
        fd, temporary = tempfile.mkstemp(prefix='.accounts-', suffix='.tmp',
                                          dir=self.path.parent)
        try:
            with os.fdopen(fd, 'wb') as f:
                f.write(blob)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temporary, self.path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def commit(self, mutation):
        old = copy.deepcopy(self.data)
        try:
            mutation()
            self.save()
        except Exception:
            self.data = old
            raise


class Session:
    def __init__(self, store):
        self.store, self.name, self.failures = store, None, 0

    def login(self, name, password):
        if self.failures >= 3:
            return 'locked'
        user = self.store.users.get(name)
        if user is None:
            return 'unknown'
        if user['blocked']:
            return 'blocked'
        if not hmac.compare_digest(self.store.crypto.digest(password), user['password_hash']):
            self.failures += 1
            return 'locked' if self.failures >= 3 else 'wrong'
        self.name = name
        return 'first' if not user['initialized'] else 'expired' if expired(user) else 'ok'

    def require_admin(self):
        if self.name != 'ADMIN':
            raise PermissionError('Действие доступно только администратору.')

    def add_user(self, name):
        self.require_admin()
        name = name.strip()
        if not name or len(name) > 64 or any(ord(c) < 32 for c in name):
            raise ValueError('Имя должно содержать от 1 до 64 печатных символов.')
        if name in self.store.users:
            raise ValueError('Пользователь с таким именем уже существует.')
        self.store.commit(lambda: self.store.users.update({name: new_user(self.store.crypto)}))

    def set_policy(self, name, blocked, restricted, length, months):
        self.require_admin()
        if name == 'ADMIN' and blocked:
            raise ValueError('Блокировка ADMIN запрещена.')
        if not 0 <= length <= 1024 or not 0 <= months <= 1200:
            raise ValueError('Длина: 0–1024. Срок: 0–1200 месяцев.')
        self.store.commit(lambda: self.store.users[name].update(
            blocked=blocked, restricted=restricted, min_length=length, months=months))

    def change_password(self, old, password, confirmation):
        if self.name is None:
            raise PermissionError('Сначала войдите.')
        u = self.store.users[self.name]
        if not hmac.compare_digest(self.store.crypto.digest(old), u['password_hash']):
            raise ValueError('Неверный старый пароль.')
        if password != confirmation:
            raise ValueError('Новый пароль и подтверждение не совпадают.')
        error = password_error(password, u)
        if error:
            raise ValueError(error)
        # При истечении срока нужно установить именно новый пароль.
        hashed = self.store.crypto.digest(password)
        if u['initialized'] and expired(u) and hmac.compare_digest(hashed, u['password_hash']):
            raise ValueError('Срок истёк: выберите другой пароль.')
        self.store.commit(lambda: u.update(password_hash=hashed, initialized=True,
                                          changed_at=now().isoformat()))
