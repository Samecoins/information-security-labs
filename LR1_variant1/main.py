import os
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog

from model import Store, Session, expired
from wincrypto import WindowsCrypto

AUTHOR = 'Ашаханов Ахмад Илèsович, группа ПИбд-42'
DATA_PATH = Path(__file__).resolve().with_name('accounts.dat')


class Fields(simpledialog.Dialog):
    def __init__(self, parent, title, fields, note='', validate_values=None):
        self.fields, self.note, self.check = fields, note, validate_values
        self.inputs, self.result = {}, None
        super().__init__(parent, title)

    def body(self, frame):
        row = 0
        if self.note:
            ttk.Label(frame, text=self.note, wraplength=440).grid(
                row=row, column=0, columnspan=2, sticky='w', pady=(0, 12))
            row += 1
        first = None
        for name, label, secret, initial in self.fields:
            ttk.Label(frame, text=label).grid(row=row, column=0, sticky='w', padx=8, pady=7)
            entry = ttk.Entry(frame, width=32, show='*' if secret else '')
            entry.insert(0, initial)
            entry.grid(row=row, column=1, padx=8, pady=7)
            self.inputs[name] = entry
            first = first or entry
            row += 1
        return first

    def validate(self):
        values = {key: entry.get() for key, entry in self.inputs.items()}
        try:
            if self.check:
                self.check(values)
        except (ValueError, OSError, PermissionError) as exc:
            messagebox.showerror('Ошибка', str(exc), parent=self)
            return False
        self.values = values
        return True

    def apply(self):
        self.result = self.values


class App:
    def __init__(self, root, store):
        self.root, self.store = root, store
        self.session = Session(store)
        root.title('ЛР №1 · Разграничение доступа · Вариант 1')
        root.geometry('880x480')
        root.minsize(740, 420)
        root.protocol('WM_DELETE_WINDOW', self.close)
        self.frame = ttk.Frame(root, padding=20)
        self.frame.pack(fill='both', expand=True)
        self.login_screen()

    def menu(self, logged=False):
        bar = tk.Menu(self.root)
        account = tk.Menu(bar, tearoff=False)
        account.add_command(label='Сменить пароль', command=self.change_password,
                            state='normal' if logged else 'disabled')
        account.add_separator()
        account.add_command(label='Выход', command=self.close)
        bar.add_cascade(label='Учётная запись', menu=account)
        admin = tk.Menu(bar, tearoff=False)
        admin.add_command(label='Список пользователей', command=self.show_users)
        admin.add_command(label='Добавить пользователя', command=self.add_user)
        admin.add_command(label='Параметры пользователя', command=self.edit_policy)
        bar.add_cascade(label='Администрирование', menu=admin,
                        state='normal' if logged and self.session.name == 'ADMIN' else 'disabled')
        help_menu = tk.Menu(bar, tearoff=False)
        help_menu.add_command(label='О программе', command=self.about)
        bar.add_cascade(label='Справка', menu=help_menu)
        self.root.config(menu=bar)

    def clear(self):
        for widget in self.frame.winfo_children():
            widget.destroy()

    def login_screen(self):
        self.menu()
        self.clear()
        ttk.Label(self.frame, text='Вход в систему', font=('Segoe UI', 18)).pack(pady=18)
        form = ttk.Frame(self.frame)
        form.pack()
        ttk.Label(form, text='Имя пользователя').grid(row=0, column=0, sticky='w', pady=8)
        self.username = ttk.Entry(form, width=30)
        self.username.grid(row=0, column=1, padx=12, pady=8)
        ttk.Label(form, text='Пароль').grid(row=1, column=0, sticky='w', pady=8)
        self.password = ttk.Entry(form, width=30, show='*')
        self.password.grid(row=1, column=1, padx=12, pady=8)
        self.password.bind('<Return>', lambda event: self.login())
        ttk.Button(self.frame, text='Войти', command=self.login).pack(pady=16)
        ttk.Label(self.frame, text='При первом входе: ADMIN, пароль оставьте пустым.').pack()
        self.username.focus_set()

    def login(self):
        result = self.session.login(self.username.get().strip(), self.password.get())
        self.password.delete(0, 'end')
        errors = {'unknown': 'Такого пользователя нет. Повторите ввод или закройте программу.',
                  'blocked': 'Учётная запись заблокирована.',
                  'wrong': f'Неверный пароль. Осталось попыток: {3 - self.session.failures}.',
                  'locked': 'Три неверных пароля. Программа завершается.'}
        if result in errors:
            messagebox.showerror('Вход', errors[result], parent=self.root)
            if result == 'locked':
                self.close()
            return
        if result in ('first', 'expired'):
            if not self.change_password(required=True, first=result == 'first'):
                self.close()
                return
        self.home()

    def home(self):
        self.menu(logged=True)
        self.clear()
        name = self.session.name
        ttk.Label(self.frame, text=f'Пользователь: {name}', font=('Segoe UI', 16)).pack(anchor='w')
        if name == 'ADMIN':
            self.show_users()
        else:
            ttk.Label(self.frame, text='Доступны смена своего пароля и завершение работы.').pack(
                anchor='w', pady=20)
            ttk.Button(self.frame, text='Сменить пароль', command=self.change_password).pack(anchor='w')
            ttk.Button(self.frame, text='Выход', command=self.close).pack(anchor='w', pady=12)

    def show_users(self):
        self.session.require_admin()
        self.clear()
        ttk.Label(self.frame, text='Учётные записи', font=('Segoe UI', 16)).pack(anchor='w', pady=(0, 12))
        table_frame = ttk.Frame(self.frame)
        table_frame.pack(fill='both', expand=True)
        columns = ('name', 'blocked', 'restricted', 'length', 'months', 'set')
        self.table = ttk.Treeview(table_frame, columns=columns, show='headings', selectmode='browse')
        labels = ('Имя', 'Блокировка', 'Ограничения', 'Мин. длина', 'Срок, мес.', 'Пароль задан')
        for col, label in zip(columns, labels):
            self.table.heading(col, text=label)
            self.table.column(col, width=120, minwidth=85, anchor='center')
        scroll = ttk.Scrollbar(table_frame, orient='vertical', command=self.table.yview)
        self.table.configure(yscrollcommand=scroll.set)
        self.table.pack(side='left', fill='both', expand=True)
        scroll.pack(side='right', fill='y')
        for name, u in self.store.users.items():
            yes = lambda b: 'Да' if b else 'Нет'
            self.table.insert('', 'end', values=(name, yes(u['blocked']), yes(u['restricted']),
                u['min_length'], u['months'], yes(u['initialized'])))
        self.table.bind('<Double-1>', lambda event: self.edit_policy())
        buttons = ttk.Frame(self.frame)
        buttons.pack(fill='x', pady=14)
        ttk.Button(buttons, text='Добавить', command=self.add_user).pack(side='left', padx=(0, 8))
        ttk.Button(buttons, text='Параметры выбранного', command=self.edit_policy).pack(side='left')
        ttk.Label(self.frame, text='Срок 0 — бессрочно. Ограничения варианта 1: строчная, прописная, + - * / =.').pack(anchor='w')

    def add_user(self):
        self.session.require_admin()
        dialog = Fields(self.root, 'Новый пользователь', [('name', 'Имя', False, '')],
                        note='Новая запись создаётся с пустым паролем.',
                        validate_values=lambda v: self.session.add_user(v['name']))
        if dialog.result is not None:
            self.show_users()

    def edit_policy(self):
        self.session.require_admin()
        selected = self.table.selection()
        if not selected:
            messagebox.showinfo('Параметры', 'Выберите пользователя в таблице.', parent=self.root)
            return
        name = self.table.item(selected[0], 'values')[0]
        u = self.store.users[name]

        def update(v):
            if v['blocked'] not in ('0', '1') or v['restricted'] not in ('0', '1'):
                raise ValueError('Для флагов введите 0 или 1.')
            try:
                length, months = int(v['length']), int(v['months'])
            except ValueError:
                raise ValueError('Длина и срок должны быть целыми числами.')
            self.session.set_policy(name, v['blocked'] == '1', v['restricted'] == '1', length, months)

        dialog = Fields(self.root, f'Параметры: {name}', [
            ('blocked', 'Блокировка (0/1)', False, str(int(u['blocked']))),
            ('restricted', 'Ограничения (0/1)', False, str(int(u['restricted']))),
            ('length', 'Минимальная длина', False, str(u['min_length'])),
            ('months', 'Срок в месяцах', False, str(u['months'])),
        ], note='0 — выключено, 1 — включено. Срок 0 — бессрочно.\n'
                'Ограничения состава и длины проверяются при выборе нового пароля.',
                        validate_values=update)
        if dialog.result is not None:
            if expired(self.store.users[self.session.name]):
                if not self.change_password(required=True):
                    self.close()
                    return
            self.show_users()

    def change_password(self, required=False, first=False):
        if self.session.name is None:
            return False
        u = self.store.users[self.session.name]
        fields = [] if first else [('old', 'Старый пароль', True, '')]
        fields += [('new', 'Новый пароль', True, ''), ('confirm', 'Повтор нового пароля', True, '')]
        note = ('Установите пароль при первом входе.' if first else
                'Срок пароля истёк. Установите новый пароль.' if required else 'Смена своего пароля.')
        note += f"\nМинимальная длина: {u['min_length']}. "
        note += 'Нужны строчная, прописная и + - * / =.' if u['restricted'] else 'Ограничения состава выключены.'
        if required:
            note += '\nОтмена завершит программу.'
        dialog = Fields(self.root, 'Установка пароля' if first else 'Смена пароля', fields,
                        note=note, validate_values=lambda v: self.session.change_password(
                            v.get('old', ''), v['new'], v['confirm']))
        if dialog.result is not None:
            messagebox.showinfo('Пароль', 'Пароль сохранён.', parent=self.root)
            return True
        return False

    def about(self):
        messagebox.showinfo('О программе', f'Автор: {AUTHOR}\n\nЛабораторная работа №1, вариант 1.\n'
            'Пароль: строчные и прописные буквы, знаки арифметических операций.\n'
            'Шифрование: DES-ECB. Случайная соль при получении ключа.\n'
            'Хеширование паролей: MD4. Криптопровайдер Windows.', parent=self.root)

    def close(self):
        try:
            self.store.save()
        except (OSError, ValueError) as exc:
            # Окно остаётся открытым: пользователь может освободить место,
            # исправить права и повторить выход без потери текущего состояния.
            messagebox.showerror('Не удалось сохранить', str(exc), parent=self.root)
            return
        self.root.destroy()


def main():
    root = tk.Tk()
    root.withdraw()
    crypto, lock, store = None, None, None
    try:
        if os.name != 'nt':
            raise OSError('Запустите программу на Windows 11.')
        # Блокировка предотвращает одновременную запись двух экземпляров.
        import msvcrt
        lock = open(DATA_PATH.with_suffix('.lock'), 'a+b')
        if lock.seek(0, 2) == 0:
            lock.write(b'0')
            lock.flush()
        lock.seek(0)
        try:
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            raise OSError('Другой экземпляр программы уже открыт.')
        crypto = WindowsCrypto()
        creating = not DATA_PATH.exists()
        fields = [('phrase', 'Парольная фраза', True, '')]
        if creating:
            fields.append(('confirm', 'Повтор фразы', True, ''))

        def check_phrase(v):
            if creating and not v['phrase']:
                raise ValueError('Задайте непустую парольную фразу для защиты файла.')
            if creating and v['phrase'] != v['confirm']:
                raise ValueError('Парольные фразы не совпадают.')

        dialog = Fields(root, 'Создание защищённого файла' if creating else 'Расшифрование файла',
                        fields, note=('Придумайте фразу для шифрования файла учётных записей.' if creating
                        else 'Введите фразу, заданную при создании файла учётных записей.') +
                        '\nЭто отдельный секрет, он не является паролем ADMIN.',
                        validate_values=check_phrase)
        if dialog.result is None:
            messagebox.showinfo('Завершение', 'Ввод фразы отменён. Программа завершается.', parent=root)
            return
        store = Store(DATA_PATH, crypto, dialog.result['phrase'])
        dialog.result.clear()
        store.open()
        App(root, store)
        root.deiconify()
        root.mainloop()
    except (OSError, ValueError) as exc:
        messagebox.showerror('Запуск невозможен', str(exc), parent=root)
    finally:
        if store:
            store.phrase, store.data = '', None
        if crypto:
            crypto.close()
        if lock:
            lock.close()
        try:
            root.destroy()
        except tk.TclError:
            pass


if __name__ == '__main__':
    main()
