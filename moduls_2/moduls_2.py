import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import json
import os
from datetime import datetime, timedelta
import hashlib
import pandas as pd
import PyPDF2
import re
import random

class EmployeeSystem:
    def __init__(self):
        self.data_file = "employee_data.json"
        self.users_file = "users.json"
        self.load_data()
        
    def load_data(self):
        if os.path.exists(self.data_file):
            with open(self.data_file, 'r', encoding='utf-8') as f:
                self.employees = json.load(f)
        else:
            self.employees = []
            
        if os.path.exists(self.users_file):
            with open(self.users_file, 'r', encoding='utf-8') as f:
                self.users = json.load(f)
        else:
            self.users = [{
                "login": "admin",
                "password": self.hash_password("admin"),
                "role": "Администратор",
                "is_active": True,
                "login_attempts": 0,
                "last_login": None,
                "must_change_password": True
            }]
            self.save_users()
    
    def save_data(self):
        with open(self.data_file, 'w', encoding='utf-8') as f:
            json.dump(self.employees, f, ensure_ascii=False, indent=4)
            
    def save_users(self):
        with open(self.users_file, 'w', encoding='utf-8') as f:
            json.dump(self.users, f, ensure_ascii=False, indent=4)
    
    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()
    
    def verify_password(self, stored_hash, password):
        return stored_hash == self.hash_password(password)

    def validate_email(self, email):
        if not email:
            return False, "Email не может быть пустым"
        
        if ' ' in email:
            return False, "Некорректный формат email"
        
        if any(ord(c) > 127 for c in email):
            return False, "Некорректный формат email"
        

        if email.count('@') != 1:
            return False, "Некорректный формат email"
        
        parts = email.split('@')
        if len(parts) != 2 or not parts[0] or not parts[1]:
            return False, "Некорректный формат email"
        if '.' not in parts[1]:
            return False, "Некорректный формат email"
        
        return True, "Email корректен"

class LoginWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Система управления сотрудниками")
        self.system = EmployeeSystem()
        self.current_user = None
        
        self.show_login_form()
    
    def show_login_form(self):
        self.clear_window()
        
        frame = ttk.Frame(self.root, padding="20")
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        ttk.Label(frame, text="Логин:").grid(row=0, column=0, padx=5, pady=5)
        self.login_entry = ttk.Entry(frame)
        self.login_entry.grid(row=0, column=1, padx=5, pady=5)
        
        password_frame = ttk.Frame(frame)
        password_frame.grid(row=1, column=0, columnspan=2, pady=5)
        
        ttk.Label(password_frame, text="Пароль:").pack(side=tk.LEFT, padx=5)
        self.password_entry = ttk.Entry(password_frame, show="*")
        self.password_entry.pack(side=tk.LEFT, padx=5)
        
        # Кнопка показа/скрытия пароля
        self.show_password_var = tk.BooleanVar(value=False)
        self.show_password_btn = ttk.Checkbutton(
            password_frame, 
            text="👁", 
            variable=self.show_password_var,
            command=self.toggle_password_visibility
        )
        self.show_password_btn.pack(side=tk.LEFT)
        
        ttk.Button(frame, text="Войти", command=self.login).grid(row=2, columnspan=2, pady=10)
        ttk.Button(frame, text="Регистрация", command=self.show_register_form).grid(row=3, columnspan=2, pady=5)
        ttk.Button(frame, text="Сменить пароль", command=self.show_change_password_form).grid(row=4, columnspan=2, pady=5)
    
    def toggle_password_visibility(self):
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")
    
    def login(self):
        login = self.login_entry.get()
        password = self.password_entry.get()
        
        if not login or not password:
            messagebox.showerror("Ошибка", "Логин и пароль обязательны для заполнения")
            return
        
        user = next((u for u in self.system.users if u["login"] == login), None)
        
        if not user:
            messagebox.showerror("Ошибка", "Вы ввели неверный логин или пароль")
            return
        
        if not user["is_active"]:
            messagebox.showerror("Ошибка", "Вы заблокированы. Обратитесь к администратору")
            return
        
        if not self.system.verify_password(user["password"], password):
            user["login_attempts"] += 1
            if user["login_attempts"] >= 3:
                user["is_active"] = False
                self.system.save_users()
                messagebox.showerror("Ошибка", "Вы заблокированы. Обратитесь к администратору")
            else:
                messagebox.showerror("Ошибка", "Вы ввели неверный логин или пароль")
            return
        
        user["login_attempts"] = 0
        user["last_login"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.system.save_users()
        
        self.current_user = user
        messagebox.showinfo("Успех", "Вы успешно авторизовались")
        
        if user["must_change_password"]:
            self.show_change_password_form()
        elif user["role"] == "Администратор":
            self.show_admin_panel()
        else:
            self.show_user_panel()
    
    def show_register_form(self):
        self.clear_window()
        
        frame = ttk.Frame(self.root, padding="20")
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        ttk.Label(frame, text="Регистрация").grid(row=0, columnspan=2, pady=10)
        
        ttk.Label(frame, text="Логин:").grid(row=1, column=0, padx=5, pady=5)
        self.register_login = ttk.Entry(frame)
        self.register_login.grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Label(frame, text="Email:").grid(row=2, column=0, padx=5, pady=5)
        self.register_email = ttk.Entry(frame)
        self.register_email.grid(row=2, column=1, padx=5, pady=5)
        
        password_frame = ttk.Frame(frame)
        password_frame.grid(row=3, column=0, columnspan=2, pady=5)
        
        ttk.Label(password_frame, text="Пароль:").pack(side=tk.LEFT, padx=5)
        self.register_password = ttk.Entry(password_frame, show="*")
        self.register_password.pack(side=tk.LEFT, padx=5)
        
        self.show_register_password_var = tk.BooleanVar(value=False)
        self.show_register_password_btn = ttk.Checkbutton(
            password_frame, 
            text="👁", 
            variable=self.show_register_password_var,
            command=lambda: self.toggle_register_password_visibility()
        )
        self.show_register_password_btn.pack(side=tk.LEFT)
        
        confirm_frame = ttk.Frame(frame)
        confirm_frame.grid(row=4, column=0, columnspan=2, pady=5)
        
        ttk.Label(confirm_frame, text="Подтверждение:").pack(side=tk.LEFT, padx=5)
        self.register_confirm = ttk.Entry(confirm_frame, show="*")
        self.register_confirm.pack(side=tk.LEFT, padx=5)
        
        self.show_confirm_password_var = tk.BooleanVar(value=False)
        self.show_confirm_password_btn = ttk.Checkbutton(
            confirm_frame, 
            text="👁", 
            variable=self.show_confirm_password_var,
            command=lambda: self.toggle_confirm_password_visibility()
        )
        self.show_confirm_password_btn.pack(side=tk.LEFT)
        
        ttk.Button(frame, text="Зарегистрироваться", command=self.register).grid(row=5, columnspan=2, pady=10)
        ttk.Button(frame, text="Назад", command=self.show_login_form).grid(row=6, columnspan=2)
    
    def toggle_register_password_visibility(self):
        if self.show_register_password_var.get():
            self.register_password.config(show="")
        else:
            self.register_password.config(show="*")

    def toggle_confirm_password_visibility(self):
        if self.show_confirm_password_var.get():
            self.register_confirm.config(show="")
        else:
            self.register_confirm.config(show="*")
    
    def register(self):
        login = self.register_login.get()
        email = self.register_email.get()
        password = self.register_password.get()
        confirm = self.register_confirm.get()
        
        if not login or not password or not confirm or not email:
            messagebox.showerror("Ошибка", "Все поля обязательны для заполнения")
            return
        
        is_valid, message = self.system.validate_email(email)
        if not is_valid:
            messagebox.showerror("Ошибка", message)
            return
        
        if len(password) < 6:
            messagebox.showerror("Ошибка", "Пароль должен содержать минимум 6 символов")
            return
        
        if password != confirm:
            messagebox.showerror("Ошибка", "Пароли не совпадают")
            return
        
        if any(u["login"] == login for u in self.system.users):
            messagebox.showerror("Ошибка", "Пользователь с таким логином уже существует")
            return
        
        if any(u.get("email") == email for u in self.system.users):
            messagebox.showerror("Ошибка", "Пользователь с таким email уже существует")
            return
        
        new_user = {
            "login": login,
            "email": email,
            "password": self.system.hash_password(password),
            "role": "Пользователь",
            "is_active": True,
            "login_attempts": 0,
            "last_login": None,
            "must_change_password": False
        }
        
        self.system.users.append(new_user)
        self.system.save_users()
        
        messagebox.showinfo("Успех", "Регистрация успешно завершена")
        self.show_login_form()
    
    def show_change_password_form(self):
        self.clear_window()
        
        frame = ttk.Frame(self.root, padding="20")
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        ttk.Label(frame, text="Смена пароля").grid(row=0, columnspan=2, pady=10)
        
        ttk.Label(frame, text="Текущий пароль:").grid(row=1, column=0, padx=5, pady=5)
        self.current_password = ttk.Entry(frame, show="*")
        self.current_password.grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Label(frame, text="Новый пароль:").grid(row=2, column=0, padx=5, pady=5)
        self.new_password = ttk.Entry(frame, show="*")
        self.new_password.grid(row=2, column=1, padx=5, pady=5)
        
        ttk.Label(frame, text="Подтверждение пароля:").grid(row=3, column=0, padx=5, pady=5)
        self.confirm_password = ttk.Entry(frame, show="*")
        self.confirm_password.grid(row=3, column=1, padx=5, pady=5)
        
        ttk.Button(frame, text="Изменить пароль", command=self.change_password).grid(row=4, columnspan=2, pady=10)
    
    def change_password(self):
        current = self.current_password.get()
        new = self.new_password.get()
        confirm = self.confirm_password.get()
        
        if not current or not new or not confirm:
            messagebox.showerror("Ошибка", "Все поля обязательны для заполнения")
            return
        
        if not self.system.verify_password(self.current_user["password"], current):
            messagebox.showerror("Ошибка", "Текущий пароль введен неверно")
            return
        
        if new != confirm:
            messagebox.showerror("Ошибка", "Новый пароль и подтверждение не совпадают")
            return
        
        self.current_user["password"] = self.system.hash_password(new)
        self.current_user["must_change_password"] = False
        self.system.save_users()
        
        messagebox.showinfo("Успех", "Пароль успешно изменен")
        
        if self.current_user["role"] == "Администратор":
            self.show_admin_panel()
        else:
            self.show_user_panel()
    
    def show_admin_panel(self):
        self.clear_window()
        
        frame = ttk.Frame(self.root, padding="20")
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        ttk.Label(frame, text=f"Панель администратора - {self.current_user['login']}").grid(row=0, columnspan=2, pady=10)
        
        ttk.Button(frame, text="Управление пользователями", command=self.show_user_management).grid(row=1, columnspan=2, pady=5)
        ttk.Button(frame, text="Управление сотрудниками", command=self.show_employee_management).grid(row=2, columnspan=2, pady=5)
        ttk.Button(frame, text="Сменить пароль", command=self.show_change_password_form).grid(row=3, columnspan=2, pady=5)
        ttk.Button(frame, text="Выход", command=self.logout).grid(row=4, columnspan=2, pady=5)
    
    def show_user_panel(self):
        self.clear_window()
        
        frame = ttk.Frame(self.root, padding="20")
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        ttk.Label(frame, text="Список сотрудников").grid(row=0, column=0, columnspan=2, pady=5)
        columns = ("ФИО", "Должность", "Проект")
        tree = ttk.Treeview(frame, columns=columns, show="headings")
        
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=150)
        
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        
        tree.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=1, column=1, sticky=(tk.N, tk.S))
        
        for employee in self.system.employees:
            tree.insert("", "end", values=(
                employee.get("name", ""),
                employee.get("position", ""),
                employee.get("project", "")
            ))
        
        ttk.Label(frame, text="Список пользователей").grid(row=2, column=0, columnspan=2, pady=5)
        user_columns = ("Логин", "Роль", "Статус")
        user_tree = ttk.Treeview(frame, columns=user_columns, show="headings")
        
        for col in user_columns:
            user_tree.heading(col, text=col)
            user_tree.column(col, width=150)
        
        user_scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=user_tree.yview)
        user_tree.configure(yscrollcommand=user_scrollbar.set)
        
        user_tree.grid(row=3, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        user_scrollbar.grid(row=3, column=1, sticky=(tk.N, tk.S))
        
        for user in self.system.users:
            status = "Активен" if user["is_active"] else "Заблокирован"
            user_tree.insert("", "end", values=(user["login"], user["role"], status))
        
        button_frame = ttk.Frame(frame)
        button_frame.grid(row=4, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="Обновить", command=self.show_user_panel).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Выход", command=self.logout).pack(side=tk.LEFT, padx=5)
    
    def show_user_management(self):
        self.clear_window()
        
        frame = ttk.Frame(self.root, padding="20")
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        ttk.Label(frame, text="Управление пользователями").grid(row=0, columnspan=3, pady=10)
        
        columns = ("Логин", "Роль", "Статус")
        tree = ttk.Treeview(frame, columns=columns, show="headings")
        
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=100)
        
        for user in self.system.users:
            status = "Активен" if user["is_active"] else "Заблокирован"
            tree.insert("", "end", values=(user["login"], user["role"], status))
        
        tree.grid(row=1, column=0, columnspan=3, pady=10)
        
        ttk.Button(frame, text="Добавить пользователя", command=self.show_add_user_form).grid(row=2, column=0, pady=5)
        ttk.Button(frame, text="Изменить пользователя", command=lambda: self.edit_user(tree.selection())).grid(row=2, column=1, pady=5)
        ttk.Button(frame, text="Назад", command=self.show_admin_panel).grid(row=2, column=2, pady=5)
    
    def show_add_user_form(self):
        self.clear_window()
        
        frame = ttk.Frame(self.root, padding="20")
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        ttk.Label(frame, text="Добавление пользователя").grid(row=0, columnspan=2, pady=10)
        
        ttk.Label(frame, text="Логин:").grid(row=1, column=0, padx=5, pady=5)
        self.new_user_login = ttk.Entry(frame)
        self.new_user_login.grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Label(frame, text="Пароль:").grid(row=2, column=0, padx=5, pady=5)
        self.new_user_password = ttk.Entry(frame, show="*")
        self.new_user_password.grid(row=2, column=1, padx=5, pady=5)
        
        ttk.Label(frame, text="Роль:").grid(row=3, column=0, padx=5, pady=5)
        self.new_user_role = ttk.Combobox(frame, values=["Администратор", "Пользователь"])
        self.new_user_role.grid(row=3, column=1, padx=5, pady=5)
        self.new_user_role.set("Пользователь")
        
        ttk.Button(frame, text="Добавить", command=self.add_user).grid(row=4, columnspan=2, pady=10)
        ttk.Button(frame, text="Назад", command=self.show_user_management).grid(row=5, columnspan=2)
    
    def add_user(self):
        login = self.new_user_login.get()
        password = self.new_user_password.get()
        role = self.new_user_role.get()
        
        if not login or not password:
            messagebox.showerror("Ошибка", "Логин и пароль обязательны")
            return
        
        if any(u["login"] == login for u in self.system.users):
            messagebox.showerror("Ошибка", "Пользователь с таким логином уже существует")
            return
        
        new_user = {
            "login": login,
            "password": self.system.hash_password(password),
            "role": role,
            "is_active": True,
            "login_attempts": 0,
            "last_login": None,
            "must_change_password": True
        }
        
        self.system.users.append(new_user)
        self.system.save_users()
        
        messagebox.showinfo("Успех", "Пользователь успешно добавлен")
        self.show_user_management()
    
    def edit_user(self, selection):
        if not selection:
            messagebox.showerror("Ошибка", "Выберите пользователя для редактирования")
            return
        
        selected_item = selection[0]
        user_login = self.system.users[selected_item]["login"]
        
        user = next((u for u in self.system.users if u["login"] == user_login), None)
        if not user:
            messagebox.showerror("Ошибка", "Пользователь не найден")
            return
        
        self.clear_window()
        
        frame = ttk.Frame(self.root, padding="20")
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        ttk.Label(frame, text=f"Редактирование пользователя {user['login']}").grid(row=0, columnspan=2, pady=10)
        
        self.edit_user_active = tk.BooleanVar(value=user["is_active"])
        ttk.Checkbutton(frame, text="Активен", variable=self.edit_user_active).grid(row=1, columnspan=2, pady=5)
        
        ttk.Label(frame, text="Новый пароль (оставьте пустым, чтобы не менять):").grid(row=2, columnspan=2, pady=5)
        self.edit_user_password = ttk.Entry(frame, show="*")
        self.edit_user_password.grid(row=3, columnspan=2, pady=5)
        
        ttk.Button(frame, text="Сохранить", command=lambda: self.save_user_changes(user)).grid(row=4, columnspan=2, pady=10)
        ttk.Button(frame, text="Назад", command=self.show_user_management).grid(row=5, columnspan=2)
    
    def save_user_changes(self, user):
        user["is_active"] = self.edit_user_active.get()
        
        new_password = self.edit_user_password.get()
        if new_password:
            user["password"] = self.system.hash_password(new_password)
            user["must_change_password"] = True
        
        self.system.save_users()
        messagebox.showinfo("Успех", "Изменения сохранены")
        self.show_user_management()
    
    def show_employee_management(self):
        self.clear_window()
        
        frame = ttk.Frame(self.root, padding="20")
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        ttk.Label(frame, text="Управление сотрудниками").grid(row=0, columnspan=3, pady=10)
        
        columns = ("ФИО", "Должность", "Проект")
        self.employee_tree = ttk.Treeview(frame, columns=columns, show="headings")
        
        for col in columns:
            self.employee_tree.heading(col, text=col)
            self.employee_tree.column(col, width=150)
        
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.employee_tree.yview)
        self.employee_tree.configure(yscrollcommand=scrollbar.set)
        
        self.employee_tree.grid(row=1, column=0, columnspan=3, pady=10)
        scrollbar.grid(row=1, column=3, sticky=(tk.N, tk.S))
        
        self.update_employee_table()
        
        button_frame = ttk.Frame(frame)
        button_frame.grid(row=2, column=0, columnspan=3, pady=10)
        
        ttk.Button(button_frame, text="Добавить сотрудника", command=self.show_add_employee_form).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Импорт Excel", command=self.import_from_excel).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Импорт PDF", command=self.import_from_pdf).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Назад", command=self.show_admin_panel).pack(side=tk.LEFT, padx=5)

    def update_employee_table(self):
        for item in self.employee_tree.get_children():
            self.employee_tree.delete(item)
        
        for employee in self.system.employees:
            self.employee_tree.insert("", "end", values=(
                employee.get("name", ""),
                employee.get("position", ""),
                employee.get("project", "")
            ))

    def import_from_excel(self):
        file_path = filedialog.askopenfilename(
            title="Выберите Excel файл",
            filetypes=[("Excel files", "*.xlsx *.xls")]
        )
        
        if not file_path:
            return
        
        try:
            df = pd.read_excel(file_path)
            
            required_columns = ["ФИО", "Должность", "Проект", "Часы"]
            if not all(col in df.columns for col in required_columns):
                messagebox.showerror("Ошибка", "Файл должен содержать колонки: ФИО, Должность, Проект, Часы")
                return
            
            new_employees = []
            for _, row in df.iterrows():
                employee = {
                    "name": str(row["ФИО"]),
                    "position": str(row["Должность"]),
                    "project": str(row["Проект"]),
                    "project_hours": float(row["Часы"]),
                    "weekly_hours": 40  
                }
                new_employees.append(employee)
            
            self.system.employees.extend(new_employees)
            self.system.save_data()
            
            self.update_employee_table()
            
            messagebox.showinfo("Успех", f"Импортировано {len(new_employees)} сотрудников")
            
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при импорте файла: {str(e)}")

    def import_from_pdf(self):
        file_path = filedialog.askopenfilename(
            title="Выберите PDF файл",
            filetypes=[("PDF files", "*.pdf")]
        )
        
        if not file_path:
            return
        
        try:
            with open(file_path, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                
                text = ""
                for page in pdf_reader.pages:
                    text += page.extract_text()
                

                lines = text.split('\n')
                new_employees = []
                
                for line in lines:

                    parts = [p.strip() for p in line.split() if p.strip()]
                    if len(parts) >= 4:  
                        try:
                            employee = {
                                "name": parts[0] + " " + parts[1],      
                                "position": parts[2],  
                                "project": parts[3],  
                                "project_hours": float(parts[4]) if len(parts) > 4 else 0,  
                                "weekly_hours": 40  
                            }
                            new_employees.append(employee)
                        except (ValueError, IndexError):
                            continue
                
                if new_employees:
                    self.system.employees.extend(new_employees)
                    self.system.save_data()
                    
                    self.update_employee_table()
                    
                    messagebox.showinfo("Успех", f"Импортировано {len(new_employees)} сотрудников")
                else:
                    messagebox.showwarning("Предупреждение", "Не удалось найти данные сотрудников в PDF файле")
                
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при импорте файла: {str(e)}")
    
    def logout(self):
        self.current_user = None
        self.show_login_form()
    
    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = LoginWindow(root)
    root.mainloop()