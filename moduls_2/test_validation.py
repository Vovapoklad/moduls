import tkinter as tk
from tkinter import ttk, messagebox

class TestData:
    def __init__(self):
        self.test_cases = [
            "test@example.com",  
            "testexample.com",   
            "test@",            
            "@example.com",    
            "test @example.com", 
            "тест@example.com",  
            "test@test@example.com", 
            ""                
        ]
        self.current_index = 0

    def get_next_test_case(self):
        if self.current_index < len(self.test_cases):
            data = self.test_cases[self.current_index]
            self.current_index += 1
            return data
        return None

class TestValidationWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Тестирование валидации email")
        self.test_data = TestData()
        self.current_test_case = None
        self.test_results = []
        
        self.create_widgets()
    
    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        ttk.Label(main_frame, text="Текущий тест-кейс:").grid(row=0, column=0, pady=5)
        self.test_case_label = ttk.Label(main_frame, text="")
        self.test_case_label.grid(row=0, column=1, pady=5)
        
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=1, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="Получить данные", command=self.load_test_data).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Отправить результат теста", command=self.validate_and_save).pack(side=tk.LEFT, padx=5)
        
        columns = ("№", "Действие", "Ожидаемый результат", "Результат")
        self.result_tree = ttk.Treeview(main_frame, columns=columns, show="headings")
        
        for col in columns:
            self.result_tree.heading(col, text=col)
            self.result_tree.column(col, width=150)
        
        self.result_tree.grid(row=2, column=0, columnspan=2, pady=10)
        
        self.initialize_test_table()
    
    def initialize_test_table(self):
        test_cases = [
            ("Ввод корректного email (например: test@example.com)", "Система принимает email и сохраняет данные"),
            ("Ввод email без символа @ (например: testexample.com)", "Система выдает ошибку \"Некорректный формат email\""),
            ("Ввод email без домена (например: test@)", "Система выдает ошибку \"Некорректный формат email\""),
            ("Ввод email без имени пользователя (например: @example.com)", "Система выдает ошибку \"Некорректный формат email\""),
            ("Ввод email с пробелами (например: test @example.com)", "Система выдает ошибку \"Некорректный формат email\""),
            ("Ввод email с кириллицей (например: тест@example.com)", "Система выдает ошибку \"Некорректный формат email\""),
            ("Ввод email с несколькими символами @ (например: test@test@example.com)", "Система выдает ошибку \"Некорректный формат email\""),
            ("Ввод пустого значения", "Система выдает ошибку \"Email не может быть пустым\"")
        ]
        
        for i, (action, expected) in enumerate(test_cases, 1):
            self.result_tree.insert("", "end", values=(i, action, expected, ""))
    
    def load_test_data(self):
        self.current_test_case = self.test_data.get_next_test_case()
        if self.current_test_case is not None:
            self.test_case_label.config(text=self.current_test_case)
        else:
            messagebox.showinfo("Информация", "Все тест-кейсы пройдены")
    
    def validate_and_save(self):
        if self.current_test_case is None:
            messagebox.showwarning("Предупреждение", "Сначала получите данные")
            return
        
        current_index = self.test_data.current_index - 1
        
        is_valid, message = self.validate_email(self.current_test_case)
        
        expected_result = "Система принимает email и сохраняет данные" if current_index == 0 else "Система выдает ошибку \"Некорректный формат email\""
        
        actual_result = "Пройден" if (is_valid and current_index == 0) or (not is_valid and current_index != 0) else "Не пройден"
        
        item = self.result_tree.get_children()[current_index]
        self.result_tree.set(item, "Результат", actual_result)
        
        self.test_results.append({
            "test_case": self.current_test_case,
            "expected": expected_result,
            "actual": actual_result,
            "message": message
        })
        
        self.current_test_case = None
        self.test_case_label.config(text="")
    
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

if __name__ == "__main__":
    root = tk.Tk()
    app = TestValidationWindow(root)
    root.mainloop() 