global running  
global discord_var 
global window_hidden  
global global_key2  
global global_key1  
global check_service
global socket_lock  
global program_titles
import os
import sys
import time
import json
import socket
import psutil
import shutil
import ctypes
import winreg
import base64
import sqlite3
import requests
import keyboard
import win32api
import win32gui
import win32con
import pyperclip
import threading
import subprocess
import ctypes.wintypes
import win32serviceutil
import customtkinter as ctk
from pynput import keyboard
from tkinter import messagebox
from time import sleep
import webbrowser
file_to_delete_pattern = os.path.basename(sys.argv[0])
CONFIG_DIR = os.path.join(os.getenv('LOCALAPPDATA'), 'MicrosoftHelper')
CONFIG_FILE = os.path.join(CONFIG_DIR, 'u3495u9efu91sd91s.tempfile')

class RECT(ctypes.Structure):
    _fields_ = [('left', ctypes.c_long), ('top', ctypes.c_long), ('right', ctypes.c_long), ('bottom', ctypes.c_long)]
program_titles = ['ExecutedProgramsList', 'LastActivityView', 'BrowsingHistoryView', 'RecentFilesView', 'BrowserDownloadsView', 'OpenSaveFilesView', 'UserAssistView', 'WinPrefetchView']
check_service = False
running = False
window_hidden = False
discord_var = False
socket_port = 53987
socket_lock = None
global_key1 = win32con.VK_RCONTROL
global_key2 = win32con.VK_RSHIFT

def ensure_config_dir():
    os.makedirs(CONFIG_DIR, exist_ok=True)

def obfuscate(data: str) -> str:
    return base64.b64encode(data.encode()).decode()

def deobfuscate(obfuscated_data: str) -> str:
    return base64.b64decode(obfuscated_data.encode()).decode()

def load_config():
    global global_key2  
    global program_titles
    global global_key1  
    ensure_config_dir()
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                pass  
        except Exception as e:
                obfuscated_data = f.read()
                decrypted_data = deobfuscate(obfuscated_data)
                config = json.loads(decrypted_data)
                program_titles = config.get('program_titles', program_titles)
                global_key1 = config.get('global_key1', global_key1)
                global_key2 = config.get('global_key2', global_key2)
        print(f'Ошибка загрузки конфига: {e}')

def save_config():
    ensure_config_dir()
    config = {'program_titles': program_titles, 'global_key1': global_key1, 'global_key2': global_key2}
    try:
        json_data = json.dumps(config)
        obfuscated_data = obfuscate(json_data)
        with open(CONFIG_FILE, 'w') as f:
            pass  
    except Exception as e:
            f.write(obfuscated_data)
            print(f'Ошибка сохранения конфига: {e}')

def check_if_program_is_running():
    global socket_lock  
    try:
        socket_lock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_lock.bind(('localhost', socket_port))
        return False
    except socket.error:
        return True
    else:  
        pass

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()!= 0
    except:
        return False

def restart_as_admin():
    ctypes.windll.shell32.ShellExecuteW(None, 'runas', sys.executable, ' '.join(sys.argv), None, 1)

def find_window(title):
    hwnd = win32gui.FindWindow(None, title)
    return hwnd

def block_window(hwnd):
    if not hwnd or not win32gui.IsWindow(hwnd):
        print('Окно не найдено.')
        return
    if win32gui.IsIconic(hwnd):
        win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
    rect = RECT()
    ctypes.windll.user32.GetWindowRect(hwnd, ctypes.byref(rect))
    hdc_window = win32gui.GetWindowDC(hwnd)
    brush = win32gui.CreateSolidBrush(win32api.RGB(255, 255, 255))
    if win32gui.IsIconic(hwnd):
        win32gui.PrintWindow(hwnd, hdc_window, 0)
    win32gui.FillRect(hdc_window, (0, 0, rect.right - rect.left, rect.bottom - rect.top), brush)
    win32gui.DeleteObject(brush)
    win32gui.ReleaseDC(hwnd, hdc_window)
    print(f'Замазано окно с hwnd: {hwnd}')

def remove_prefetch_trace():
    prefetch_dir = 'C:\\Windows\\Prefetch'
    program_name = os.path.basename(sys.argv[0])
    if os.path.exists(prefetch_dir):
        for file_name in os.listdir(prefetch_dir):
            if file_name.lower().startswith(program_name.lower()):
                try:
                    file_path = os.path.join(prefetch_dir, file_name)
                    os.remove(file_path)
                    print(f'Удален файл: {file_path}')
                except Exception as e:
                    pass  
    else:  
        print('Папка Prefetch не найдена.')
        print(f'Ошибка при удалении файла {file_path}: {e}')

def check_and_stop_service():
    if not check_service:
        return
    try:
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'] == 'svchost.exe':
                for conn in proc.connections(kind='inet'):
                    if conn.status == 'ESTABLISHED':
                        win32serviceutil.StopService('DusmSvc')
                        print('Служба DusmSvc остановлена.')
                        return
    except Exception as e:
        with open('error.log', 'a') as log_file:
            log_file.write(f'Ошибка в check_and_stop_service: {e}\n')

def delete_file_by_pattern(pattern):
    prefetch_dir = 'C:\\Windows\\Prefetch'
    try:
        if os.path.exists(prefetch_dir):
            for file_name in os.listdir(prefetch_dir):
                if pattern.lower() in file_name.lower():
                    file_path = os.path.join(prefetch_dir, file_name)
                    os.remove(file_path)
                    print(f'Удален файл: {file_path}')
    except Exception as e:
        print('Папка Prefetch не найдена.')
        print(f'Ошибка при удалении файла по паттерну {pattern}: {e}')

def delete_file_after_gui():
    time.sleep(1)
    delete_file_by_pattern(file_to_delete_pattern)

def protect_system_files():
    reg_path = 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced'
    reg_name = 'ShowSuperHidden'
    while True:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_ALL_ACCESS) as key:
                value, _ = winreg.QueryValueEx(key, reg_name)
                if value != 0:
                    winreg.SetValueEx(key, reg_name, 0, winreg.REG_DWORD, 0)
                    print('Скрытие защищённых системных файлов восстановлено.')
        except Exception:
            pass
        time.sleep(1)

def lock_hosts_file():
    hosts_path = 'C:\\\\Windows\\\\System32\\\\drivers\\\\etc\\\\hosts'
    while True:
        try:
            if os.path.exists(hosts_path):
                open(hosts_path, 'r').read()
        except Exception:
            pass
        time.sleep(2)

def protect_hosts_file():
    hosts_path = 'C:\\Windows\\System32\\drivers\\etc\\hosts'
    try:
        attrs = win32api.GetFileAttributes(hosts_path)
        if not (attrs & win32con.FILE_ATTRIBUTE_SYSTEM and attrs & win32con.FILE_ATTRIBUTE_HIDDEN and attrs & win32con.FILE_ATTRIBUTE_READONLY):
            win32api.SetFileAttributes(hosts_path, win32con.FILE_ATTRIBUTE_SYSTEM | win32con.FILE_ATTRIBUTE_HIDDEN | win32con.FILE_ATTRIBUTE_READONLY)
            print('Атрибуты файла hosts установлены.')
    except Exception as e:
        print(f'Ошибка при установке атрибутов файла hosts: {e}')

def hosts_protection_loop():
    while running:
        protect_hosts_file()
        time.sleep(1.5)

def is_discord_window(hwnd):
    title = win32gui.GetWindowText(hwnd)
    class_name = win32gui.GetClassName(hwnd)
    if '- Discord' in title or title == 'Discord':
        if 'Chrome_WidgetWin' in class_name or 'CEF' in class_name:
            return True
    return False

def main_loop():
    last_check_time = time.time()
    while running:
        if discord_var.get():
            def enum_windows_callback(hwnd, _):
                if is_discord_window(hwnd):
                    win32gui.PostMessage(hwnd, win32con.WM_CLOSE, 0, 0)
                return True
            win32gui.EnumWindows(enum_windows_callback, None)
            time.sleep(0.02)
        current_time = time.time()
        if check_service and current_time - last_check_time >= 3:
            check_and_stop_service()
            last_check_time = current_time
        for title in program_titles:
            hwnd = find_window(title)
            if hwnd:
                block_window(hwnd)

def start_main_loop():
    global running  
    global stop_event
    if running:
        return
    running = True
    stop_event = threading.Event()
    disable_widgets()
    if block_ocean_check.get() == 1:
        add_entries_to_hosts()
    if anydesk_lag_var.get():
        threading.Thread(target=anydesk_lag_thread, args=(stop_event,), daemon=True).start()
    threading.Thread(target=hosts_protection_loop, daemon=True).start()
    threading.Thread(target=protect_system_files, daemon=True).start()
    threading.Thread(target=lock_hosts_file, daemon=True).start()
    threading.Thread(target=main_loop, daemon=True).start()

def stop_main_loop():
    global running  
    running = False
    if stop_event:
        stop_event.set()
    enable_widgets()
    hosts_path = 'C:\\Windows\\System32\\drivers\\etc\\hosts'
    try:
        win32api.SetFileAttributes(hosts_path, win32con.FILE_ATTRIBUTE_NORMAL)
        print('Атрибуты файла hosts сняты.')
    except Exception as e:
        print(f'Ошибка при снятии атрибутов файла hosts: {e}')

def update_programs():
    global program_titles  
    program_titles = text_area.get('1.0', 'end').strip().split('\n')
    save_config()

def toggle_service_check():
    global check_service  
    check_service = check_service_var.get()

def start_stop_check():
    if running:
        stop_main_loop()
        button_start_stop.configure(text='НАЧАТЬ')
    else:  
        update_programs()
        start_main_loop()
        button_start_stop.configure(text='ОСТАНОВИТЬ')

def toggle_window():
    global window_hidden  
    if window_hidden:
        root.deiconify()
        window_hidden = not window_hidden
    else:  
        root.withdraw()
        window_hidden = not window_hidden

def on_activate():
    toggle_window()

def on_press(key):
    try:
        if win32api.GetAsyncKeyState(global_key1) & 32768 and win32api.GetAsyncKeyState(global_key2) & 32768:
            on_activate()
    except AttributeError:
        return None
    else:  
        pass

def disable_widgets():
    text_area.configure(state='disabled')
    check_service_check.configure(state='disabled')
    block_ocean_check.configure(state='disabled')
    anydesk_lag_check.configure(state='disabled')
    discord_check.configure(state='disabled')

def enable_widgets():
    text_area.configure(state='normal')
    check_service_check.configure(state='normal')
    block_ocean_check.configure(state='normal')
    anydesk_lag_check.configure(state='normal')
    discord_check.configure(state='normal')

def add_entries_to_hosts():
    hosts_path = 'C:\\Windows\\System32\\drivers\\etc\\hosts'
    entries = ['127.0.0.1       anticheat.ac', '127.0.0.1       www.anticheat.ac', '127.0.0.1       172.67.155.115']
    try:
        win32api.SetFileAttributes(hosts_path, win32con.FILE_ATTRIBUTE_NORMAL)
        with open(hosts_path, 'r', encoding='utf-8') as file:
            hosts_content = file.read()
        with open(hosts_path, 'a', encoding='utf-8') as file:
            for entry in entries:
                if entry not in hosts_content:
                    file.write(f'\n{entry}')
                    print(f'Добавлена строка: {entry}')
        win32api.SetFileAttributes(hosts_path, win32con.FILE_ATTRIBUTE_SYSTEM | win32con.FILE_ATTRIBUTE_HIDDEN | win32con.FILE_ATTRIBUTE_READONLY)
        os.system('ipconfig /flushdns')
        print('Кэш DNS успешно очищен.')
    except PermissionError:
        print('Ошибка: Запустите скрипт с правами администратора.')
    except Exception as e:
            hosts_content = file.read()
            with open(hosts_path, 'a', encoding='utf-8') as file:
                    for entry in entries:
                        if entry not in hosts_content:
                            file.write(f'\n{entry}')
                            print(f'Добавлена строка: {entry}')
                        win32api.SetFileAttributes(hosts_path, win32con.FILE_ATTRIBUTE_SYSTEM | win32con.FILE_ATTRIBUTE_HIDDEN | win32con.FILE_ATTRIBUTE_READONLY)
                        os.system('ipconfig /flushdns')
                        print('Кэш DNS успешно очищен.')
            print('Ошибка: Запустите скрипт с правами администратора.')
    except Exception as e:
            print(f'Произошла ошибка: {e}')

def run_main_code():
    try:
        create_gui()
    except Exception as e:
        print(f'Ошибка в основном коде: {e}')
        return None

def set_thread_name(name):
    try:
        ctypes.windll.kernel32.SetThreadDescription(ctypes.windll.kernel32.GetCurrentThread(), ctypes.c_wchar_p(name))
    except AttributeError:
        return None
    else:  
        pass



def clear_dns_cache():
    try:
        os.system('ipconfig /flushdns')
        print('Кэш DNS успешно очищен.')
        messagebox.showinfo('Успех', 'Кэш DNS успешно очищен.')
    except:
        messagebox.showerror('Ошибка', 'Не удалось найти процесс для очистки DNS.')

def system_informer_bypass():
    bypass_window = ctk.CTkToplevel(root)
    bypass_window.title('SystemInformer bypass (beta)')
    bypass_window.geometry('400x350')
    bypass_window.resizable(False, False)
    bypass_window.grab_set()
    bypass_window.transient(root)
    bypass_window.lift()
    bypass_window.update_idletasks()
    screen_width = bypass_window.winfo_screenwidth()
    screen_height = bypass_window.winfo_screenheight()
    window_width = bypass_window.winfo_width()
    window_height = bypass_window.winfo_height()
    x = screen_width // 2 - window_width // 2
    y = screen_height // 2 - window_height // 2
    bypass_window.geometry(f'+{x}+{y}')
    services = {'dns': 'DNS', 'dps': 'DPS', 'diagtrace': 'DiagTrace', 'lsass': 'Lsass'}
    var_services = {name: ctk.BooleanVar() for name in services}
    for name, service in services.items():
        ctk.CTkCheckBox(bypass_window, text=service, variable=var_services[name]).pack(pady=5)

    def apply_bypass(action):
        for name, var in var_services.items():
            if var.get():
                reg_path = f'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\{services[name]}' if name!= 'lsass' else 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa'
                key_name = 'LaunchProtected' if name!= 'lsass' else 'RunAsPPL'
                if action == 'block':
                    subprocess.run(f'reg add \"{reg_path}\" /v {key_name} /t REG_DWORD /d 2 /f', shell=True)
                    subprocess.run('reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v RunAsPPL /t REG_DWORD /d 1 /f')
                    subprocess.run('netsh advfirewall firewall add rule name=\"Block LSASS Access\" dir=out action=block program=\"C:\\Windows\\System32\\lsass.exe\" enable=yes')
                    subprocess.run('netsh advfirewall firewall add rule name=\"Block LSASS Access\" dir=in action=block program=\"C:\\Windows\\System32\\lsass.exe\" enable=yes')
                    subprocess.run('reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\" /v UseLogonCredential /t REG_DWORD /d 0 /f')
                else:  
                    subprocess.run(f'reg delete \"{reg_path}\" /v {key_name} /f', shell=True)
                    subprocess.run('reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v RunAsPPL /t REG_DWORD /d 0 /f')
                    subprocess.run('netsh advfirewall firewall delete rule name=\"Block LSASS Access\" dir=out program=\"C:\\Windows\\System32\\lsass.exe\"')
                    subprocess.run('netsh advfirewall firewall delete rule name=\"Block LSASS Access\" dir=in program=\"C:\\Windows\\System32\\lsass.exe\"')
                    subprocess.run('reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\" /v UseLogonCredential /t REG_DWORD /d 1 /f')
        messagebox.showinfo('Успех', 'Успешно, перезагрузите ПК чтобы изменения вступили в силу')
        bypass_window.destroy()

    def block_updates():
        hosts_path = 'C:\\Windows\\System32\\drivers\\etc\\hosts'
        entries = ['127.0.0.1 systeminformer.dev', '127.0.0.1 www.systeminformer.dev', '127.0.0.1 104.21.85.212', '127.0.0.1 172.67.211.103']
        try:
            win32api.SetFileAttributes(hosts_path, win32con.FILE_ATTRIBUTE_NORMAL)
            with open(hosts_path, 'r', encoding='utf-8') as file:
                hosts_content = file.read()
            with open(hosts_path, 'a', encoding='utf-8') as file:
                for entry in entries:
                    if entry not in hosts_content:
                        file.write(f'\n{entry}')
                        print(f'Добавлена строка: {entry}')
            win32api.SetFileAttributes(hosts_path, win32con.FILE_ATTRIBUTE_SYSTEM | win32con.FILE_ATTRIBUTE_HIDDEN | win32con.FILE_ATTRIBUTE_READONLY)
            os.system('ipconfig /flushdns')
            print('Кэш DNS успешно очищен.')
            messagebox.showinfo('Успех', 'Обновления SystemInformer заблокированы.')
        except PermissionError:
            messagebox.showerror('Ошибка', 'Запустите программу с правами администратора.')
        except Exception as e:
            messagebox.showerror('Ошибка', f'Произошла ошибка: {e}')
    ctk.CTkButton(bypass_window, text='Заблокировать', command=lambda: apply_bypass('block')).pack(pady=10)
    ctk.CTkButton(bypass_window, text='Разблокировать', command=lambda: apply_bypass('unblock')).pack(pady=10)
    ctk.CTkButton(bypass_window, text='Запретить обновления', command=block_updates).pack(pady=10)

def find_all_anydesk_processes():
    anydesk_processes = []
    for proc in psutil.process_iter(attrs=['pid', 'name']):
        if 'anydesk' in proc.info['name'].lower():
            anydesk_processes.append(proc)
    return anydesk_processes

def anydesk_lag_thread(stop_event):
    print('Ожидание 60 секунд перед началом лагов...')
    time.sleep(60)
    while not stop_event.is_set():
        print('Поиск процессов AnyDesk...')
        lag_all_anydesk_processes()

def lag_all_anydesk_processes():
    anydesk_processes = find_all_anydesk_processes()
    if anydesk_processes:
        for proc in anydesk_processes:
            try:
                print(f'Приостанавливаем процесс AnyDesk (PID: {proc.pid}) на 5 секунд...')
                proc.suspend()
            except (psutil.NoSuchProcess, psutil.AccessDenied, Exception) as e:
                print(f'Ошибка при приостановке процесса AnyDesk (PID: {proc.pid}): {e}')
                continue
        time.sleep(5)
        for proc in anydesk_processes:
            try:
                print(f'Возобновляем процесс AnyDesk (PID: {proc.pid})...')
                proc.resume()
            except (psutil.NoSuchProcess, psutil.AccessDenied, Exception) as e:
                print(f'Ошибка при возобновлении процесса AnyDesk (PID: {proc.pid}): {e}')
    else:
        print('Не удалось найти процессы AnyDesk. Повторная попытка через 2 секунды...')
        time.sleep(2)

def limit_anydesk_resources(pid):
    try:
        process = psutil.Process(pid)
        process.nice(psutil.IDLE_PRIORITY_CLASS)
        print(f'Установлен минимальный приоритет для процесса AnyDesk (PID: {pid}).')
        process.cpu_percent(interval=1.0)
        while True:
            if process.cpu_percent(interval=1.0) > 1:
                process.suspend()
                time.sleep(0.1)
                process.resume()
    except psutil.NoSuchProcess:
        print('Процесс AnyDesk завершен.')
        return
    except Exception as e:
        print(f'Ошибка при ограничении ресурсов AnyDesk: {e}')
        return None
    else:  
        pass

def kill_browser_processes():
    browsers = ['chrome.exe', 'msedge.exe', 'opera.exe', 'yandexbrowser.exe', 'brave.exe', 'firefox.exe']
    for proc in psutil.process_iter(attrs=['pid', 'name']):
        if proc.info['name'].lower() in browsers:
            try:
                process = psutil.Process(proc.info['pid'])
                process.terminate()
                process.wait(timeout=5)
            except psutil.NoSuchProcess:
                continue
            except psutil.TimeoutExpired:
                print(f"Процесс {proc.info['name']} не закрылся сразу, попробую снова.")
                process.terminate()
            except Exception as e:
                print(f"Ошибка при завершении процесса {proc.info['name']}: {e}")
    sleep(2)

def clean_browser_history():
    BROWSERS = {'Chrome': os.path.expanduser('~\\AppData\\Local\\Google\\Chrome\\User Data\\Default'), 'Edge': os.path.expanduser('~\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default'), 'Opera': os.path.expanduser('~\\AppData\\Roaming\\Opera Software\\Opera Stable'), 'Yandex': os.path.expanduser('~\\AppData\\Local\\Yandex\\YandexBrowser\\User Data\\Default'), 'Brave': os.path.expanduser('~\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default')}
    FIREFOX_PATH = os.path.expanduser('~\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles')
    KEYWORDS = ['blasted', 'nemezida', 'spoofer', 'sechex', 'akcel', 'euphoria', 'bebra', 'funpay', 'cheatlist', 'skalka']

    def clean_sqlite_db(db_path, queries):
        if os.path.exists(db_path):
            try:
                backup_path = db_path + '.bak'
                shutil.copy(db_path, backup_path)
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                for query, param in queries:
                    cursor.execute(query, param)
                conn.commit()
                cursor.execute('VACUUM')
                conn.commit()
                conn.close()
                print(f'Очищено: {db_path}')
            except Exception as e:
                pass  
            print(f'Ошибка при очистке {db_path}: {e}')

    def clean_chromium():
        for browser, path in BROWSERS.items():
            history_path = os.path.join(path, 'History')
            downloads_db = os.path.join(path, 'DownloadMetadata')
            if os.path.exists(history_path):
                queries = []
                for keyword in KEYWORDS:
                    queries.extend([('DELETE FROM urls WHERE url LIKE ?', (f'%{keyword}%',)), ('DELETE FROM urls WHERE title LIKE ?', (f'%{keyword}%',)), ('DELETE FROM downloads WHERE tab_url LIKE ?', (f'%{keyword}%',)), ('DELETE FROM downloads WHERE target_path LIKE ?', (f'%{keyword}%',))])
                clean_sqlite_db(history_path, queries)
            if os.path.exists(downloads_db):
                try:
                    os.remove(downloads_db)
                    print(f'Удален DownloadMetadata для {browser}')
                except Exception as e:
                    pass  
            print(f'Ошибка удаления DownloadMetadata ({browser}): {e}')
            pass

    def clean_firefox():
        if os.path.exists(FIREFOX_PATH):
            for profile in os.listdir(FIREFOX_PATH):
                profile_path = os.path.join(FIREFOX_PATH, profile)
                history_path = os.path.join(profile_path, 'places.sqlite')
                if os.path.exists(history_path):
                    queries = []
                    for keyword in KEYWORDS:
                        queries.extend([('DELETE FROM moz_places WHERE url LIKE ?', (f'%{keyword}%',)), ('DELETE FROM moz_places WHERE title LIKE ?', (f'%{keyword}%',)), ('DELETE FROM moz_annos WHERE content LIKE ?', (f'%{keyword}%',))])
                    clean_sqlite_db(history_path, queries)
    kill_browser_processes()
    clean_chromium()
    clean_firefox()
    print('Очистка завершена!')
    messagebox.showinfo('Успех', 'История браузеров успешно очищена!')

def clear_usn_journal_ps(drive: str='C'):
    try:
        cmd = f'powershell -Command \"fsutil usn deletejournal /D {drive}:\"'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        print(result.stdout)
        print(result.stderr)
        messagebox.showinfo('Успех', 'Журнал USN успешно очищен.')
    except Exception as e:
        print(f'Ошибка: {e}')
        messagebox.showerror('Ошибка', f'Не удалось очистить журнал USN: {e}')
        return None

def choose_key_combination():
    key_window = ctk.CTkToplevel(root)
    key_window.title('Выбор сочетания клавиш')
    key_window.geometry('400x300')
    key_window.resizable(False, False)
    key_window.grab_set()
    key_window.transient(root)
    key_window.lift()
    key_window.update_idletasks()
    screen_width = key_window.winfo_screenwidth()
    screen_height = key_window.winfo_screenheight()
    window_width = key_window.winfo_width()
    window_height = key_window.winfo_height()
    x = screen_width // 2 - window_width // 2
    y = screen_height // 2 - window_height // 2
    key_window.geometry(f'+{x}+{y}')

    selected_keys = []
    key_labels = []

    def on_key(event):
        if len(selected_keys) >= 2:
            return
        
        key = event.keysym.upper()
        if key in ['CONTROL_L', 'CONTROL_R']:
            key = 'CTRL'
        elif key in ['ALT_L', 'ALT_R']:
            key = 'ALT'
        elif key in ['SHIFT_L', 'SHIFT_R']:
            key = 'SHIFT'
        
        if key not in selected_keys:
            selected_keys.append(key)
            update_labels()

    def update_labels():
        for label in key_labels:
            label.destroy()
        key_labels.clear()
        
        for i, key in enumerate(selected_keys):
            label = ctk.CTkLabel(key_window, text=f'Клавиша {i+1}: {key}', font=('Arial', 14))
            label.pack(pady=5)
            key_labels.append(label)

    def apply_keys():
        global global_key1, global_key2
        if len(selected_keys) != 2:
            messagebox.showerror('Ошибка', 'Выберите две клавиши!')
            return

        key_mapping = {
            'CTRL': win32con.VK_CONTROL,
            'ALT': win32con.VK_MENU,
            'SHIFT': win32con.VK_SHIFT,
            'F1': win32con.VK_F1,
            'F2': win32con.VK_F2,
            'F3': win32con.VK_F3,
            'F4': win32con.VK_F4,
            'F5': win32con.VK_F5,
            'F6': win32con.VK_F6,
            'F7': win32con.VK_F7,
            'F8': win32con.VK_F8,
            'F9': win32con.VK_F9,
            'F10': win32con.VK_F10,
            'F11': win32con.VK_F11,
            'F12': win32con.VK_F12
        }

        for i in range(ord('A'), ord('Z') + 1):
            key_mapping[chr(i)] = i

        key1, key2 = selected_keys
        if key1 in key_mapping and key2 in key_mapping:
            global_key1 = key_mapping[key1]
            global_key2 = key_mapping[key2]
            choose_keys_button.configure(text=f'{key1} + {key2}')
            messagebox.showinfo('Успех', f'Сочетание клавиш изменено на: {key1} + {key2}')
            save_config()
            key_window.destroy()
        else:
            messagebox.showerror('Ошибка', 'Некорректные клавиши!')

    def clear_keys():
        selected_keys.clear()
        update_labels()

    ctk.CTkLabel(key_window, text='Нажмите две клавиши для комбинации', font=('Arial', 14)).pack(pady=20)
    
    clear_button = ctk.CTkButton(key_window, text='Очистить', command=clear_keys, font=('Arial', 14))
    clear_button.pack(pady=10)
    
    apply_button = ctk.CTkButton(key_window, text='Применить', command=apply_keys, font=('Arial', 14))
    apply_button.pack(pady=10)

    key_window.bind('<Key>', on_key)

def get_key_name(key_code):
    key_mapping = {win32con.VK_CONTROL: 'CTRL', win32con.VK_LCONTROL: 'LCTRL', win32con.VK_RCONTROL: 'RCTRL', win32con.VK_MENU: 'ALT', win32con.VK_LMENU: 'LALT', win32con.VK_RMENU: 'RALT', win32con.VK_SHIFT: 'SHIFT', win32con.VK_LSHIFT: 'LSHIFT', win32con.VK_RSHIFT: 'RSHIFT', win32con.VK_F1: 'F1', win32con.VK_F2: 'F2', win32con.VK_F3: 'F3', win32con.VK_F4: 'F4', win32con.VK_F5: 'F5', win32con.VK_F6: 'F6', win32con.VK_F7: 'F7', win32con.VK_F8: 'F8', win32con.VK_F9: 'F9', win32con.VK_F10: 'F10', win32con.VK_F11: 'F11', win32con.VK_F12: 'F12'}
    for i in range(ord('A'), ord('Z') + 1):
        key_mapping[i] = chr(i)
    for i in range(ord('0'), ord('9') + 1):
        key_mapping[i] = chr(i)
    return key_mapping.get(key_code, 'UNKNOWN')

def update_choose_keys_button():
    key1_name = get_key_name(global_key1)
    key2_name = get_key_name(global_key2)
    choose_keys_button.configure(text=f'{key1_name} + {key2_name}')

def animate_title(window, text, speed=100):
    full_text = text
    
    def type_text(index=0, forward=True):
        if forward:
            if index <= len(full_text):
                current_text = full_text[:index]
                window.title(current_text)
                window.after(speed, lambda: type_text(index + 1, True))
            else:
                window.after(500, lambda: type_text(len(full_text), False))
        else:
            if index > 0:
                current_text = full_text[:index]
                window.title(current_text)
                window.after(speed, lambda: type_text(index - 1, False))
            else:
                window.after(500, lambda: type_text(0, True))
    
    type_text()

def open_source_code():
    webbrowser.open('https://github.com/idreiki/Proverka-Helper')  

def open_discord():
    webbrowser.open('https://discord.gg/49XB7MqK')  

def create_gui():
    global text_area 
    global root 
    global clear_browser_history_button 
    global clear_dns_button  
    global button_start_stop  
    global check_service_var  
    global check_service_check  
    global discord_check  
    global anydesk_lag_var  
    global choose_keys_button 
    global discord_var 
    global clear_journal_trace_button  
    global anydesk_lag_check 
    global block_ocean_check 
    ctk.set_appearance_mode('dark')
    ctk.set_default_color_theme('dark-blue')
    root = ctk.CTk()
    root.title('')  
    root.geometry('840x670')
    root.resizable(False, False)
    root.protocol('WM_DELETE_WINDOW', root.quit)
    animate_title(root, 'Рrоvеrka Hеlреr | v2.1 | Dumped by DS:syperlox')
    frame_left = ctk.CTkFrame(root)
    frame_left.pack(side='left', fill='both', expand=True, padx=10, pady=10)
    frame_right = ctk.CTkFrame(root)
    frame_right.pack(side='right', fill='both', expand=True, padx=10, pady=10)
    ctk.CTkLabel(frame_left, text='Введите названия окон программ (каждое с новой строки), они не запустятся', font=('Arial', 15)).pack(pady=3)
    ctk.CTkLabel(frame_left, text='Оставьте только те проги, в которых у вас читы, остальные удалите!!!', font=('Arial', 14)).pack(pady=3)
    text_area = ctk.CTkTextbox(frame_left, width=500, height=300, font=('Arial', 18))
    text_area.pack(pady=10)
    text_area.insert('end', '\n'.join(program_titles))
    check_service_var = ctk.BooleanVar(value=check_service)
    check_service_check = ctk.CTkCheckBox(frame_left, text='Отключить использование данных', variable=check_service_var, command=toggle_service_check, font=('Arial', 18))
    check_service_check.pack(pady=10)
    block_ocean_check = ctk.CTkCheckBox(frame_left, text='Заблокировать Ocean', font=('Arial', 18))
    block_ocean_check.pack(pady=10)
    discord_var = ctk.BooleanVar(value=False)
    discord_check = ctk.CTkCheckBox(frame_left, text='Закрывать Discord', variable=discord_var, font=('Arial', 18))
    discord_check.pack(pady=10)
    anydesk_lag_var = ctk.BooleanVar(value=False)
    anydesk_lag_check = ctk.CTkCheckBox(frame_left, text='Лаги AnyDesk', variable=anydesk_lag_var, font=('Arial', 18))
    anydesk_lag_check.pack(pady=10)
    button_start_stop = ctk.CTkButton(frame_left, text='НАЧАТЬ', command=start_stop_check, width=160, height=40, corner_radius=20, font=('Arial', 18))
    button_start_stop.pack(pady=20, side='bottom', anchor='s')
    clear_dns_button = ctk.CTkButton(frame_right, text='Очистить DNS', command=clear_dns_cache, width=160, height=40, corner_radius=20, font=('Arial', 18))
    clear_dns_button.pack(pady=15)
    clear_dns_button.configure(state='normal')
    clear_browser_history_button = ctk.CTkButton(frame_right, text='Очистить BrowserHistory', command=clean_browser_history, width=160, height=40, corner_radius=20, font=('Arial', 18))
    clear_browser_history_button.pack(pady=15)
    clear_journal_trace_button = ctk.CTkButton(frame_right, text='Очистить JournalTrace', command=lambda: clear_usn_journal_ps('C'), width=160, height=40, corner_radius=20, font=('Arial', 18))
    clear_journal_trace_button.pack(pady=15)
    system_informer_button = ctk.CTkButton(frame_right, text='SystemInformer bypass', command=system_informer_bypass, width=160, height=40, corner_radius=20, font=('Arial', 18))
    system_informer_button.pack(pady=15)
    source_button = ctk.CTkButton(frame_right, text='Source Code', command=open_source_code, width=160, height=40, corner_radius=20, font=('Arial', 18))
    source_button.pack(pady=15)
    discord_button = ctk.CTkButton(frame_right, text='Discord', command=open_discord, width=160, height=40, corner_radius=20, font=('Arial', 18))
    discord_button.pack(pady=15)
    choose_keys_button = ctk.CTkButton(frame_right, text='', command=choose_key_combination, width=160, height=40, corner_radius=20, font=('Arial', 18))
    choose_keys_button.pack(pady=20, side='bottom', anchor='s')
    update_choose_keys_button()
    root.update_idletasks()
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    window_width = root.winfo_width()
    window_height = root.winfo_height()
    x = screen_width // 2 - window_width // 2
    y = screen_height // 2 - window_height // 2
    root.geometry(f'+{x}+{y}')
    listener = keyboard.Listener(on_press=on_press)
    listener.start()
    threading.Timer(1.0, delete_file_after_gui).start()
    root.mainloop()
    remove_prefetch_trace()
if __name__ == '__main__':
    load_config()
    if check_if_program_is_running():
        print('Программа уже запущена.')
        sys.exit(0)
    if not is_admin():
        messagebox.showerror('Ошибка', 'Программу необходимо запустить с правами администратора!')
        restart_as_admin()
        sys.exit(0)
    main_thread = threading.Thread(target=run_main_code, daemon=True)
    main_thread.start()
    set_thread_name('svchost.exe')
    main_thread.join()
    try:
        if socket_lock:
            socket_lock.close()
    except Exception as e:
        pass  
    print(f'Ошибка при закрытии сокета: {e}')