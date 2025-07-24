import subprocess
import sys
import os


def install_requirements():
    """
    Installs the required dependencies from requirements.txt.
    :return:
    None
    """
    print("Встановлення залежностей...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])


def run_server():
    """
    Runs the chat server.
    :return:
    None
    """
    print("Запуск чат-сервера...")
    print("Сервер буде доступний за адресою: http://localhost:5000")
    print("Для зупинки натисніть Ctrl+C")

    if not os.path.exists('app.py'):
        print("Помилка: файл app.py не знайдено!")
        return

    subprocess.run([sys.executable, "app.py"])


if __name__ == "__main__":
    try:
        install_requirements()
        run_server()
    except KeyboardInterrupt:
        print("\nСервер зупинено.")
    except Exception as e:
        print(f"Помилка: {e}")
