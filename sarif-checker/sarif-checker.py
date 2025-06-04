import argparse
import json
import os
import glob
from collections import Counter

def extract_comments(obj, comments_list):
    """Рекурсивно извлекает комментарии из JSON-структуры"""
    if isinstance(obj, dict):
        if "comments" in obj and isinstance(obj["comments"], list):
            for comment in obj["comments"]:
                if isinstance(comment, str) and comment:
                    comments_list.append(comment)
        for value in obj.values():
            extract_comments(value, comments_list)
    elif isinstance(obj, list):
        for item in obj:
            extract_comments(item, comments_list)

def process_sarif_file(file_path):
    """Обрабатывает один SARIF-файл и возвращает статистику комментариев"""
    with open(file_path, 'r', encoding='utf-8') as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            print(f"Ошибка: Файл {file_path} не является валидным JSON")
            return None
    
    all_comments = []
    extract_comments(data, all_comments)
    return Counter(all_comments)

def main():
    parser = argparse.ArgumentParser(description='Анализ комментариев в SARIF-файлах')
    parser.add_argument('patterns', nargs='+', help='Маски для поиска SARIF-файлов (например: *.sarif)')
    args = parser.parse_args()

    # Собираем все файлы по указанным маскам
    sarif_files = []
    for pattern in args.patterns:
        sarif_files.extend(glob.glob(pattern, recursive=True))
    
    # Убираем дубликаты и сортируем
    sarif_files = sorted(set(sarif_files))
    
    if not sarif_files:
        print("Не найдено ни одного SARIF-файла по указанным маскам")
        return

    print(f"Найдено SARIF-файлов: {len(sarif_files)}\n")
    
    for file_path in sarif_files:
        if not os.path.isfile(file_path):
            print(f"Предупреждение: Файл {file_path} не найден, пропускаем")
            continue
        
        print(f"Обработка файла: {file_path}")
        counter = process_sarif_file(file_path)
        if counter is None:
            continue
        
        # Формируем имя файла отчета
        report_file = f"{file_path}.report"
        
        # Выводим результаты на экран
        print(f"  Уникальные комментарии: {len(counter)}")
        for comment, count in counter.items():
            print(f"  - [{count}] {comment}")
        
        # Сохраняем отчет в файл
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(f"Отчет по файлу: {file_path}\n")
            f.write("=" * 50 + "\n")
            f.write(f"Всего уникальных комментариев: {len(counter)}\n\n")
            for comment, count in counter.items():
                f.write(f"- [{count}] {comment}\n")
        
        print(f"Отчет сохранен в файл: {report_file}\n")

if __name__ == "__main__":
    main()