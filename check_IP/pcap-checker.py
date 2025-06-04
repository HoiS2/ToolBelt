import sys
import glob
import os
import argparse
from scapy.all import PcapReader, IP
from datetime import datetime

def canonical_ip(ip_str):
    """Приводит IP-адрес к каноническому виду (убирает ведущие нули)"""
    try:
        parts = ip_str.split('.')
        if len(parts) != 4:
            return None
        nums = []
        for p in parts:
            num = int(p)
            if num < 0 or num > 255:
                return None
            nums.append(str(num))
        return ".".join(nums)
    except:
        return None

def load_white_list(filename):
    """Загружает белый список IP из файла"""
    white_list = {}
    with open(filename, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line[0].isdigit():
                parts = line.split(maxsplit=1)
                candidate = parts[0]
                canon_ip = canonical_ip(candidate)
                if canon_ip is None:
                    continue
                comment = line[len(candidate):].strip()
                if comment.startswith('-'):
                    comment = comment[1:].strip()
                white_list[canon_ip] = comment
    return white_list

def get_ip_group(ip):
    """Определяет группу IP-адреса"""
    try:
        parts = list(map(int, ip.split('.')))
    except:
        return "other"
    
    first = parts[0]
    if first == 10:
        return "10.0.0.0/8 (private)"
    if first == 172 and 16 <= parts[1] <= 31:
        return "172.16.0.0/12 (private)"
    if first == 192 and parts[1] == 168:
        return "192.168.0.0/16 (private)"
    if first == 127:
        return "127.0.0.0/8 (loopback)"
    if 224 <= first <= 239:
        return "224.0.0.0/4 (multicast)"
    if first == 169 and parts[1] == 254:
        return "169.254.0.0/16 (link-local)"
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24 (public)"

def group_ips_by_range(ip_set):
    """Группирует IP-адреса по диапазонам"""
    groups = {}
    for ip in ip_set:
        group = get_ip_group(ip)
        if group not in groups:
            groups[group] = set()
        groups[group].add(ip)
    return groups

def process_pcap(file_path, white_list_dict=None):
    """Обрабатывает pcap-файл и анализирует IP-адреса"""
    try:
        unique_ips = set()
        white_ips_in_file = {}
        non_white_ips = set()

        with PcapReader(file_path) as packets:
            for pkt in packets:
                if IP in pkt:
                    src = pkt[IP].src
                    dst = pkt[IP].dst
                    unique_ips.add(src)
                    unique_ips.add(dst)

        if white_list_dict:
            for ip in unique_ips:
                canon_ip = canonical_ip(ip)
                if canon_ip and canon_ip in white_list_dict:
                    white_ips_in_file[canon_ip] = white_list_dict[canon_ip]
                else:
                    non_white_ips.add(ip)
        else:
            non_white_ips = unique_ips

        return {
            'unique_ips': unique_ips,
            'white_ips': white_ips_in_file,
            'non_white_ips': non_white_ips,
            'error': None
        }
    except Exception as e:
        return {
            'unique_ips': None,
            'white_ips': None,
            'non_white_ips': None,
            'error': str(e)
        }

def generate_report(files, white_list_dict=None, white_list_output=None):
    """Генерирует отчет по анализу pcap-файлов"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"{timestamp}_report.txt"
    
    with open(report_filename, 'w', encoding='utf-8') as report_file:
        if white_list_output:
            print(white_list_output)
            report_file.write(white_list_output + "\n\n")
        
        for file_path in files:
            result = process_pcap(file_path, white_list_dict)
            
            output = [f"[Файл: {file_path}]"]
            
            if result['error']:
                output.append(f"  Ошибка обработки: {result['error']}")
            else:
                unique_ips = result['unique_ips']
                white_ips_in_file = result['white_ips']
                non_white_ips = result['non_white_ips']
                
                output.append(f"  Уникальных IP-адресов: {len(unique_ips)}")
                
                if white_list_dict:
                    output.append(f"  Из них в белом списке: {len(white_ips_in_file)}")
                    
                    if white_ips_in_file:
                        output.append("  IP-адреса из белого списка:")
                        for ip, comment in sorted(white_ips_in_file.items()):
                            if comment:
                                output.append(f"    {ip} - {comment}")
                            else:
                                output.append(f"    {ip}")
                    else:
                        output.append("  IP-адреса из белого списка не обнаружены.")
                    
                    output.append(f"  Остальные IP-адреса (всего {len(non_white_ips)}):")
                    groups = group_ips_by_range(non_white_ips)
                    
                    if groups:
                        for group, ips in sorted(groups.items()):
                            sorted_ips = sorted(ips)
                            output.append(f"    * {group} ({len(ips)}):")
                            
                            chunk_size = 5
                            for i in range(0, len(sorted_ips), chunk_size):
                                chunk = sorted_ips[i:i+chunk_size]
                                output.append("        " + ", ".join(chunk))
                    else:
                        output.append("    Нет других IP-адресов.")
                else:
                    output.append("  Диапазоны IP-адресов:")
                    groups = group_ips_by_range(unique_ips)
                    
                    if groups:
                        for group, ips in sorted(groups.items()):
                            sorted_ips = sorted(ips)
                            output.append(f"    * {group} ({len(ips)}):")
                            
                            chunk_size = 5
                            for i in range(0, len(sorted_ips), chunk_size):
                                chunk = sorted_ips[i:i+chunk_size]
                                output.append("        " + ", ".join(chunk))
                    else:
                        output.append("    Нет IP-адресов для отображения.")
            
            output.append("=" * 60)
            report_content = "\n".join(output)
            
            print(report_content)
            report_file.write(report_content + "\n")
    
    print(f"\nОтчет сохранен в файл: {report_filename}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Анализ pcap-файлов')
    parser.add_argument('pcap_files', nargs='+', 
                        help='pcap-файлы или маска (например, *.pcap)')
    parser.add_argument('--white-list', dest='white_list', metavar='FILE',
                        help='Файл белого списка IP-адресов')
    
    args = parser.parse_args()
    
    pcap_files = []
    for pattern in args.pcap_files:
        pcap_files.extend(glob.glob(pattern))
    
    pcap_files = [f for f in pcap_files if os.path.isfile(f) and 
                 os.path.splitext(f)[1].lower() in ('.pcap', '.pcapng')]
    
    if not pcap_files:
        print("Не найдено подходящих pcap-файлов для обработки")
        sys.exit(1)
    
    white_list_dict = {}
    white_list_output = None
    
    if args.white_list:
        if not os.path.isfile(args.white_list):
            print(f"Ошибка: файл белого списка '{args.white_list}' не найден")
            sys.exit(1)
        
        white_list_dict = load_white_list(args.white_list)
        lines = [f"Белый список (файл: {args.white_list}):"]
        for ip, comment in sorted(white_list_dict.items()):
            if comment:
                lines.append(f"  {ip} - {comment}")
            else:
                lines.append(f"  {ip}")
        white_list_output = "\n".join(lines)
    
    generate_report(pcap_files, white_list_dict, white_list_output)