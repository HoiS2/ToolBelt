# pcap-checker

## Подготовка окружения
1. Создать и активировать виртуальное окружение.

python3 -m venv venv
source venv/bin/activate

2. Установить необходимые библеотеки.

pip install scapy
pip install argparse

## Использование
usage: pcap-checker.py [--white-list=WhiteListName.txt] filiname (или маска: *.pcap)

options
  --white-list=         
                        Учитывает при анализе pcap файла белый список IP-адресов.