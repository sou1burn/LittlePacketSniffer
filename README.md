# Сниффер пакетов с распределением по обработчикам и простой генератор трафика на Python

Для запуска исходников:
```
cmake .
cd build 
make 

sudo ./main [interface_name]
```
## Для запуска генератора трафика:
```
usage: trafic_gen.py [-h] [--port PORT] {TCP,UDP,FTP} [{TCP,UDP,FTP} ...] [sessions]

Генератор трафика (TCP, UDP, FTP)

positional arguments:
  {TCP,UDP,FTP}  Типы трафика (можно указать несколько)
  sessions       Количество генерируемых сессий

options:
  -h, --help     show this help message and exit
  --port PORT    Сетевой порт клиента (опционально)
```

Пример запуска:
```
python3 ./trafic_gen.py TCP UDP FTP 10 --port 5001
```
