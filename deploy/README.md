# Отдельный стенд FortiGate-VM

В контейнере работает официальный FortiOS на QEMU/KVM. Docker Compose создаёт management, LAN и DMZ. Учебный клиент и HTTP-сервер подключены к разным закрытым сетям. Доступ между ними регулирует сама VM.

## Подготовка

Нужны Linux x86-64 или WSL 2 с доступом к `/dev/kvm` и `/dev/net/tun`, Python 3, Git, Docker Engine 28+ и Compose 2.36+. Оставьте не менее 3 ГБ ОЗУ для этой VM и свободное место для локального образа и диска. Контейнер VM использует привилегии хоста для создания интерфейсов и сетевого пространства passthrough. Запускайте его на выделенном лабораторном хосте.

Скачайте разрешённый вам пакет **FortiGate-VM64 for KVM** из Fortinet Support. Извлеките исходный standalone `fortios.qcow2` в локальную папку. Выберите образ FortiOS 7.6.8 для этой версии шаблона. [Документация Fortinet по KVM](https://docs.fortinet.com/document/fortigate-private-cloud/7.6.0/kvm-administration-guide/659352/deploying-the-fortigate-vm)

```bash
cd deploy
cp -n .env.example .env
```

Для второй копии задайте в `.env` уникальные имя проекта, локальный тег образа, подсети и четыре порта. Поле `FORTIGATE_UUID` оставьте пустым при первом запуске. Скрипт один раз создаст отдельный UUID и затем использует его для этой VM. Management IP гостя и адрес управления контейнера должны совпадать для passthrough. На LAN и DMZ у гостя, контейнера и Docker bridge отдельные адреса.

```bash
(
  umask 077
  mkdir -p secrets
  if [ ! -e secrets/admin-password ]; then
    python3 -c 'import secrets; print(secrets.token_hex(20) + "Aa9!")' > secrets/admin-password
  fi
)
bash scripts/build-fortigate.sh /absolute/path/to/fortios.qcow2
bash scripts/start.sh
bash scripts/status.sh
```

Скрипт сборки проверяет формат диска и закреплённый коммит адаптера vrnetlab. Образ Docker остаётся на локальном хосте. Файл исходной прошивки и локальный образ с ней храните у себя. Скрипт запуска сохраняет настройки в локальном диске `state/vm`. Стартовая конфигурация создаётся один раз из `config/startup.conf.template`.

## Штатный вход и проверка

`scripts/start.sh` ждёт готовности контейнеров и ответа страницы входа FortiOS по HTTPS. После завершения скрипта откройте `https://127.0.0.1:18843/` на хосте VM. Для доступа с другого компьютера пробросьте этот порт через SSH.

```sh
ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:18843:127.0.0.1:18843 my-lab-host
```

Войдите в FortiOS как `admin` с локальным паролем стенда. Для штатного HTTPS используйте доверенный сертификат или настройте доверие к сертификату своего стенда. Выполните разрешённую активацию VM по [инструкции Fortinet](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/441460/permanent-trial-mode-for-fortigate-vm). Штатный Dashboard и доступные возможности определяются установленной версией и лицензией.

Новый стенд загружает адресные объекты `LAB-LAN-NET` и `LAB-DMZ-NET` из подсетей в `.env`. В **Policy & Objects → Firewall Policy** правило `LAB-LAN-DMZ-HTTP` разрешает HTTP на порту 80, а `LAB-LAN-DMZ-DENY-8080` блокирует TCP 8080. Учебный сервер в DMZ отвечает на обоих портах. После активации запустите проверку из каталога `deploy`.

```bash
bash scripts/verify-forwarding.sh
```

Скрипт сначала проверяет оба порта непосредственно с сервера, затем проверяет доступ с клиента в LAN. Сравните события политик 1 и 2 в **Log & Report → Forward Traffic**. Журнал сохраняется в памяти FortiOS.

Для остановки используйте `bash scripts/stop.sh`, для повторного запуска — `bash scripts/start.sh`. Эти команды используют сохранённые диски и настройки. Если меняете пароль `admin` в FortiOS, обновите локальный файл пароля перед перезапуском. В рабочей VM делайте резервную копию через родное меню FortiOS и храните её вне Git. Чтобы поднять чистый стенд отдельно, начните с новой копии шаблона, чистого официального диска и отдельной разрешённой активации.
