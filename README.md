# FortiGate Lab Template

Шаблон для настоящего FortiGate-VM. Конфигурация, политики, логи и дашборд открываются в штатном FortiOS. Репозиторий содержит развёртывание, локальный доступ и автоматизацию производителя. Образ FortiOS предоставляется владельцем через Fortinet Support и хранится на машине лаборатории.

При новом развёртывании нативная страница входа по умолчанию открывается на `https://127.0.0.1:18843/` на хосте VM. В [отдельном учебном стенде](deploy/README.md) есть адресные объекты LAN и DMZ, правила с разрешением и запретом и проверка трафика между двумя контейнерами.

## Подключить существующую лабораторию

Откройте её обычный адрес FortiGate через локальный SSH-туннель. Пример для лаборатории, где уже работает локальный мост входа:

```powershell
.\scripts\Open-NativeFortiGate.ps1 -SshHost my-lab-host -LocalPort 18787 -RemotePort 8787 -ExistingLabBridge
python scripts/check-native.py --port 18787
```

Проверка открывает штатный `/system/dashboard/1` и читает версию из REST API тем же локальным маршрутом. Для нового стенда используйте проброс HTTPS и обычный вход FortiOS. Параметр `-ExistingLabBridge` предназначен для уже настроенного моста `/_lab/open`.

## Подключить Fortinet к репозиторию

В `automation/requirements.yml` закреплена коллекция **fortinet.fortios 2.6.0** по коммиту из GitHub Fortinet. Playbook `automation/audit.yml` штатными модулями производителя получает версию устройства и количество действующих записей в таблице политик. Он выполняется рядом со стендом. [Исходная коллекция Fortinet](https://github.com/fortinet-ansible-dev/ansible-galaxy-fortios-collection/tree/5174d341626cb099a079b18276906f3f91f4a110)

```bash
bash automation/install.sh
source .venv/bin/activate
cd automation
cp inventory.example.yml inventory.local.yml
```

В локальном inventory укажите адрес лабораторного FortiOS по HTTPS. Используйте имя из его сертификата и доверенный CA. Для автоматизации подготовьте на устройстве API-администратора с правами чтения и ограничением Trusted Hosts. Передайте его токен в переменной `FORTIOS_ACCESS_TOKEN` локального процесса. [Документация Fortinet по REST API](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/940602/using-apis)

```bash
ANSIBLE_CONFIG="$PWD/ansible.cfg" ansible-playbook -i inventory.local.yml audit.yml
```

Если на хосте уже настроен и проверен локальный мост для этой VM, `bash audit-loopback.sh PORT /path/to/local-password-file` использует существующий файл учётных данных на этом хосте. Playbook выводит только версию, билд и число политик. Файл и токен хранятся локально. GitHub Actions устанавливает закреплённую коллекцию и проверяет синтаксис. Сам FortiGate опрашивается с локальной машины.

## Развернуть отдельный стенд

В GitHub выберите **Use this template**, затем следуйте [инструкции по развёртыванию](deploy/README.md). В ней описаны подготовка официального KVM-образа, отдельные сети, запуск, вход в FortiOS и применение стартовой конфигурации. [Fortinet KVM Deployment Guide](https://docs.fortinet.com/document/fortigate-private-cloud/7.6.0/kvm-administration-guide/659352/deploying-the-fortigate-vm)

FortiOS проверяет лицензию самостоятельно. Для бесплатной лаборатории используется официальная evaluation-лицензия в её штатных пределах. Новому экземпляру требуется собственная разрешённая активация.
