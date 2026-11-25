# VPN_Scripts

Три независимых bash-скрипта для развёртывания VPN/прокси-сервера **одной командой** на Debian/Ubuntu. Каждый скрипт сам ставит бинарник, генерирует ключи/пользователей, пишет конфиг и systemd-юнит, открывает порт в файрволе, прогоняет end-to-end самотест и печатает готовые клиентские ссылки.

| Скрипт | Протокол | Порт по умолчанию | Сервис | Рабочая папка (ссылки) | Документация |
|---|---|---|---|---|---|
| `deploy-xray.sh` | Xray VLESS + REALITY | **443/tcp** | `xray` | `/root/xray-deploy` | [xray.md](xray.md) |
| `deploy-hysteria2.sh` | Hysteria2 (QUIC, HTTP/3-маскировка) | **443/udp** | `hysteria-server` | `/root/hysteria2-deploy` | [hysteria2.md](hysteria2.md) |
| `deploy-trusttunnel.sh` | TrustTunnel (протокол AdGuard VPN, HTTP/2 + HTTP/3) | **8443/tcp+udp** | `trusttunnel` | `/root/trusttunnel-deploy` | [trusttunnel.md](trusttunnel.md) |

Скрипты спроектированы так, чтобы работать на одном сервере **одновременно** (порты по умолчанию не пересекаются: Xray — TCP 443, Hysteria2 — UDP 443, TrustTunnel — 8443).

## Требования

- Debian 11/12 или Ubuntu 20.04/22.04/24.04 с systemd
- запуск от **root** (или через `sudo`)
- доступ сервера в интернет (скачивание бинарников с GitHub, определение внешнего IP)
- архитектура: Hysteria2 и TrustTunnel — x86_64 и arm64; Xray по умолчанию скачивает сборку `Xray-linux-64` (только x86_64), для других архитектур передайте свой бинарник через `--bin`

## Установка одной командой

```bash
# Xray VLESS+REALITY  (TCP 443)
curl -fsSL https://raw.githubusercontent.com/alexsys87/VPN_Scripts/main/deploy-xray.sh | sudo bash

# Hysteria2  (UDP 443)
curl -fsSL https://raw.githubusercontent.com/alexsys87/VPN_Scripts/main/deploy-hysteria2.sh | sudo bash

# TrustTunnel  (TCP+UDP 8443)
curl -fsSL https://raw.githubusercontent.com/alexsys87/VPN_Scripts/main/deploy-trusttunnel.sh | sudo bash
```

После завершения скрипт печатает ссылки (`vless://`, `hysteria2://`, `tt://`) и сохраняет их в `links.txt` в рабочей папке. Ссылки можно импортировать в клиент вручную или по QR-коду из терминала.

### Передача параметров при запуске через pipe

Параметры передаются после `bash -s --`:

```bash
curl -fsSL https://raw.githubusercontent.com/alexsys87/VPN_Scripts/main/deploy-xray.sh \
  | sudo bash -s -- --port 8443 --clients 5
```

### Скачать, прочитать, затем запустить

```bash
curl -fsSLO https://raw.githubusercontent.com/alexsys87/VPN_Scripts/main/deploy-xray.sh
less deploy-xray.sh
sudo bash deploy-xray.sh --help      # справка работает только из сохранённого файла
sudo bash deploy-xray.sh
```

## Как сменить порт

Порт задаётся параметром `--port`. Смена порта = повторный запуск скрипта с новым значением. Ключи, пароли и UUID при этом **сохраняются** (ссылки меняются только номером порта).

| Скрипт | Как сменить | Что нужно знать |
|---|---|---|
| Xray | `bash deploy-xray.sh --port 8443` | Порт и SNI **не читаются** из существующего конфига — при каждом запуске передавайте `--port` (и `--sni`, если он не по умолчанию), иначе вернутся 443 и `www.bing.com`. Так же для `--check`, `--fix`, `--uninstall`. |
| Hysteria2 | `bash deploy-hysteria2.sh --port 8443` | Без `--port` повторный запуск оставляет прежний порт (хранится в `/etc/hysteria/.deploy-state`). Диапазон `--hop` запоминается. |
| TrustTunnel | `bash deploy-trusttunnel.sh --port 9443` | Без `--port` оставляет прежний порт (`/opt/trusttunnel/.deploy-state`). Порт открывается и для TCP, и для UDP. |

После смены порта:

1. Раздайте клиентам **новые ссылки** из `links.txt`.
2. Скрипты открывают новый порт, но не закрывают правило для старого порта — проверьте и при необходимости удалите его вручную (`ufw status`, `iptables -S INPUT`, `nft list ruleset`).
3. Если у вашего хостинга есть внешний файрвол/security group — откройте новый порт и там.

Подробнее и с примерами — в документации каждого скрипта.

## Общие параметры

Эти параметры есть у всех трёх скриптов:

| Параметр | Действие |
|---|---|
| `--port PORT` | порт прослушивания |
| `--ip IP` | внешний IP для ссылок (по умолчанию определяется автоматически) |
| `--clients N` | число пользователей (по умолчанию 3) |
| `--name PREFIX` | префикс имён пользователей/меток |
| `--workdir DIR` | куда сохранять `links.txt` и бэкапы |
| `--force` | сбросить и перегенерировать ключи/пароли (старые ссылки перестанут работать) |
| `--check` | диагностика без изменений |
| `--fix` | диагностика + безопасное автоисправление (рестарт сервиса, файрвол, hardening); конфиг и ключи не трогает |
| `--uninstall` | удалить сервис, конфиги и правила файрвола |
| `--no-harden` | не применять сетевой hardening (keepalive/MTU probing/MSS clamp/UDP-буферы) |
| `--dry-run` | сгенерировать конфиг и ссылки, систему не менять |
| `-h`, `--help` | справка |

## Повторный запуск безопасен

По умолчанию скрипты идемпотентны: повторный запуск переиспользует существующие ключи, пароли и сертификат, обновляет сервис и **не ломает клиентские ссылки**. Если самотест после изменений не прошёл, Xray и Hysteria2 откатываются на предыдущий конфиг.

## Как обновить программы на сервере

Подробные команды, проверка и откат — в документации каждого скрипта. Коротко:

| Что | Как обновить | Что сохраняется |
|---|---|---|
| Xray-core | вручную заменить `/usr/local/bin/xray` и geo-данные, `systemctl restart xray` ([инструкция](xray.md#как-обновить-xray-на-сервере)). Повторный запуск скрипта бинарник **не обновляет** | конфиг, ключи, ссылки |
| Hysteria 2 | `sudo env HY_VERSION=<версия> bash deploy-hysteria2.sh` ([инструкция](hysteria2.md#как-обновить-hysteria-2-на-сервере)) | пароли, сертификат, порт, ссылки |
| TrustTunnel endpoint | `sudo env TT_VERSION=<версия> bash deploy-trusttunnel.sh` ([инструкция](trusttunnel.md#как-обновить-trusttunnel-на-сервере)) | пароли, сертификат, порт, ссылки |
| TrustTunnel CLI-клиент (самотест) | скачивается при каждом запуске скрипта; версия — `TT_CLIENT_VERSION=<версия>` | — |

Не используйте `--force` для обновления: он пересоздаёт ключи/пароли, и старые ссылки перестанут работать. Перед обновлением сделайте копию бинарника — скрипты откатывают при неудачном самотесте только конфиг, но не бинарник.

## Совместная работа

Скрипты `hysteria2` и `trusttunnel` читают состояние Xray и проверяют конфликты портов, никогда не меняют конфиг и правила Xray. Все добавленные ими правила файрвола помечены тегами (`hysteria`, `trusttunnel`), и `--uninstall` удаляет только их.

## Устранение неполадок

```bash
sudo bash deploy-xray.sh --check             # диагностика (для не-443 порта: --port N)
sudo bash deploy-xray.sh --fix               # автоисправление
journalctl -u xray -n 50                     # логи сервиса
journalctl -u hysteria-server -n 50
journalctl -u trusttunnel -n 50
```
