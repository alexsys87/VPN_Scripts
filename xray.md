# deploy-xray.sh — Xray VLESS + REALITY

Разворачивает Xray с протоколом VLESS + REALITY и `xtls-rprx-vision` (без веб-панели): ставит Xray, генерирует ключи REALITY и UUID клиентов, пишет конфиг, systemd-юнит и правила файрвола, проверяет всю цепочку самотестом и выдаёт `vless://` ссылки.

## Установка одной командой

```bash
curl -fsSL https://raw.githubusercontent.com/alexsys87/VPN_Scripts/main/deploy-xray.sh | sudo bash
```

С параметрами:

```bash
curl -fsSL https://raw.githubusercontent.com/alexsys87/VPN_Scripts/main/deploy-xray.sh \
  | sudo bash -s -- --port 8443 --sni www.bing.com --clients 5
```

Результат:

- ссылки `vless://…` — в терминале и в `/root/xray-deploy/links.txt`
- QR-код первой ссылки в терминале (`qrencode` ставится автоматически)
- клиентский конфиг с keepalive — `/root/xray-deploy/client.json`

## Параметры

| Параметр | По умолчанию | Описание |
|---|---|---|
| `--port PORT` | `443` | порт прослушивания (TCP) |
| `--sni DOMAIN` | `www.bing.com` | домен-маска REALITY |
| `--ip IP` | авто | внешний IP для ссылок |
| `--clients N` | `3` | число UUID клиентов |
| `--name PREFIX` | `reality` | префикс меток ссылок |
| `--bin PATH` | — | использовать локальный бинарник xray (нужно для не-x86_64) |
| `--workdir DIR` | `/root/xray-deploy` | `links.txt`, `client.json`, бэкапы конфига |
| `--force` | — | пересоздать ключи и UUID (старые ссылки перестанут работать) |
| `--uninstall` | — | удалить Xray, конфиг, логи, юнит, правило файрвола и workdir |
| `--check` | — | диагностика без изменений |
| `--fix` | — | диагностика + автоисправление (рестарт, hardening, порт в файрволе); ключи не меняет |
| `--no-harden` | — | отключить сетевой hardening |
| `--with-mux` | — | дополнительно создать mux-профиль (без `flow`, только как запасной вариант) |
| `--dry-run` | — | сгенерировать конфиг и ссылки, систему не менять |

Версию Xray можно зафиксировать переменной окружения: `XRAY_VERSION=26.11.9 bash deploy-xray.sh` (по умолчанию именно эта). Работает только при **первой установке**; обновление уже работающего сервера — см. «Как обновить Xray на сервере» ниже.

## Как сменить порт

Запустите скрипт ещё раз с нужным `--port`:

```bash
sudo bash deploy-xray.sh --port 8443
```

Что произойдёт: конфиг перезапишется с новым портом, сервис перезапустится, новый порт откроется в файрволе (ufw → iptables → nftables), самотест проверит туннель, `links.txt` обновится. Ключ REALITY, shortId и UUID клиентов сохранятся.

Важно:

- **Порт и SNI не запоминаются.** Они берутся только из аргументов. Если вы раньше использовали свой `--sni`, укажите его снова: `--port 8443 --sni example.com`. Иначе вернётся `www.bing.com`, и в ссылках изменится `sni`.
- Для `--check`, `--fix` и `--uninstall` при нестандартном порте тоже указывайте `--port` (иначе скрипт проверит/закроет 443).
- Правило файрвола для старого порта автоматически не удаляется — закройте его вручную:
  ```bash
  ufw delete allow 443/tcp                         # если используется ufw
  iptables -D INPUT -p tcp --dport 443 -j ACCEPT   # если iptables
  ```
- Раздайте клиентам новые ссылки из `/root/xray-deploy/links.txt`.
- Порт 443 лучше всего маскирует трафик под обычный HTTPS; нестандартный порт может быть заметнее.

## Как обновить Xray на сервере

Повторный запуск `deploy-xray.sh` **не обновляет** уже установленный `/usr/local/bin/xray` (бинарник скачивается только если его нет), а `--force` пересоздаёт ключи и UUID и ломает ссылки. Поэтому обновляйте бинарник вручную — конфиг, ключи и ссылки клиентов остаются прежними. Команды выполняйте от root:

```bash
V=26.11.9    # нужная версия: https://github.com/XTLS/Xray-core/releases
apt-get install -y unzip curl
T="$(mktemp -d)" && cd "$T"
curl -fsSL -o x.zip "https://github.com/XTLS/Xray-core/releases/download/v${V}/Xray-linux-64.zip"
unzip -q x.zip -d x

# бэкап текущего бинарника (для отката)
cp -a /usr/local/bin/xray /usr/local/bin/xray.bak

# замена бинарника и geo-данных
install -m 0755 x/xray /usr/local/bin/xray
install -m 0644 x/geoip.dat x/geosite.dat /usr/local/share/xray/

# проверка конфига новой версией и перезапуск
/usr/local/bin/xray run -test -config /usr/local/etc/xray/config.json \
  && systemctl restart xray
xray version
systemctl is-active xray
```

Затем проверьте туннель (передайте тот же `--port`/`--sni`, что при установке — они не читаются из конфига):

```bash
sudo bash deploy-xray.sh --check --port 443
```

Откат, если что-то пошло не так:

```bash
install -m 0755 /usr/local/bin/xray.bak /usr/local/bin/xray && systemctl restart xray
```

Только `Xray-linux-64` (x86_64). На другой архитектуре возьмите подходящий архив со страницы релизов; для новой установки такого бинарника есть `--bin PATH`.

## Примеры

```bash
# 5 клиентов, свой SNI
sudo bash deploy-xray.sh --sni www.bing.com --clients 5

# Явно указать IP (если автоопределение не подходит)
sudo bash deploy-xray.sh --ip 203.0.113.10

# Другая архитектура / свой бинарник
sudo bash deploy-xray.sh --bin /path/to/xray

# Пробный прогон без изменений в системе
sudo bash deploy-xray.sh --dry-run

# Ротация всех ключей и UUID
sudo bash deploy-xray.sh --force

# Диагностика и починка (если порт нестандартный — добавьте --port N)
sudo bash deploy-xray.sh --check
sudo bash deploy-xray.sh --fix

# Полное удаление
sudo bash deploy-xray.sh --uninstall
```

## Выбор SNI

Домен-маска должен поддерживать TLS 1.3, HTTP/2 и X25519 и быть доступен с сервера. Скрипт проверяет это перед применением. Некоторые домены ломают REALITY-релей (например, `www.microsoft.com` за Akamai) — самотест обнаружит это, и скрипт откажется завершать установку.

## Hardening (включён по умолчанию)

- TCP keepalive в конфиге Xray (мёртвые соединения обнаруживаются за ~30 с)
- `tcp_mtu_probing=1` и BBR/fq через `/etc/sysctl.d`
- MSS clamping (iptables mangle или nft) для путей с PMTU-blackhole

Отключается флагом `--no-harden`.

## Клиенты

Подойдёт любой клиент с поддержкой VLESS + REALITY + `xtls-rprx-vision`: импортируйте ссылку из `links.txt` или отсканируйте QR. Первая ссылка в списке помечена как `<name>-<port>`.

## Файлы и сервис

| Что | Где |
|---|---|
| Конфиг | `/usr/local/etc/xray/config.json` |
| Бинарник | `/usr/local/bin/xray` |
| Данные geoip/geosite | `/usr/local/share/xray/` |
| Логи | `/var/log/xray/` |
| Сервис | `systemctl status xray`, `journalctl -u xray -n 50` |
| Ссылки, клиентский конфиг, бэкапы конфига | `/root/xray-deploy/` |

## Заметки

- Повторный запуск переиспользует ключ, shortId и UUID. Если указать меньше `--clients`, лишние UUID не попадут в новый конфиг; если больше — недостающие создадутся.
- Перед перезаписью конфиг бэкапится в workdir; при провале самотеста выполняется откат.
- Firewall: ufw, иначе iptables, иначе nftables (набор правил сохраняется в `/etc/nftables.conf`).
