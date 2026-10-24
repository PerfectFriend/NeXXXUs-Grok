# NeXXXUs

Суверенная нода. Без центрального сервера. Linux 0.3.0 хранит сейф, проверяет чужие чанки и подтягивает журнал с контакта. Android 0.1.2 по-прежнему только чат и файл, без реплик.: X25519 4DH, HELLO v3 с подписью Ed25519, чат и файлы чанками по 16 КБ.

Репозиторий: https://github.com/PerfectFriend/NeXXXUs-Grok

## Linux

Нужен Node.js 22+.

```bash
git clone https://github.com/PerfectFriend/NeXXXUs-Grok.git
cd NeXXXUs-Grok/linux-node
chmod +x install/install.sh
./install/install.sh
export PATH="$HOME/.local/bin:$PATH"
nexxus start
```

Панель: http://127.0.0.1:4378/ . Mesh: TCP 4377.

## Android

APK в релизах этого репозитория. Поставьте на телефон, разрешите неизвестные источники, нажмите «Слушать сеть». В контакте должен быть адрес, который виден второму устройству (обычно Wi-Fi IP). Обменяйтесь строками `nexxus:1:…` и нажмите «Связь».

Сборка из исходников: Android SDK 34, JDK 17, `cd android && gradle assembleRelease`.

## Чего ещё нет

Tor, четыре реплики по сети, биржа NXX.
