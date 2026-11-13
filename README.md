# SimpleDesk Server

SimpleDesk ist ein Fork des kostenlosen RustDesk-Servers (`rustdesk/rustdesk-server`) unter derselben Lizenz (AGPL-3.0). Ziel: Alles läuft über Port 443, auch wenn eine Firewall nur Webseiten durchlässt.

## Änderungen gegenüber dem RustDesk-Server

- Geräte können sich auch über TCP und WebSocket anmelden, nicht nur über UDP. Die Verbindung bleibt offen, der Server schickt alle 20 Sekunden ein Lebenszeichen, und Anfragen anderer Geräte kommen über diese Verbindung.
- Neuer Schalter `WS_ONLY=Y` für hbbs und hbbr: Nur die WebSocket-Ports (21118 und 21119) lauschen auf der Bind-Adresse, alle anderen Ports nur auf 127.0.0.1. Verbindungen laufen dann immer über das Relay.
- Ein Gerät kann seine ID ändern (`--set-id`), mit `IDS_BY_ADMIN=Y` aber nur auf die ID, die ein Admin vergeben hat.
- Web-Panel in hbbs auf Port 21114: Anmelden über Eider, Geräteliste mit Status (Aktiv, AFK, Offline), Besitzer und Gruppe, eigenes und geteilte Adressbücher, die Seite „Protokoll“ und für Admins die Seite „Benutzer“. Abschalten mit `PANEL=N`.
- API für den Client auf demselben Port: Anmelden über Eider im Browser, eigenes und geteilte Adressbücher mit Einträgen und Tags, Status der Geräte (`POST /api/simpledesk/peer-status`). Heartbeat, Systeminfo und Protokoll-Einträge der Geräte werden gespeichert. `GET /api/simpledesk/server-info` nennt ohne Anmeldung den Key des Servers (wie in `id_ed25519.pub`), damit der Client sich beim ersten Start selbst einrichten kann.
- Der Client fragt den Online-Status über WebSocket ab (`/ws/id`), hbbs antwortet dort. Vorher war mit WebSocket jedes Gerät „Offline“.
- Neuer Schalter `LOGIN_REQUIRED=Y` (im Docker-Image Standard): Verbinden darf nur, wer im Client angemeldet ist und das Gerät steuern darf (siehe unten). Der Server prüft den Token, den der Client mit jeder Verbindungsanfrage schickt. Ohne Anmeldung sieht man „Bitte melde dich in SimpleDesk an“, ohne Recht „Du darfst dieses Gerät nicht steuern.“ Das gilt auch für den normalen RustDesk-Client. Geräte, auf die man zugreift, brauchen keine Anmeldung.

## Anmeldung über Eider oder einen anderen OIDC-Anbieter

Es gibt keine Konten mit Benutzername und Passwort in SimpleDesk. Panel und Client melden sich über OpenID Connect an, zum Beispiel über Eider. Der Anbieter prüft Passwort, zweiten Faktor und Lizenz, SimpleDesk bekommt nur den Namen. Einstellungen für hbbs:

| Variable | Bedeutung |
|---|---|
| `OIDC_ISSUER` | Adresse des Anbieters, zum Beispiel `https://eider.example`. Ohne sie kann sich niemand anmelden. |
| `OIDC_CLIENT_ID` | Client-ID beim Anbieter, Standard `simpledesk` |
| `OIDC_CLIENT_SECRET` | Geheimnis des Clients beim Anbieter |
| `OIDC_NAME` | Name auf dem Knopf, Standard `Eider` |
| `PANEL_URL` | öffentliche Adresse des Panels, zum Beispiel `https://remote.example`. Die Rücksprung-Adresse ist `PANEL_URL/oidc/callback`. |

Der Anbieter muss Discovery, den Code-Flow mit PKCE (S256) und ein ID-Token mit HS256 und dem Client-Geheimnis können. Ein Konto aus dem Anbieter hat hier kein eigenes Passwort.

## Admins, Rechte und Ablauf der Anmeldung

| Variable | Bedeutung |
|---|---|
| `ADMIN_USERS` | Admins, mit Komma getrennt, zum Beispiel `felix,it-admin`. Es sind die Benutzernamen bei Eider, groß oder klein ist egal. |
| `TOKEN_DAYS` | So viele Tage bleibt der Client nach der Anmeldung angemeldet. Standard `14`. |
| `PANEL_SESSION_HOURS` | So viele Stunden bleibt das Panel nach der Anmeldung angemeldet. Standard `8`. |
| `IDS_BY_ADMIN` | `Y`: IDs vergibt nur ein Admin (siehe unten). Im Docker-Image Standard, sonst aus. |

**Setz `ADMIN_USERS` vor dem Update.** Ohne Admins kann niemand die Seite „Benutzer“ öffnen, und Geräte ohne Besitzer kann mit `LOGIN_REQUIRED=Y` niemand mehr steuern.

- **Admins** sehen und steuern alle Geräte, auch Geräte ohne Besitzer. Sie haben im Panel die Seite „Benutzer“. Admin ist nur, wer in `ADMIN_USERS` steht. Im Panel kann man Admins nicht sperren.
- **Benutzer** sehen und steuern nur ihre eigenen Geräte und die Geräte ihrer Gruppen.
- **Besitzer:** Ein Gerät gehört dem, der sich zuletzt im Client darauf anmeldet. Meldet sich ein Admin an, bleibt der Besitzer gleich. Auf der Seite „Geräte“ können Admins Besitzer und Gruppe von Hand setzen.
- **Gruppen** legen Admins auf der Seite „Benutzer“ an. Dort fügen sie auch Leute hinzu.
- **Abmelden** (Seite „Benutzer“) beendet alle Anmeldungen einer Person in Clients und Panel. Danach kann sie sich wieder anmelden. **Sperren** meldet sie ab, und sie kommt nicht mehr herein, bis ein Admin sie entsperrt.
- **Ablauf:** Eider gibt keine Refresh-Tokens heraus. SimpleDesk prüft die Lizenz also nur bei der Anmeldung. Verliert jemand bei Eider die Lizenz, bleibt er höchstens `TOKEN_DAYS` Tage angemeldet. Soll es sofort gelten, klick auf „Sperren“. Ist die Anmeldung abgelaufen, meldet sich der Client von selbst ab.

## IDs vergibt der Admin (`IDS_BY_ADMIN=Y`)

- Ein neues Gerät meldet sich mit der ID an, die es sich selbst ausgedacht hat. Verbinden kann sich damit aber niemand („Dieses Gerät hat noch keine ID.“).
- Admins sehen es im Panel unter „Neue Geräte (ohne ID)“ mit Rechnername, Benutzer, System und IP. Mit „ID vergeben“ bekommt es seine ID. Die vorgeschlagene ID kann man auch einfach stehen lassen.
- Mit „ID ändern“ geben Admins einem Gerät eine neue ID. Das Gerät übernimmt sie mit seinem nächsten Heartbeat, also nach ein paar Sekunden, sobald es online ist. Eine neue ID muss mit einem Buchstaben anfangen und 6 bis 16 Zeichen lang sein. Das Übernehmen kann erst der neue SimpleDesk-Client.
- Ein Gerät darf seine ID nicht selbst ändern, nur auf die ID, die ein Admin für es gewählt hat. Admins können das auch im Client tun (`/api/simpledesk/change-id`).
- Geräte, die schon vor dem Update angemeldet waren, behalten ihre ID.

## Geteilte Adressbücher

Im Panel unter „Adressbuch“ legt jeder geteilte Adressbücher an und teilt sie mit Benutzern oder Gruppen:

- **lesen:** ansehen und verbinden
- **schreiben:** zusätzlich Einträge und Tags ändern
- **voll:** zusätzlich teilen, umbenennen und löschen

Wer ein Adressbuch anlegt, und alle Admins haben „voll“. Der Client zeigt die geteilten Adressbücher neben dem eigenen. Passwörter, die jemand in einem geteilten Adressbuch speichert, sehen alle, mit denen es geteilt ist. Das eigene Adressbuch sieht nur man selbst, auch kein Admin.

## Status der Geräte: Aktiv, AFK, Offline

| Variable | Bedeutung |
|---|---|
| `AFK_MINUTES` | So viele Minuten ohne Tastatur oder Maus, dann gilt ein Gerät als AFK. Standard `5`. |

- **Online (Aktiv):** Das Gerät ist mit dem Server verbunden, und jemand hat vor Kurzem getippt oder die Maus bewegt.
- **AFK (seit X min):** online, aber seit `AFK_MINUTES` keine Eingabe. Die Zeit der letzten Eingabe schickt der Client im Heartbeat (`simpledesk_idle_secs`). Ältere Clients schicken sie nicht, die sind immer „Aktiv“.
- **Offline (seit X):** nicht mit dem Server verbunden. „Seit“ ist, wann der Server das Gerät zuletzt gesehen hat. Das bleibt auch nach einem Neustart von hbbs erhalten.

Das Panel zeigt den Status in der Geräteliste. Der Client fragt ihn so ab:

```
POST /api/simpledesk/peer-status
Authorization: Bearer <Token>
{"ids": ["Rathaus-PC", "Lager-PC"]}
```

Antwort: `{"Rathaus-PC": {"state": "afk", "since": 1763025600}}`. `state` ist `active`, `afk` oder `offline`, `since` sind Unix-Sekunden: bei `afk` die letzte Eingabe, bei `offline` wann das Gerät zuletzt gesehen wurde (`0` = nie), bei `active` die letzte Eingabe oder jetzt. In der Antwort stehen nur Geräte, die der Benutzer sehen darf, höchstens 1000 auf einmal.

## Protokoll

| Variable | Bedeutung |
|---|---|
| `AUDIT_DAYS` | So viele Tage bleiben Einträge im Protokoll. Standard `180`. |

Die Seite „Protokoll“ im Panel zeigt:

- **Verbindungen:** wer (angemeldeter Benutzer), von welchem Gerät und welcher IP, zu welchem Gerät, wann, wie lange und welche Art (Fernsteuerung, Dateiübertragung, Terminal, …). Verbindungen, die nicht zustande kamen (zum Beispiel falsches Passwort), stehen auch drin.
- **Dateien**, die vom Gerät geholt oder auf das Gerät kopiert wurden, mit Ordner und den größten Dateien.
- **Alarme** der Geräte, zum Beispiel „6 falsche Passwörter in einer Minute“.
- **Änderungen im Panel:** ID vergeben oder ändern, Besitzer und Gruppe setzen, Benutzer abmelden, sperren und entsperren, Gruppen und Mitglieder, Adressbücher teilen.

Admins sehen alles. Benutzer sehen, was auf ihren Geräten und den Geräten ihrer Gruppen passiert ist, und was sie selbst geändert haben. Filtern geht nach Gerät, Benutzer und Datum. Die Seite zeigt höchstens die neuesten 500 Einträge.

Die Einträge schickt das Gerät, auf das zugegriffen wird. Wer sich verbunden hat, weiß der Server aus der Verbindungsanfrage. Verbindet sich jemand direkt per IP, ohne den Server, steht beim Benutzer „–“.

## Alarm-Mails (optional)

| Variable | Bedeutung |
|---|---|
| `SMTP_HOST` | Mailserver, zum Beispiel `smtp.example.org`. Ohne ihn gehen keine Mails raus. |
| `SMTP_PORT` | Standard `587` (STARTTLS). `465` heißt TLS von Anfang an. |
| `SMTP_USER` | Benutzer am Mailserver, leer für keine Anmeldung |
| `SMTP_PASSWORD` | Passwort am Mailserver. Es steht nie im Log. |
| `SMTP_FROM` | Absender, zum Beispiel `SimpleDesk <simpledesk@example.org>`. Standard ist `SMTP_USER`. |
| `ALARM_MAIL_TO` | Empfänger, mit Komma getrennt |

- Eine kurze Mail kommt bei jedem Alarm eines Geräts, pro Gerät aber höchstens alle 10 Minuten. Im Protokoll steht jeder Alarm.
- Mit `IDS_BY_ADMIN=Y` kommt eine Mail, wenn ein neues Gerät auf seine ID wartet.
- Die Verbindung zum Mailserver ist immer verschlüsselt. Der Mailserver braucht ein Zertifikat, dem auch ein Browser vertraut.

## Betrieb nur über Port 443

1. hbbs und hbbr mit `WS_ONLY=Y` starten.
2. Einen Reverse Proxy mit HTTPS davorsetzen: `/ws/id` an Port 21118, `/ws/relay` an Port 21119 und alles andere (`/`) an Port 21114 für das Web-Panel. Der Proxy muss `X-Real-IP` setzen.
3. Die Ports 21114, 21118 und 21119 dürfen nur für den Proxy erreichbar sein, nicht aus dem Internet. Der Server übernimmt die IP aus `X-Real-IP` ungeprüft.
4. In jedem RustDesk-Client `allow-websocket` auf `Y` setzen und als API-Server `https://<deine Domain>` eintragen. Der SimpleDesk-Client hat das schon eingebaut.

---

# RustDesk Server Program

[![build](https://github.com/SimpleDesk-Org/simpledesk-server/actions/workflows/simpledesk.yml/badge.svg)](https://github.com/SimpleDesk-Org/simpledesk-server/actions/workflows/simpledesk.yml)

[**Docker image**](https://github.com/SimpleDesk-Org/simpledesk-server/pkgs/container/simpledesk-server)

[**Configuration & environment variables**](docs/environment-variables.md)

Self-host your own RustDesk server, it is free and open source.

## How to build manually

```bash
cargo build --release
```

Three executables will be generated in target/release.

- hbbs - RustDesk ID/Rendezvous server
- hbbr - RustDesk relay server
- rustdesk-utils - RustDesk CLI utilities

The Docker image `ghcr.io/simpledesk-org/simpledesk-server` is built by `.github/workflows/simpledesk.yml`.

## Configuration

`hbbs` and `hbbr` can be configured with command-line flags, environment
variables, or an `.env` / config file. Run `hbbs --help` or `hbbr --help` to see
the available flags.

The most common options:

| Option | Flag | Env var | Applies to | Purpose |
| --- | --- | --- | --- | --- |
| Key | `-k` | `KEY` | hbbs, hbbr | `hbbs` loads/generates one by default |
| Bind address | `-b` | `BIND` | hbbs, hbbr | Local IP address to listen on (default: all interfaces; requires 1.1.17+) |
| Port | `-p` | `PORT` | hbbs, hbbr | Listening port (hbbs `21116`, hbbr `21117`) |
| Relay servers | `-r` | `RELAY-SERVERS` | hbbs | Override when the relay uses a different address or a non-standard port |
| Force relay | — | `ALWAYS_USE_RELAY` | hbbs | `Y` disables direct connections |
| Log level | — | `RUST_LOG` | hbbs, hbbr | e.g. `debug` (default `info`) |

See **[docs/environment-variables.md](docs/environment-variables.md)** for the
full list of variables, the file/flag/env precedence rules, database and relay
bandwidth tuning, Docker image variables, and examples.

## Installation

See [docs/environment-variables.md](docs/environment-variables.md).
