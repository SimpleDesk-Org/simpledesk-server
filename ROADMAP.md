# SimpleDesk Roadmap

SimpleDesk ist ein Fork von RustDesk (Server, Client und gemeinsamer Code). Ziel: eine Fernwartung, die komplett über Port 443 läuft, nur mit dem eigenen Server spricht und alle Funktionen der RustDesk-Pro-Version selbst gebaut mitbringt. Von RustDesk Pro wird nichts kopiert, alles wird neu geschrieben.

## Repos

| Repo | Fork von | Inhalt |
|---|---|---|
| [simpledesk-server](https://github.com/felixthedevgit/simpledesk-server) | rustdesk/rustdesk-server | ID-Server (hbbs) und Relay (hbbr), später API und Web-Panel |
| [simpledesk](https://github.com/felixthedevgit/simpledesk) | rustdesk/rustdesk | Client |
| [simpledesk-common](https://github.com/felixthedevgit/simpledesk-common) | rustdesk/hbb_common | gemeinsamer Code von Client und Server |

Gearbeitet wird jeweils auf dem Branch `simpledesk`.

## Fertig

- Anmeldung der Geräte über WebSocket (Port 443), nicht nur über UDP
- Schalter `WS_ONLY=Y`: nach außen nur die WebSocket-Ports, alles läuft über das Relay
- ID ändern (`--set-id`)
- Docker-Image `ghcr.io/felixthedevgit/simpledesk-server`
- Server fragt nicht mehr täglich bei RustDesk nach Updates
- Client: eingebauter Server, Key und API statt RustDesk-Servern
- Client: Update-Check und Updates nur aus den eigenen Releases, mit eigenem Signaturschlüssel
- Client: keine öffentlichen STUN-Server mehr (Google, Cloudflare und andere)
- Client: Lizenz-Konfigurationen von RustDesk werden nicht mehr angenommen, Custom-Client-Konfigurationen nur mit SimpleDesk-Schlüssel
- Client: Links zu rustdesk.com zeigen auf die Projektseite
- Eigener Server läuft mit dem SimpleDesk-Image (remote.felixthedev.com)
- Anmeldung nur über Eider (OIDC), live mit www.klg-orga.de. SimpleDesk hat keine Konten mit Benutzername und Passwort.
- Verbinden nur mit Anmeldung (`LOGIN_REQUIRED=Y`)
- Server-Info für die Ersteinrichtung des Clients (`/api/simpledesk/server-info`)
- Anmeldungen laufen ab: Client nach `TOKEN_DAYS` (14), Panel nach `PANEL_SESSION_HOURS` (8)
- Rollen Admin (`ADMIN_USERS`) und Benutzer, Seite „Benutzer“ mit Abmelden, Sperren und Gruppen
- Geräte haben Besitzer und Gruppe. Benutzer sehen und steuern nur ihre Geräte und die ihrer Gruppen, Admins alle.
- Geteilte Adressbücher mit den Rechten lesen, schreiben und voll (Client und Panel)
- IDs vergibt nur ein Admin (`IDS_BY_ADMIN=Y`): neue Geräte im Panel, „ID vergeben“ und „ID ändern“, das Gerät übernimmt die ID über den Heartbeat
- Panel verlinkt auf jeder Seite den Quellcode (AGPL)

## Als Nächstes

1. Client-Build und Windows-Installer über GitHub Actions (läuft)
2. Client: Anmeldefenster beim Start, nur "Mit Eider anmelden"
3. Echter Test mit zwei Clients
4. Client: Icons und Installer mit SimpleDesk-Namen
5. Client: nur noch erlaubte Server (Allowlist für klg-orga.de und felixthedev.com)
6. Client: Liste „Zugängliche Geräte“ (`/api/peers`) mit den eigenen Geräten und denen der Gruppen

## Pro-Funktionen

| Funktion | Stand |
|---|---|
| Verbindung über WebSocket/HTTPS | fertig |
| ID ändern | fertig |
| Eigener Client mit festen Einstellungen | Grundlage fertig (SimpleDesk-Schlüssel), Generator fehlt |
| Web-Panel | Anmelden über Eider, Geräte mit Besitzer und Gruppe, Adressbücher, Benutzer und Gruppen |
| Login im Client mit Konto | über Eider im Browser, Anmeldefenster im Client wird gebaut |
| Login mit 2FA | über Eider |
| Geräteverwaltung und Online-Status | Online-Status, Besitzer und Gruppe fertig, Löschen und Deaktivieren offen |
| Adressbuch | persönliche und geteilte Adressbücher fertig (Client und Panel) |
| Audit-Log (Verbindungen, Dateien, Alarme) | offen |
| Zugriffsrechte, Rollen Admin und Control | Admin und Benutzer, Gruppen, Gerätebesitzer und Sperren fertig |
| Zentrale Einstellungen für alle Clients | offen |
| Geräte zentral einrichten | offen |
| Mehrere Relays, das nächste automatisch | offen |
| OIDC (Eider) | fertig und live, einziger Weg zum Anmelden |
| LDAP (AD) | offen |
| SMTP für Mails | offen |
| Web-Client selbst hosten | offen |

Das Web-Panel wird mit axum und askama gebaut (wie Eider) und läuft in hbbs.
