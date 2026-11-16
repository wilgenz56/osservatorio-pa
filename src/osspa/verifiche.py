import socket
import ssl
import time
from pprint import pprint
from urllib.parse import urlparse

import certifi
import requests

USER_AGENT = "osservatorio-pa/0.1 (+[URL PROGETTO]; ricerca; contatto: [EMAIL])"


# ---------------------------------------------------------------- TLS

def classifica_errore_cert(messaggio):
    """Trasforma il messaggio di OpenSSL in una categoria leggibile."""
    m = messaggio.lower()
    if "expired" in m:
        return "scaduto"
    if "mismatch" in m:
        return "nome_errato"
    if "self-signed certificate in certificate chain" in m or "self signed certificate in certificate chain" in m:
        return "radice_non_fidata"
    if "self-signed" in m or "self signed" in m:
        return "autofirmato"
    if "unable to get local issuer" in m or "unable to verify the first" in m:
        return "catena_incompleta_o_non_fidata"
    return "altro_certificato"


def verifica_tls(hostname, timeout=10):
    risultato = {
        "host": hostname,
        "tls_ok": 0,
        "tls_categoria": None,
        "tls_dettaglio": None,
        "tls_version": None,
        "cert_giorni_residui": None,
    }

    context = ssl.create_default_context(cafile=certifi.where())

    try:
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls:
                cert = tls.getpeercert()
                scadenza = ssl.cert_time_to_seconds(cert["notAfter"])
                risultato["tls_ok"] = 1
                risultato["tls_categoria"] = "valido"
                risultato["tls_version"] = tls.version()
                risultato["cert_giorni_residui"] = int((scadenza - time.time()) // 86400)

    except ssl.SSLCertVerificationError as e:
        risultato["tls_categoria"] = classifica_errore_cert(e.verify_message)
        risultato["tls_dettaglio"] = e.verify_message
    except ssl.SSLError as e:
        risultato["tls_categoria"] = "handshake_fallito"
        risultato["tls_dettaglio"] = str(e)
    except socket.gaierror as e:
        risultato["tls_categoria"] = "dns_errore"
        risultato["tls_dettaglio"] = str(e)
    except (socket.timeout, TimeoutError):
        risultato["tls_categoria"] = "timeout"
    except ConnectionRefusedError:
        risultato["tls_categoria"] = "connessione_rifiutata"
    except UnicodeError as e:
        risultato["tls_categoria"] = "host_non_valido"
        risultato["tls_dettaglio"] = str(e)
    except OSError as e:
        risultato["tls_categoria"] = "errore_rete"
        risultato["tls_dettaglio"] = str(e)

    return risultato


# ---------------------------------------------------------------- HTTPS GET

def verifica_http(hostname, timeout=10):
    """GET https://host/ : legge stato, redirect, tempo e header di sicurezza.
    None = non misurato; 0/1 = misurato (assente/presente)."""
    risultato = {
        "http_ok": 0,
        "errore_http": None,
        "errore_dettaglio": None,
        "stato": None,
        "redirect_seguiti": None,
        "host_finale_uguale": None,
        "tempo_risposta_ms": None,
        "h_hsts": None,
        "h_csp": None,
        "h_xcto": None,
        "h_frame": None,
        "h_referrer": None,
        "server_ha_versione": None,
    }

    url = f"https://{hostname}/"

    try:
        with requests.Session() as sessione:
            sessione.max_redirects = 5
            sessione.headers.update({"User-Agent": USER_AGENT})

            with sessione.get(url, timeout=timeout, stream=True) as risposta:
                h = risposta.headers  # dizionario che ignora maiuscole/minuscole
                csp = h.get("Content-Security-Policy", "")

                risultato["http_ok"] = 1
                risultato["stato"] = risposta.status_code
                risultato["redirect_seguiti"] = len(risposta.history)
                risultato["host_finale_uguale"] = int(urlparse(risposta.url).hostname == hostname)
                risultato["tempo_risposta_ms"] = int(risposta.elapsed.total_seconds() * 1000)

                risultato["h_hsts"] = int("Strict-Transport-Security" in h)
                risultato["h_csp"] = int("Content-Security-Policy" in h)
                risultato["h_xcto"] = int("X-Content-Type-Options" in h)
                risultato["h_frame"] = int("X-Frame-Options" in h or "frame-ancestors" in csp.lower())
                risultato["h_referrer"] = int("Referrer-Policy" in h)
                risultato["server_ha_versione"] = int(any(c.isdigit() for c in h.get("Server", "")))

    except requests.exceptions.TooManyRedirects:
        risultato["errore_http"] = "troppi_redirect"
    except requests.exceptions.SSLError as e:
        risultato["errore_http"] = "errore_ssl"
        risultato["errore_dettaglio"] = str(e)[:200]
    except requests.exceptions.Timeout:
        risultato["errore_http"] = "timeout"
    except requests.exceptions.ConnectionError as e:
        risultato["errore_http"] = "errore_connessione"
        risultato["errore_dettaglio"] = str(e)[:200]
    except requests.exceptions.RequestException as e:
        risultato["errore_http"] = "errore_richiesta"
        risultato["errore_dettaglio"] = str(e)[:200]

    return risultato


# ---------------------------------------------------------------- Redirect HTTP -> HTTPS

def verifica_redirect_http(hostname, timeout=10):
    """GET http://host/ senza seguire i redirect.
    redirect_a_https: 1 = rimanda a https, 0 = no, None = porta 80 non raggiungibile."""
    risultato = {
        "redirect_a_https": None,
        "errore_redirect_http": None,
    }

    url = f"http://{hostname}/"

    try:
        with requests.Session() as sessione:
            sessione.headers.update({"User-Agent": USER_AGENT})

            with sessione.get(url, timeout=timeout, allow_redirects=False, stream=True) as risposta:
                location = risposta.headers.get("Location", "")
                risultato["redirect_a_https"] = int(
                    risposta.status_code in (301, 302, 303, 307, 308)
                    and location.lower().startswith("https://")
                )

    except requests.exceptions.RequestException as e:
        risultato["errore_redirect_http"] = type(e).__name__

    return risultato


# ---------------------------------------------------------------- Insieme

def analizza_sito(hostname):
    risultato = {"host": hostname, "ts": int(time.time())}

    tls = verifica_tls(hostname)
    risultato.update(tls)

    if tls["tls_ok"]:
        risultato.update(verifica_http(hostname))

    risultato.update(verifica_redirect_http(hostname))
    return risultato


if __name__ == "__main__":
    prove = [
        "badssl.com",                       # valido
        "expired.badssl.com",               # scaduto
        "self-signed.badssl.com",           # autofirmato
        "questo-host-non-esiste-12345.it",  # DNS
        # aggiungi qui 2-3 siti di enti calabresi
    ]
    for h in prove:
        print("=" * 60)
        pprint(analizza_sito(h))