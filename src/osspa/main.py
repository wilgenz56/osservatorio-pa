import asyncio
import json
import os
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

import requests

import verifiche
import punteggio

from pprint import pprint
from tqdm import tqdm


FILE_CHECKPOINT = "data/scansione_in_corso.jsonl"
CONCORRENZA = 20   # massimo di siti analizzati contemporaneamente (vedi METHODOLOGY.md)
PAUSA = 0.3        # secondi di pausa dopo ogni analisi


def carica_checkpoint(percorso):
    """Legge le analisi già salvate: dizionario host -> risultato dell'analisi."""
    fatti = {}
    if os.path.exists(percorso):
        with open(percorso, encoding="utf-8") as f:
            for riga in f:
                try:
                    r = json.loads(riga)
                except json.JSONDecodeError:
                    continue   # ultima riga incompleta per interruzione a metà scrittura
                if "host" in r and "analisi" in r:   # ignora righe del vecchio formato
                    fatti[r["host"]] = r["analisi"]
    return fatti


def salva_riga(percorso, record):
    with open(percorso, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def calcola_punteggio(risultato_analisi):
    return punteggio.tabella["HTTPS valido"] * (risultato_analisi.get("tls_ok") or 0) + punteggio.tabella["Certificato 14 gg"] * ((risultato_analisi.get("cert_giorni_residui") or 0) > 14) + (punteggio.tabella["TLS 1.3"] if risultato_analisi.get("tls_version") == "TLSv1.3" else punteggio.tabella["TLS 1.2"] if risultato_analisi.get("tls_version") == "TLSv1.2" else 0) + punteggio.tabella["Redirect da HTTP a HTTPS"] * (risultato_analisi.get("redirect_a_https") or 0) + punteggio.tabella["HSTS presente"] * (risultato_analisi.get("h_hsts") or 0) + punteggio.tabella["CSP presente"] * (risultato_analisi.get("h_csp") or 0) + punteggio.tabella["X-Content-Type-Options presente"] * (risultato_analisi.get("h_xcto") or 0) + punteggio.tabella["protezione frame presente"] * (risultato_analisi.get("h_frame") or 0) + punteggio.tabella["Referrer-Policy presente"] * (risultato_analisi.get("h_referrer") or 0)


def media_punteggio_province(province_enti):

    media_punteggio_per_provincia = {}
    
    somma = 0
    for i in province_enti:
        for j in province_enti[i]:
            somma+= j[2]
        media_punteggio_per_provincia[i] = somma / len(province_enti[i])
        somma = 0

    return media_punteggio_per_provincia


async def scansiona_host(hostnames, percorso_checkpoint):
    """Analizza i siti in parallelo (max CONCORRENZA alla volta) e salva ogni risultato appena arriva."""
    if not hostnames:
        return {}

    loop = asyncio.get_running_loop()
    executor = ThreadPoolExecutor(max_workers=CONCORRENZA)
    semaforo = asyncio.Semaphore(CONCORRENZA)

    async def analizza(host):
        async with semaforo:
            try:
                analisi = await loop.run_in_executor(executor, verifiche.analizza_sito, host)
            except Exception as e:
                tqdm.write(f"Errore su {host}: {e!r}")
                analisi = {"host": host, "errore_interno": repr(e)}
            await asyncio.sleep(PAUSA)
        return host, analisi

    compiti = [asyncio.create_task(analizza(h)) for h in hostnames]
    risultati = {}

    try:
        for compito in tqdm(asyncio.as_completed(compiti), total=len(compiti), desc="Scansione siti", unit="sito"):
            host, analisi = await compito
            risultati[host] = analisi
            salva_riga(percorso_checkpoint, {"host": host, "analisi": analisi})
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

    return risultati


def main():

    os.makedirs("data", exist_ok=True)
    fatti = carica_checkpoint(FILE_CHECKPOINT)

    url_province = "https://raw.githubusercontent.com/avalla/coordinate-comuni-italiani/refs/heads/master/province.json"
    lista_province = requests.get(url_province).json()

    # Crea un dizionario di lookup: codice ISTAT (3 cifre) -> Nome Provincia
    mappa_province = {
        str(p["codice_prov_istat"]).strip().zfill(3): p["name"].strip()
        for p in lista_province
    }


    province_enti = {}


    url = "https://indicepa.gov.it/ipa-dati/api/3/action/datastore_search_sql"

    # Usa l'operatore IN e gli apici singoli per i codici testuali
    # Prendo solo gli enti dei comuni calabresi (identificati con le prime 3 cifre del codice istat)
    query_sql = """
    SELECT "Denominazione_ente", "Sito_istituzionale", "Codice_comune_ISTAT"
    FROM "d09adf99-dc10-4349-8c53-27b1e5aa97b6"
    WHERE LEFT("Codice_comune_ISTAT", 3) IN ('078', '079', '080', '101', '102') 
    """

    parametri = {
        "sql": query_sql.strip()
    }

    intestazioni = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "application/json"
    }

    risultato = requests.get(url, params=parametri, headers=intestazioni, timeout=30)
    risultato.raise_for_status()

    dati = risultato.json()["result"]["records"]


    # FASE 1: elenco (ente, host, provincia)
    enti = []
    for record in dati:

        ente = record["Denominazione_ente"]
        sito_completo_ente = record["Sito_istituzionale"]
        codice_provincia = record["Codice_comune_ISTAT"][:3]

        if sito_completo_ente == None:
            continue

        sito = sito_completo_ente.strip()
        try:
            hostname_ente = urlsplit(
                sito if "://" in sito else f"//{sito}"
            ).hostname
        except ValueError:   # indirizzo malformato
            continue

        if not hostname_ente:
            continue

        enti.append((ente, hostname_ente, codice_provincia))


    # FASE 2: host unici ancora da analizzare
    host_da_fare = sorted({h for _, h, _ in enti if h not in fatti})
    print(f"Enti con sito: {len(enti)} | host unici: {len({h for _, h, _ in enti})} | da analizzare: {len(host_da_fare)}")


    # FASE 3: scansione parallela
    nuovi = asyncio.run(scansiona_host(host_da_fare, FILE_CHECKPOINT))
    fatti.update(nuovi)


    # FASE 4: punteggi e medie
    for ente, hostname_ente, codice_provincia in enti:
        risultato_analisi = fatti[hostname_ente]
        punteggio_ente_corrente = calcola_punteggio(risultato_analisi)
        province_enti.setdefault(codice_provincia, []).append((ente, hostname_ente, punteggio_ente_corrente, risultato_analisi))


    medie = media_punteggio_province(province_enti)

    for i in medie:
        for j in mappa_province:
            if i == j:
                print(f"La media della provincia di {mappa_province[j]} è {medie[i]}")



    return



if __name__=="__main__":
    main()