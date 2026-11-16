# Metodologia

Questo documento descrive **cosa misura** l'Osservatorio PA, **come lo misura** e, soprattutto, **cosa non misura**. Va letto prima di interpretare qualsiasi dato pubblicato.


---

## Scopo

L'Osservatorio misura in modo **passivo e ripetibile** l'igiene tecnica dei siti web istituzionali degli enti pubblici italiani, a partire dalla Calabria, per osservare come cambia nel tempo.

Gli obiettivi sono:

- offrire un quadro **aggregato** (per provincia e tipologia di ente), non una classifica dei singoli enti;
- rendere il metodo **trasparente e replicabile**, così che chiunque possa verificarlo;
- seguire l'**andamento nel tempo**, che è più informativo di una singola fotografia.

L'Osservatorio **non** è uno strumento di audit, non valuta la sicurezza reale degli enti e **non** cerca vulnerabilità.

## Perimetro

- **Geografico:** fase iniziale limitata alla Calabria; l'estensione ad altre regioni verrà magari in seguito.
- **Soggetti:** enti presenti nell'Indice dei domicili digitali delle pubbliche amministrazioni (IPA) con un sito istituzionale dichiarato.
- **Oggetto della misura:** la home page del sito istituzionale (`/`), raggiunta come farebbe un normale visitatore.

## Fonte dei dati

L'elenco degli enti e dei relativi siti proviene dall'**IPA**, pubblicato come dato aperto.

Gli enti possono condividere lo stesso sito. Prima della scansione gli indirizzi vengono **deduplicati**: ogni host viene misurato una sola volta per scansione.

## Cosa viene misurato

Per ogni host vengono eseguiti, in ordine, i seguenti accessi:

1. una connessione TLS sulla porta 443;
2. una richiesta `GET https://host/` (seguendo al massimo 5 redirect);
3. una richiesta `GET http://host/` **senza** seguire i redirect, solo per verificare se rimanda a HTTPS.

Non vengono effettuate altre richieste.

| # | Controllo | Cosa verifica | Come |
|---|-----------|---------------|------|
| 1 | Raggiungibilità | Il sito risponde | Esito della connessione |
| 2 | HTTPS valido | Connessione cifrata con certificato verificabile | Handshake TLS con verifica standard |
| 3 | Validità del certificato | Giorni residui alla scadenza; errore (scaduto, nome errato, catena non valida) | Dati del certificato presentato |
| 4 | Versione TLS | Versione negoziata (1.3, 1.2, ...) | Esito dell'handshake con le impostazioni predefinite |
| 5 | Redirect HTTP→HTTPS | La versione non protetta rimanda a quella protetta | Risposta a `http://host/` |
| 6 | HSTS | Presenza dell'header `Strict-Transport-Security` | Header della risposta HTTPS |
| 7 | CSP | Presenza dell'header `Content-Security-Policy` | Header della risposta HTTPS |
| 8 | `X-Content-Type-Options` | Presenza dell'header | Header della risposta HTTPS |
| 9 | Protezione dai frame | Presenza di `X-Frame-Options` (o di `frame-ancestors` nella CSP) | Header della risposta HTTPS |
| 10 | `Referrer-Policy` | Presenza dell'header | Header della risposta HTTPS |
| 11 | Banner con versione | L'header `Server` contiene un numero di versione (sì/no, **mai il valore**) | Header della risposta HTTPS |
| 12 | Tempo di risposta | Millisecondi per ottenere la risposta | Misura lato client |

Per i controlli sugli header viene registrata **solo la presenza**, non la correttezza del contenuto.

## Cosa NON viene misurato

L'Osservatorio **non**:

- cerca o verifica vulnerabilità;
- effettua scansioni di porte o di servizi diversi dal sito web;
- visita pagine diverse dalla home, né segue link;
- compila moduli, effettua login o invia parametri;
- esamina il contenuto delle pagine, i cookie o gli script;
- accede in alcun modo a sistemi interni degli enti;
- raccoglie dati personali.

## Regole di carico e identificazione

Per ridurre al minimo l'impatto sui siti misurati:

- **concorrenza massima:** 20 connessioni contemporanee in totale;
- **una sola richiesta per tipo e per host** a ogni scansione, senza ripetizioni oltre a un singolo nuovo tentativo in caso di errore di rete;
- **pausa** di almeno 0,3 secondi tra una richiesta e la successiva sulla stessa esecuzione;
- **timeout** di 10 secondi;
- **frequenza:** una scansione a settimana;
- **orario:** scansioni eseguite preferibilmente in fascia notturna.

Ogni richiesta si identifica con questo `User-Agent`:

```
osservatorio-pa/[VERSIONE] (+[URL PAGINA DEL PROGETTO]; ricerca;)
```

## Punteggio

A ogni host viene assegnato un punteggio da 0 a 100 come somma dei seguenti contributi:

| Controllo | Punti |
|-----------|-------|
| HTTPS valido | 30 |
| Certificato con più di 14 giorni di validità residua | 10 |
| TLS 1.3 (TLS 1.2: 5 punti) | 10 |
| Redirect da HTTP a HTTPS | 10 |
| HSTS presente | 15 |
| CSP presente | 10 |
| `X-Content-Type-Options` presente | 5 |
| Protezione dai frame presente | 5 |
| `Referrer-Policy` presente | 5 |
| **Totale** | **100** |

I pesi sono una scelta metodologica **discutibile e modificabile**. 

I controlli 11 (banner con versione) e 12 (tempo di risposta) sono raccolti ma **non entrano nel punteggio**.

Se il sito non è raggiungibile o non offre HTTPS valido, i controlli sugli header non sono applicabili e contribuiscono con 0 punti.

## Aggregazione e riservatezza

- I risultati si pubblicano **solo in forma aggregata** per provincia e per tipologia di ente.
- Un gruppo con **meno di 10 enti** non viene mostrato.
- **Non si pubblicano** elenchi di singoli enti associati a carenze, certificati scaduti o altri difetti.
- I dati grezzi per singolo host restano privati e non sono presenti nel repository.
- Se un risultato aggregato permettesse comunque di identificare un singolo ente (per esempio una provincia con un solo ente di una certa tipologia), viene accorpato o omesso.

## Limiti e cautele di lettura

- Il punteggio misura l'**igiene tecnica visibile dall'esterno**, non la sicurezza reale: un sito può avere tutti gli header e problemi interni, o pochi header ed essere ben protetto.
- Molti enti usano **piattaforme condivise** o servizi forniti da terzi e non possono modificare queste impostazioni in autonomia: un punteggio basso non implica negligenza dell'ente.
- Si misura **solo la home** e **solo l'host dichiarato in IPA**: altri sottodomini o servizi dello stesso ente non sono considerati.
- I risultati dipendono dal momento, dalla rete e da eventuali sistemi di protezione (CDN, WAF) che possono rispondere in modo diverso a client automatici.
- La presenza di un header **non ne garantisce la configurazione corretta**.
- L'elenco IPA può contenere indirizzi errati, non aggiornati o che puntano a servizi di terzi.
- I dati di un singolo periodo vanno letti come fotografia, i **trend** come indicazione di direzione.

---

*Autore: FRANCESCO DE FILIPPIS · Contatto: francesco.fdf01@gmail.com*