# Osservatorio PA

Misura in modo **passivo** l'igiene tecnica dei siti web istituzionali degli enti pubblici italiani, partendo dalla Calabria, e ne segue l'andamento nel tempo.

Guardare `METHODOLOGY.md` per la metodologia di analisi.

> Attualmente il progetto raccoglie i dati per i soli enti calabresi

## Dati
L'elenco degli enti e dei siti proviene dall'IPA (AgID), pubblicato come dato aperto.
Fonte: `https://indicepa.gov.it/ipa-dati/dataset/enti/resource/d09adf99-dc10-4349-8c53-27b1e5aa97b6` · Data di scarico: 16/11/2026

## Come eseguire
```bash
python -m venv venv
venv\Scripts\activate          # Windows (Linux/macOS: source venv/bin/activate)
pip install requests certifi tqdm
python src/osspa/main.py
```

## Struttura
```
src/osspa/
├── main.py        # scarica gli enti, lancia le analisi, calcola le medie
├── verifiche.py   # controlli TLS, HTTPS e redirect
└── punteggio.py   # tabella dei pesi
METHODOLOGY.md     # metodologia, limiti, etica
```


# Risultati

Da una scansione effettuata il 16/11/2026 i dati risultati sono i seguenti:


| Provincia | Punteggio Medio |
| :--- | :---: |
| **Reggio di Calabria** | 60.45 |
| **Crotone** | 60.33 |
| **Cosenza** | 60.31 |
| **Vibo Valentia** | 59.73 |
| **Catanzaro** | 58.75 |
