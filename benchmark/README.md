# Ollama Incident Benchmark

Ce dossier contient un benchmark ciblé pour comparer plusieurs modèles Ollama sur **un seul incident normalisé** avec le **profil Lite**.

## Cible par défaut

- Incident: `5468293`
- Profil: `LITE`
- Serveur Ollama: `http://10.163.3.76:11434/`
- Timeout dur par modèle: `300s`
- Modèles:
  - `llama3.1:8b`
  - `phi3:mini`
  - `gemma3:4b`
  - `gemma3:1b`
  - `qwen2.5:1.5b`
  - `qwen2.5:3b`
  - `qwen2.5:7b`

## Lancer

Depuis la racine du repo:

```bash
python benchmark/run_benchmark.py
```

Optionnel (override):

```bash
python benchmark/run_benchmark.py \
  --incident-id 5468293 \
  --profile LITE \
  --server-url http://10.163.3.76:11434/ \
  --models llama3.1:8b,qwen2.5:3b \
  --timeout 300
```

## Sorties

Chaque exécution crée un dossier horodaté sous `benchmark/results/`:

- `results.json`: résultat complet du benchmark
- `summary.csv`: résumé compact par modèle
- `normalized_input.json`: input normalisé unique partagé par tous les modèles
- `skill_snapshot.json`: snapshot du skill / schéma utilisé
- `outputs/*-raw_output.json`: sortie brute LLM parsée JSON
- `outputs/*-validated_output.json`: sortie validée schéma (si validation OK)

## Notes d’implémentation

- Le script réutilise le pipeline réel:
  - normalisation via `IncidentAnalysisService.build_analysis_input(...)`
  - appel LLM via `OllamaStructuredLLMClient`
  - validation de sortie via `IncidentAnalysisService.validate_structured_output(...)`
- L’input normalisé est construit une seule fois et persisté, puis réutilisé pour tous les modèles.
- Timeout dur de 300s par modèle implémenté par process séparé + terminaison forcée en cas de dépassement.

