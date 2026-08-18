# VulnPatch Competition Demo

This directory contains deterministic, auditable fixtures for demonstrating the two title capabilities:

1. **Autonomous multi-model routing** — `ModelRouter` emits a structured `RoutingDecision` using complexity, static confidence, sensitivity, provider availability/health, cost and latency.
2. **Self-evolving repair case library** — `CaseRetriever` injects verified positive and negative historical constraints before repair; `VerificationAgent` determines the outcome; `CaseEvolver` writes a positive/negative `RepairCase`; later runs can retrieve the new case.

## Preflight and reset

```powershell
python demo\preflight.py
python demo\reset_demo.py
```

## Backend / frontend

```powershell
python -m uvicorn api.server:app --host 127.0.0.1 --port 8000
```

In another terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open the frontend and choose **比赛展示**.

## Recommended live sequence

1. `simple_sql + public + live + auto`: high-confidence/simple task should prefer the deterministic rule engine.
2. `path_evolution + public + live + weak`: explicitly labelled weak candidate fails anti-bypass verification and becomes a NEGATIVE case.
3. `path_evolution + public + live + safe` (or `auto` with a configured model): verified repair becomes a POSITIVE case.
4. `similar_path`: the cases just created are retrieved and shown as positive guidance / negative constraints.
5. `similar_path + confidential`: cloud candidates are visibly blocked by privacy policy.

`replay` mode is explicitly labelled in the UI. It replays only a recorded model response; detection, verification, case writeback and retrieval still execute live.
