# VulnPatch Validation Fixtures

This directory contains deterministic, auditable fixtures for validating the two title capabilities:

1. **Autonomous multi-model routing** — `ModelRouter` emits a structured `RoutingDecision` using complexity, static confidence, sensitivity, provider availability/health, cost and latency.
2. **Self-evolving repair case library** — `CaseRetriever` supplies verified positive and negative historical constraints before repair; `VerificationAgent` determines the outcome; `CaseEvolver` writes a positive/negative `RepairCase`; later runs can retrieve the new case and influence the next repair decision.

## Preflight and reset

```powershell
python demo\preflight.py
python demo\reset_demo.py
```

## Start the application

Backend:

```powershell
python -m uvicorn api.server:app --host 127.0.0.1 --port 8000
```

Frontend:

```powershell
cd frontend
npm install
npm run dev
```

There is intentionally **no dedicated competition/demo page, route or menu entry** in the product frontend. This follows the Owner decision to keep the normal product UI unchanged. Use the generic **Agents** page to inspect routing decisions and the **Knowledge** page to inspect repair cases/events.

The `/api/demo/*` endpoints are retained as backend validation fixtures for reproducible acceptance testing; they are not presented as a product UI workflow.

## Recommended validation sequence

Invoke `POST /api/demo/run` with the corresponding request body for each scenario:

1. `simple_sql + public + live + auto`: high-confidence/simple task should prefer the deterministic rule engine.
2. `path_evolution + public + live + weak`: explicitly labelled weak candidate fails anti-bypass verification and becomes a NEGATIVE case.
3. `path_evolution + public + live + safe`: verified repair becomes a POSITIVE case.
4. `similar_path + public + live + auto`: the newly created positive/negative cases are retrieved and must affect the actual repair decision.
5. `similar_path + confidential + live + auto`: cloud candidates are blocked by privacy policy; only an available local provider may execute.

Example PowerShell request:

```powershell
$body = @{
  scenario = "similar_path"
  sensitivity = "public"
  mode = "live"
  repair_variant = "auto"
  simulate_provider_failure = $false
} | ConvertTo-Json

Invoke-RestMethod `
  -Method Post `
  -Uri "http://127.0.0.1:8000/api/demo/run" `
  -ContentType "application/json" `
  -Body $body
```

For offline reproduction, use `mode="replay"`. Replay is explicitly recorded as replay metadata and must not be described as a live cloud-model call. Detection, deterministic verification, case writeback and retrieval still execute locally.
