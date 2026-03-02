# Quality Scorecard (10/10 Exit Gates)

This scorecard defines 35 strict gates with an explicit verification hook (command, test, or artifact check).

Pass policy: all rows must be `PASS` on `main` before declaring 10/10 readiness.

| ID | Dimension | Strict Gate | Verification Hook |
| --- | --- | --- | --- |
| P01 | Product | Async run submission flow exists (`/api/runs/submit`) | `npm --prefix ui run test -- --run src/test/server-contract.test.ts` (submit contract cases) |
| P02 | Product | Live run detail with progress, stage, and ETA | `npm --prefix ui run test -- --run src/test/components.test.tsx` (run detail UI cases) |
| P03 | Product | Cancel action available from dashboard and run detail | `npm --prefix ui run test -- --run src/test/server-contract.test.ts` (cancel cases) |
| P04 | Product | Alert deep-link route (`/alerts/:alertId`) resolves selected alert | `npm --prefix ui run test:e2e:smoke` |
| P05 | Product | First-run onboarding appears once and can be reset | `npm --prefix ui run test:e2e:smoke` |
| A01 | Architecture | `src/wazuh_sysmon_triage/cli_helpers.py` <= 400 LOC | `python - <<'PY' ...` line-count gate |
| A02 | Architecture | `src/wazuh_sysmon_triage/pipeline/detect.py` split to <= 400 LOC modules | `python - <<'PY' ...` line-count gate |
| A03 | Architecture | `ui/server/lib/routes.ts` <= 400 LOC | `python - <<'PY' ...` line-count gate |
| A04 | Architecture | `ui/server/lib/artifact-loader.ts` uses async FS in API hot path | `rg -n \"readFileSync|readdirSync\" ui/server/lib/artifact-loader.ts` |
| A05 | Architecture | Clear queue/executor boundary (`RunQueueService` + `RunExecutor`) | `npm --prefix ui run test -- --run src/test/server-contract.test.ts` (queue tests) + code check (`ui/server/lib/run-executor.ts`) |
| Q01 | Code Quality | `mypy` with `check_untyped_defs=true` passes | `python -m mypy src` |
| Q02 | Code Quality | TS build/typecheck clean | `npm --prefix ui run build` |
| Q03 | Code Quality | Dead code scan (`vulture`) passes | `python -m vulture src tests` |
| Q04 | Code Quality | Dead code scan (`knip`) passes | `npm --prefix ui exec knip` |
| Q05 | Code Quality | Contract docs match API behavior | `npm --prefix ui run test -- --run src/test/server-contract.test.ts` |
| S01 | Security | CSRF guard enforced on browser mutating routes | `npm --prefix ui run test -- --run src/test/middleware.test.ts` |
| S02 | Security | Non-loopback bind requires explicit public bind + auth | `npm --prefix ui run test -- --run src/test/standalone-server.test.ts` |
| S03 | Security | Brute-force Basic Auth throttling active | `npm --prefix ui run test -- --run src/test/standalone-server.test.ts` |
| S04 | Security | SSRF allowlist blocks disallowed OpenSearch targets | `npm --prefix ui run test -- --run src/test/health.test.ts` (allowlist cases) |
| S05 | Security | Secrets/vulnerability scans are clean | CI `Security gate` in `.github/workflows/ci.yml` |
| R01 | Reliability | `POST /api/runs` idempotency replay is stable | `npm --prefix ui run test -- --run src/test/server-contract.test.ts` |
| R02 | Reliability | Health endpoint probe fan-out bounded by cache policy | `npm --prefix ui run test -- --run src/test/health.test.ts` |
| R03 | Reliability | Active-case delete guard prevents destructive race | `npm --prefix ui run test -- --run src/test/server-contract.test.ts` |
| R04 | Reliability | Graceful shutdown drains cleanly and avoids orphan state | `npm --prefix ui run test -- --run src/test/standalone-server.test.ts` (shutdown cases) |
| R05 | Reliability | Queue state survives restart without orphan locks | `npm --prefix ui run test -- --run src/test/server-contract.test.ts` (queue recovery cases) |
| F01 | Performance | `GET /api/runs` p95 <= 300ms on 200-case baseline | `npm --prefix ui run test -- --run src/test/server-performance.test.ts` |
| F02 | Performance | Health endpoint p95 <= 200ms with warm cache | `npm --prefix ui run test -- --run src/test/health.test.ts` (cache latency case) |
| F03 | Performance | Alert table remains responsive at 1000+ rows | `npm --prefix ui run test:e2e:smoke` + UI perf trace |
| F04 | Performance | Sync FS removed from API list/load hot paths | `rg -n \"readFileSync|readdirSync\" ui/server/lib` (targeted exceptions reviewed) |
| F05 | Performance | Existing perf smoke suite stays green | `npm --prefix ui run test -- --run src/test/server-performance.test.ts` |
| M01 | Maintainability | `CONTRIBUTING.md` exists and matches current workflows | doc review + `scripts/release_gate.ps1` dry run |
| M02 | Maintainability | ADR set documents async queue + compatibility decisions | `docs/decisions/*.md` review gate |
| M03 | Maintainability | Devcontainer boots and passes baseline tests | `.devcontainer/devcontainer.json` + CI smoke |
| M04 | Maintainability | Release workflow builds artifacts and notes | `.github/workflows/release.yml` dry-run on tag |
| M05 | Maintainability | New engineer one-day setup path is fully documented | fresh-clone runbook + `README.md` steps validation |

## Current Baseline Commands

Use these commands as the baseline gate run:

```powershell
python -m pytest -q
npm --prefix ui run test -- --run
npm --prefix ui run build
```
