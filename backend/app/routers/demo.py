"""Demo scenarios, sandbox (M5), experiments, ML information and system reset."""
from fastapi import APIRouter, Depends, HTTPException
from fastapi.concurrency import run_in_threadpool
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import demo, experiments
from app.database import get_db
from app.ml.model import get_classifier
from app.models import ExperimentRun, SandboxRun, User
from app.routers.serializers import iso, sandbox_dict
from app.security import sandbox
from app.security.audit import append_audit
from app.security.auth import require_permission
from app.seed import init_database

router = APIRouter(prefix="/api", tags=["demo"])


@router.get("/demo/scenarios")
def list_scenarios(_user: User = Depends(require_permission("dashboard:view"))):
    return demo.SCENARIOS


@router.post("/demo/scenarios/{scenario_id}/run")
async def run_demo(scenario_id: int, db: Session = Depends(get_db), user: User = Depends(require_permission("demo:run"))):
    try:
        return await demo.run_scenario(db, scenario_id, user.username)
    except KeyError as exc:
        raise HTTPException(404, str(exc))


@router.get("/sandbox/scenarios")
def sandbox_scenarios(_user: User = Depends(require_permission("dashboard:view"))):
    return [{"key": k, "title": v["title"], "description": v["description"], "expected": v["expected"]}
            for k, v in sandbox.SCENARIOS.items()]


@router.post("/sandbox/run/{key}")
async def run_sandbox(key: str, db: Session = Depends(get_db), user: User = Depends(require_permission("sandbox:run"))):
    if key not in sandbox.SCENARIOS:
        raise HTTPException(404, "unknown sandbox scenario")
    result = await run_in_threadpool(sandbox.run_scenario, key)
    run = SandboxRun(scenario=key, outcome=result["outcome"], expected_outcome=result["expected"],
                     duration_ms=result["duration_ms"], output=result["output"],
                     blocked_operation=result["blocked_operation"], run_by=user.username)
    db.add(run)
    db.commit()
    append_audit(db, event_type="SANDBOX_RUN", actor=user.username, action=result["outcome"].upper(),
                 details={"scenario": key, "blocked_operation": result["blocked_operation"], "passed": result["passed"]})
    return sandbox_dict(run)


@router.get("/sandbox/runs")
def sandbox_runs(db: Session = Depends(get_db), _user: User = Depends(require_permission("dashboard:view"))):
    return [sandbox_dict(r) for r in db.scalars(select(SandboxRun).order_by(SandboxRun.created_at.desc()).limit(50))]


@router.post("/experiments/run")
async def run_experiments(seed: int = experiments.DEFAULT_SEED, db: Session = Depends(get_db),
                          user: User = Depends(require_permission("experiments:run"))):
    results = await run_in_threadpool(experiments.run_experiment, seed)
    await run_in_threadpool(experiments.write_results, results)
    run = ExperimentRun(seed=seed, results=results, run_by=user.username)
    db.add(run)
    db.commit()
    append_audit(db, event_type="EXPERIMENT_RUN", actor=user.username, action="COMPLETED",
                 details={"seed": seed, "detection_rates": {k: v["overall"]["detection_rate"]
                                                            for k, v in results["configurations"].items()}})
    return {"id": run.id, "created_at": iso(run.created_at), "run_by": run.run_by, "results": results}


@router.get("/experiments/latest")
def latest_experiment(db: Session = Depends(get_db), _user: User = Depends(require_permission("dashboard:view"))):
    run = db.scalar(select(ExperimentRun).order_by(ExperimentRun.created_at.desc()).limit(1))
    if run is None:
        return None
    return {"id": run.id, "created_at": iso(run.created_at), "run_by": run.run_by, "results": run.results}


@router.get("/ml/info")
def ml_info(_user: User = Depends(require_permission("dashboard:view"))):
    return get_classifier().metrics


@router.post("/admin/reset")
async def reset_system(user: User = Depends(require_permission("system:reset"))):
    """Recreate the database with fresh demo data (useful before a live demonstration)."""
    await init_database(reset=True)
    return {"reset": True, "by": user.username}
