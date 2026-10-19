"""Flask API for bounded asynchronous passive scans."""

from __future__ import annotations

import hmac
import hashlib
import json
import logging
import queue
import re
import threading
import time
import uuid
from pathlib import Path
from datetime import datetime, timezone
from io import BytesIO
from urllib.parse import urlsplit

from flask import Flask, Response, jsonify, request
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from werkzeug.exceptions import HTTPException

from config import Settings
from reports.json_report import write_report
from scanner import Scanner
from scanner.url_validation import TargetValidationError, report_safe_url, validate_target
from storage import ScanStore
from rate_limit import LocalLimiter, RedisLimiter

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("sitesentry.api")


def create_app(settings: Settings | None = None) -> Flask:
    settings = settings or Settings.from_env()
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
    store = ScanStore(settings.database_path)
    if settings.redis_url:
        import redis
        work_queue = redis.Redis.from_url(settings.redis_url,decode_responses=True,socket_connect_timeout=2,socket_timeout=2)
        work_queue.ping()
        work_queue_key=f"{settings.redis_namespace.rstrip(':')}:scan_queue"
    else:
        work_queue: queue.Queue[tuple[str, str, str]] = queue.Queue(maxsize=settings.max_pending_scans)
        work_queue_key=None
    active_scans: set[str] = set()
    scans_lock = threading.Lock()
    limiter = RedisLimiter(settings.redis_url, settings.redis_namespace) if settings.redis_url else LocalLimiter()
    cancelled_lock = threading.Lock()
    cancelled: set[str] = set()
    scan_lock = threading.Lock()

    def model_artifact_dir() -> Path:
        return Path(__file__).resolve().parent / "models" / "mswd-final"

    def identity() -> str | None:
        if settings.auth_mode=="proxy_identity":
            if request.headers.get("X-Forwarded-Proto", "").lower() != "https": return None
            value=request.headers.get("X-Authenticated-User", "").strip()
            return value[:200] if value else None
        supplied=request.headers.get("Authorization", "").removeprefix("Bearer ")
        if not settings.api_token or not hmac.compare_digest(supplied,settings.api_token): return None
        return "token:"+hashlib.sha256(settings.api_token.encode()).hexdigest()[:24]

    def worker():
        scanner=Scanner(timeout=(settings.connect_timeout,settings.read_timeout),allowed_domains=set(settings.allowed_domains) or None)
        while True:
            try:
                if work_queue_key:
                    item=work_queue.blpop(work_queue_key,timeout=1)
                    if item is None: continue
                    _,payload=item
                    queued=json.loads(payload)
                    scan_id,url=queued[0],queued[1]
                    profile=queued[2] if len(queued)>2 else "standard"
                else:
                    queued=work_queue.get(timeout=0.5)
                    scan_id,url=queued[0],queued[1]
                    profile=queued[2] if len(queued)>2 else "standard"
            except (queue.Empty,TimeoutError): continue
            with scan_lock:
                with cancelled_lock:
                    is_cancelled=scan_id in cancelled
                if is_cancelled or store.get_status(scan_id)!="queued":
                    if not work_queue_key: work_queue.task_done()
                    continue
                store.update_status(scan_id,"running")
            with scans_lock: active_scans.add(scan_id)
            try:
                result=scanner.scan(url,profile=profile); data=result.to_dict()
                if result.scan_status=="completed": write_report(result,settings.report_dir)
                store.update_status(scan_id,result.scan_status,result=data,error="; ".join(result.errors) or None,finished_at=datetime.now(timezone.utc).isoformat())
            except Exception:
                logger.exception("Unhandled scan failure for %s",scan_id)
                store.update_status(scan_id,"error",error="Internal scan error.",finished_at=datetime.now(timezone.utc).isoformat())
            finally:
                with scans_lock: active_scans.discard(scan_id)
                if not work_queue_key: work_queue.task_done()

    for i in range(settings.max_workers): threading.Thread(target=worker,name=f"sitesentry-worker-{i}",daemon=True).start()

    @app.before_request
    def guard():
        if request.path=="/api/health" and settings.auth_mode=="static_token" and not settings.api_token: return None
        if identity() is None: return jsonify({"error":"unauthorized"}),401

    @app.errorhandler(413)
    def request_too_large(_exc): return jsonify({"error":"request_too_large"}),413

    @app.errorhandler(Exception)
    def unexpected(exc):
        if isinstance(exc, HTTPException):
            return jsonify({"error": exc.name.lower().replace(" ", "_")}), exc.code
        logger.exception("API request failed")
        return jsonify({"error":"internal_error"}),500

    @app.get("/api/health")
    def health():
        with scans_lock: active=len(active_scans)
        depth=work_queue.llen(work_queue_key) if work_queue_key else work_queue.qsize()
        return jsonify({"status":"ok","queue_depth":depth,"active_scans":active,"workers":settings.max_workers})

    @app.get("/api/models")
    def list_models():
        """List only checksum-verified deployed advisory classifiers."""
        from ml.deployment import verify_bundle
        directory = model_artifact_dir()
        entries = []
        for manifest_path in sorted(directory.glob("*.manifest.json")):
            artifact = manifest_path.with_name(manifest_path.name.removesuffix(".manifest.json"))
            try:
                manifest = verify_bundle(artifact)
            except (OSError, ValueError, json.JSONDecodeError):
                logger.exception("Model manifest verification failed for %s", artifact.name)
                continue
            if manifest.get("task") != "mswd_malicious_site":
                continue
            try:
                metadata = json.loads((directory / "mswd_training_report.json").read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                metadata = {}
            model_key = artifact.stem
            entries.append({"id": model_key, "model_version": manifest.get("model_version"),
                "task": manifest.get("task"), "feature_columns": manifest.get("feature_columns", []),
                "metrics": (metadata.get("metrics") or {}).get(model_key),
                "label_mapping": metadata.get("label_mapping"),
                "label_mapping_status": metadata.get("label_mapping_status"),
                "limitations": metadata.get("limitations", []), "manifest": manifest})
        config_path = Path(__file__).resolve().parent / "models" / "config_review.joblib"
        try:
            manifest = verify_bundle(config_path)
            entries.append({"id": "configuration_review", "model_version": manifest.get("model_version"),
                "task": "configuration_review", "feature_columns": manifest.get("feature_columns", []),
                "metrics": manifest.get("metrics"), "manifest": manifest})
        except FileNotFoundError:
            pass
        except (OSError, ValueError, json.JSONDecodeError):
            logger.exception("Configuration review model verification failed")
        return jsonify({"models": entries})

    @app.post("/api/models/<model_id>/predict")
    def predict_model(model_id):
        """Run an explicit advisory model request; never mutates scan findings."""
        if not re.fullmatch(r"[a-z0-9_-]{1,80}", model_id):
            return jsonify({"error": "invalid_model_id"}), 400
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict) or set(payload) != {"features"} or not isinstance(payload["features"], dict):
            return jsonify({"error": "invalid_request", "message": "Send a JSON object with a features object."}), 400
        features = payload["features"]
        if len(features) > 100 or any(not isinstance(key, str) or len(key) > 120 for key in features):
            return jsonify({"error": "invalid_features"}), 400
        from ml.deployment import verify_bundle
        from ml.mswd_predict import predict_mswd_features
        artifact = model_artifact_dir() / f"{model_id}.joblib"
        if model_id == "configuration_review":
            artifact = Path(__file__).resolve().parent / "models" / "config_review.joblib"
        if not artifact.is_file():
            return jsonify({"error": "model_not_found"}), 404
        try:
            manifest = verify_bundle(artifact)
            if manifest.get("task") == "mswd_malicious_site":
                if set(features) - set(manifest.get("feature_columns", [])):
                    return jsonify({"error": "unknown_features"}), 400
                result = predict_mswd_features(features, artifact)
            elif manifest.get("task") == "configuration_review":
                if set(features) - {"https", "tls_verified", "tls_days_remaining", "headers"}:
                    return jsonify({"error": "unknown_features"}), 400
                if not isinstance(features.get("headers", {}), dict):
                    return jsonify({"error": "invalid_features"}), 400
                from ml.predict import assess
                from xai.feature_attribution import explain_linear
                result = assess(features, str(artifact))
                result["xai"] = explain_linear(features, str(artifact))
            else:
                return jsonify({"error": "unsupported_model_task"}), 409
        except (ValueError, OSError, KeyError) as exc:
            logger.exception("Model inference failed for %s", model_id)
            return jsonify({"error": "model_inference_failed", "detail": type(exc).__name__}), 500
        return jsonify(result)

    @app.post("/api/scans")
    def create_scan():
        payload=request.get_json(silent=True)
        if not isinstance(payload,dict) or set(payload)-{"url","profile"}: return jsonify({"error":"invalid_request"}),400
        try: target=validate_target(payload.get("url"),allowed_domains=set(settings.allowed_domains) or None)
        except TargetValidationError as exc: return jsonify({"error":"target_rejected","message":str(exc)}),400
        profile=payload.get("profile","standard")
        if profile=="passive": profile="standard"
        if not isinstance(profile,str) or profile not in {"quick","standard","advanced"}: return jsonify({"error":"unsupported_profile"}),400
        client=identity()
        if client is None: return jsonify({"error":"unauthorized"}),401
        scan_id,created=uuid.uuid4().hex,datetime.now(timezone.utc).isoformat()
        with scan_lock:
            if (work_queue.llen(work_queue_key)>=settings.max_pending_scans if work_queue_key else work_queue.full()): return jsonify({"error":"scan_queue_full"}),429
            allowed,reason=limiter.allow(client,per_minute=settings.per_minute_limit,per_day=settings.daily_quota_per_client,global_per_day=settings.daily_scan_quota)
            if not allowed: return jsonify({"error":reason}),429
            store.create_scan(scan_id,report_safe_url(target.url),created,profile,client)
            if work_queue_key:
                work_queue.rpush(work_queue_key,json.dumps([scan_id,target.url,profile]))
            else:
                work_queue.put_nowait((scan_id,target.url,profile))
        return jsonify({"scan_id":scan_id,"status":"queued","created_at":created,"profile":profile}),202

    @app.get("/api/scans")
    def list_scans():
        try: limit=min(max(int(request.args.get("limit","50")),1),100)
        except ValueError: return jsonify({"error":"invalid_limit"}),400
        return jsonify({"scans":store.list_scans(limit,identity())})

    @app.get("/api/scans/<scan_id>")
    def get_scan(scan_id):
        scan=store.get_scan(scan_id,identity())
        if not scan: return jsonify({"error":"not_found"}),404
        return jsonify({key:value for key,value in scan.items() if key!="result"}|{"summary":scan["result"].get("summary") if scan["result"] else None})

    @app.get("/api/scans/<scan_id>/findings")
    def findings(scan_id):
        scan=store.get_scan(scan_id,identity())
        if not scan: return jsonify({"error":"not_found"}),404
        return jsonify({"scan_id":scan_id,"findings":_enrich_saved_result(scan["result"]).get("findings",[]) if scan["result"] else []})

    @app.get("/api/scans/<scan_id>/workflow")
    def get_finding_workflow(scan_id):
        scan=store.get_scan(scan_id,identity())
        if not scan: return jsonify({"error":"not_found"}),404
        return jsonify({"scan_id":scan_id,"workflow":store.get_workflows(scan_id,identity())})

    @app.put("/api/scans/<scan_id>/findings/<path:check_id>/workflow")
    def update_finding_workflow(scan_id,check_id):
        scan=store.get_scan(scan_id,identity())
        if not scan: return jsonify({"error":"not_found"}),404
        if not scan["result"]: return jsonify({"error":"scan_not_complete"}),409
        finding=next((item for item in scan["result"].get("findings",[]) if item.get("check_id")==check_id),None)
        if not finding: return jsonify({"error":"finding_not_found"}),404
        payload=request.get_json(silent=True)
        if not isinstance(payload,dict) or set(payload)-{"status","note"} or payload.get("status") not in {"open","acknowledged","fixed"}:
            return jsonify({"error":"invalid_workflow_status","allowed":["open","acknowledged","fixed"]}),400
        note=payload.get("note","")
        if not isinstance(note,str) or len(note)>500 or any(ord(char)<32 and char not in "\t\n\r" for char in note):
            return jsonify({"error":"invalid_note"}),400
        updated=datetime.now(timezone.utc).isoformat()
        try:
            if payload["status"] == "open":
                store.delete_workflow(scan_id,check_id,identity(),updated)
            else:
                store.set_workflow(scan_id,check_id,identity(),payload["status"],note.strip(),updated)
        except PermissionError:
            return jsonify({"error":"not_found"}),404
        return jsonify({"scan_id":scan_id,"check_id":check_id,"status":payload["status"],"note":note.strip(),"updated_at":updated}),200

    @app.get("/api/scans/<scan_id>/compare/<baseline_id>")
    def compare_scans(scan_id,baseline_id):
        current=store.get_scan(scan_id,identity())
        baseline=store.get_scan(baseline_id,identity())
        if not current or not baseline: return jsonify({"error":"not_found"}),404
        if not current["result"] or not baseline["result"]: return jsonify({"error":"scan_not_complete"}),409
        if not _same_scan_target(current["target"],baseline["target"]):
            return jsonify({"error":"target_mismatch","message":"Historical comparisons require the same hostname, port, and path."}),400
        baseline_result=_enrich_saved_result(baseline["result"])
        current_result=_enrich_saved_result(current["result"])
        old={item.get("check_id"):item for item in baseline_result.get("findings",[])}
        new={item.get("check_id"):item for item in current_result.get("findings",[])}
        unresolved={"finding","warning","fail","error","inconclusive"}
        changes=[]
        for check_id in sorted(set(old)|set(new)):
            before,after=old.get(check_id),new.get(check_id)
            before_status=before.get("status") if before else None
            after_status=after.get("status") if after else None
            if before is None or before_status=="pass" and after_status in unresolved:
                change="new"
            elif before_status in unresolved and after_status=="pass":
                change="resolved"
            elif before_status in unresolved and after_status in unresolved:
                change="recurring" if before_status==after_status and before.get("evidence")==after.get("evidence") else "changed"
            elif before_status==after_status and (before or {}).get("evidence")== (after or {}).get("evidence"):
                change="unchanged"
            else:
                change="changed"
            changes.append({"check_id":check_id,"check":(after or before or {}).get("check"),"change":change,
                "before_status":before_status,"after_status":after_status,"before_evidence":(before or {}).get("evidence"),
                "after_evidence":(after or {}).get("evidence"),"risk_before":(before or {}).get("risk"),"risk_after":(after or {}).get("risk")})
        return jsonify({"scan_id":scan_id,"baseline_scan_id":baseline_id,"target":current["target"],
            "baseline_completed_at":baseline["finished_at"],"current_completed_at":current["finished_at"],
            "scanner_version_changed":baseline_result.get("scanner_version")!=current_result.get("scanner_version"),
            "profile_changed":baseline.get("profile")!=current.get("profile"),"changes":changes})

    @app.get("/api/scans/<scan_id>/explanations")
    def explanations(scan_id):
        scan=store.get_scan(scan_id,identity())
        if not scan: return jsonify({"error":"not_found"}),404
        items=scan["result"].get("findings",[]) if scan["result"] else []
        return jsonify({"scan_id":scan_id,"explanations":[{"check_id":f["check_id"],"explanation":f["explanation"],"evidence":f["evidence"],"recommendation":f["recommendation"],"source":"deterministic_rule"} for f in items]})

    @app.get("/api/scans/<scan_id>/xai-report")
    def xai_report(scan_id):
        scan=store.get_scan(scan_id,identity())
        if not scan: return jsonify({"error":"not_found"}),404
        if not scan["result"]: return jsonify({"error":"report_not_ready"}),409
        from xai.report import generate_xai_report
        return jsonify(generate_xai_report(_enrich_saved_result(scan["result"])))

    @app.get("/api/scans/<scan_id>/report")
    def report(scan_id):
        scan=store.get_scan(scan_id,identity())
        if not scan: return jsonify({"error":"not_found"}),404
        if not scan["result"]: return jsonify({"error":"report_not_ready"}),409
        result=_enrich_saved_result(scan["result"])
        fmt=request.args.get("format","json").lower()
        if fmt=="json": return Response(json.dumps(result,ensure_ascii=False,indent=2),mimetype="application/json",headers={"Content-Disposition":f"attachment; filename=sitesentry-{scan_id}.json"})
        if fmt=="pdf": return Response(_pdf_report(result),mimetype="application/pdf",headers={"Content-Disposition":f"attachment; filename=sitesentry-{scan_id}.pdf"})
        return jsonify({"error":"unsupported_format"}),400

    @app.post("/api/scans/<scan_id>/cancel")
    def cancel_scan(scan_id):
        scan=store.get_scan(scan_id,identity())
        if not scan: return jsonify({"error":"not_found"}),404
        with scan_lock:
            scan=store.get_scan(scan_id,identity())
            if scan["status"]!="queued": return jsonify({"error":"scan_not_cancellable","status":scan["status"]}),409
            # Queue ownership is serialized with the worker's dequeue transition by
            # scan_lock; queued rows are cancellable until that transition commits.
            if work_queue_key:
                try:
                    # Queue payloads carry the actual URL for the worker. Match
                    # by scan ID without copying secret query values into history.
                    for queued_payload in work_queue.lrange(work_queue_key,0,-1):
                        try:
                            if json.loads(queued_payload)[0] == scan_id:
                                work_queue.lrem(work_queue_key,1,queued_payload)
                                break
                        except (ValueError, TypeError, IndexError):
                            continue
                except Exception:
                    logger.exception("Could not remove cancelled scan %s from shared queue",scan_id)
            with cancelled_lock: cancelled.add(scan_id)
            store.update_status(scan_id,"cancelled",error="Cancelled before execution.",finished_at=datetime.now(timezone.utc).isoformat())
        return jsonify({"scan_id":scan_id,"status":"cancelled"})

    app.extensions["sitesentry_store"]=store
    app.extensions["sitesentry_queue"]=work_queue
    app.extensions["sitesentry_limiter"]=limiter
    return app


def _pdf_report(result: dict) -> bytes:
    buffer=BytesIO(); pdf=canvas.Canvas(buffer,pagesize=letter); height=letter[1]; y=height-48
    def line(text,bold=False):
        nonlocal y
        if y<54: pdf.showPage(); y=height-48
        pdf.setFont("Helvetica-Bold" if bold else "Helvetica",9); pdf.drawString(42,y,str(text)[:130]); y-=14
    for text,bold in [("SiteSentry Security Assessment Report",True),(f"Target: {result.get('target','')}",False),(f"Scan ID: {result.get('scan_id','')}",False),(f"Status: {result.get('scan_status','')}",False),(f"Summary: {result.get('summary',{})}",False)]: line(text,bold)
    for finding in result.get("findings",[]):
        line(f"{finding.get('check_id')} | {finding.get('status')} | {finding.get('severity')}",True)
        risk=finding.get("risk") or {}
        if risk: line(f"Risk priority: {risk.get('score',0)}/100 | evidence confidence: {float(risk.get('confidence',0)):.0%}")
        line(f"Evidence: {finding.get('evidence','')}"); line(f"Recommendation: {finding.get('recommendation','')}"); line(f"Explanation: {finding.get('explanation','')}")
        for mapping in finding.get("standards",[]): line(f"Guidance: {mapping.get('framework')} {mapping.get('version')} | {mapping.get('control')} | partial mapping only")
    for limitation in result.get("limitations",[]): line(f"Limitation: {limitation}")
    pdf.save(); return buffer.getvalue()


def _enrich_saved_result(result: dict) -> dict:
    from scanner.risk import aggregate_risk, annotate_findings
    enriched=dict(result)
    enriched["findings"]=annotate_findings(result.get("findings", []))
    enriched["risk_summary"]=aggregate_risk(enriched["findings"])
    return enriched


def _same_scan_target(first: str, second: str) -> bool:
    """Compare identical hostname/port/path, ignoring scheme and query values."""
    try:
        left, right = urlsplit(first), urlsplit(second)
        if left.username or left.password or right.username or right.password:
            return False
        left_port = left.port or (443 if left.scheme == "https" else 80)
        right_port = right.port or (443 if right.scheme == "https" else 80)
        left_path = left.path.rstrip("/") or "/"
        right_path = right.path.rstrip("/") or "/"
        return bool(left.hostname and right.hostname and left.hostname.lower() == right.hostname.lower()
            and left_port == right_port and left_path == right_path)
    except ValueError:
        return False


if __name__ == "__main__":
    from dotenv import load_dotenv
    from pathlib import Path
    load_dotenv(Path(__file__).resolve().parent / ".env", override=False)
    create_app().run(host="127.0.0.1", port=5000, debug=False)
