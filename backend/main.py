from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import secrets
import statistics
import tempfile
import threading
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import httpx
from cvss import (
    CVSS2,
    CVSS2Error,
    CVSS3,
    CVSS3Error,
    CVSS4,
    CVSS4Error,
)
from fastapi import (
    Depends,
    FastAPI,
    File,
    Form,
    HTTPException,
    Request,
    Security,
    UploadFile,
    status,
)
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from parsers import ECOSYSTEM_MAP, PROJECT_NAME_RE, identify_manifest, parse_manifest


logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent
MANIFESTS_DIR = BASE_DIR / "manifests"
RESULTS_DIR = BASE_DIR / "results"
CONFIG_FILE = BASE_DIR / "config" / "settings.json"
SYSTEM_STATE_FILE = BASE_DIR / "config" / "system_state.json"

DEFAULT_SETTINGS = {
    "cron_schedule": "0 */6 * * *",
    "scan_history_size": 15,
    "relative_url_root": "",
    "scan_batch_size": 10,
}
SYSTEM_STATE_KEYS = {
    "api_token",
    "upload_token",
    "last_global_scan",
    "ignored_vulnerabilities_by_project",
    "ignored_vulnerabilities",
    "scan_history",
    "vulnerability_lifecycle",
}
DEFAULT_SYSTEM_STATE = {
    "last_global_scan": None,
    "ignored_vulnerabilities_by_project": {},
    "scan_history": [],
    "vulnerability_lifecycle": [],
}
MAX_UPLOAD_BYTES = 5 * 1024 * 1024
MAX_PACKAGES_PER_MANIFEST = 1000
OSV_QUERY_BATCH_SIZE = 100
MAX_PROJECT_CONCURRENCY = 10
MAX_VULN_DETAIL_CONCURRENCY = 20
OSV_BASE_URL = "https://api.osv.dev/v1"
MAX_UPLOAD_REQUEST_BYTES = MAX_UPLOAD_BYTES + 64 * 1024

for directory in (MANIFESTS_DIR, RESULTS_DIR, CONFIG_FILE.parent):
    directory.mkdir(parents=True, exist_ok=True)

CONFIG_STATE_LOCK = threading.RLock()
RESULTS_LOCK = threading.RLock()


class UploadBodyLimitMiddleware:
    """Bound multipart bodies before FastAPI parses and spools uploaded files."""

    def __init__(self, app, maximum_request_bytes: int):
        self.app = app
        self.maximum_request_bytes = maximum_request_bytes

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http" or not scope.get("path", "").rstrip("/").endswith("/api/upload"):
            await self.app(scope, receive, send)
            return

        content_length = next(
            (value.decode("latin-1") for key, value in scope.get("headers", []) if key.lower() == b"content-length"),
            None,
        )
        if content_length:
            try:
                too_large = int(content_length) > self.maximum_request_bytes
            except ValueError:
                too_large = True
            if too_large:
                await self._send_too_large(send)
                return

        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                continue
            body.extend(message.get("body", b""))
            if len(body) > self.maximum_request_bytes:
                await self._send_too_large(send)
                return
            if not message.get("more_body", False):
                break

        consumed = False

        async def replay_receive():
            nonlocal consumed
            if not consumed:
                consumed = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return {"type": "http.disconnect"}

        await self.app(scope, replay_receive, send)

    @staticmethod
    async def _send_too_large(send):
        body = json.dumps({"detail": "La carga supera el límite de 5 MiB"}).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


def _atomic_write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temp_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(data, stream, indent=2, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
    except Exception:
        Path(temp_name).unlink(missing_ok=True)
        raise


def _atomic_write_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temp_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
    except Exception:
        Path(temp_name).unlink(missing_ok=True)
        raise


def _default_system_state() -> dict:
    return {
        **DEFAULT_SYSTEM_STATE,
        "api_token": secrets.token_hex(32),
        "upload_token": secrets.token_hex(32),
    }


def _read_json_object(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as stream:
            loaded = json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"No se pudo leer {path.name}: {exc}") from exc
    if not isinstance(loaded, dict):
        raise RuntimeError(f"{path.name} debe contener un objeto JSON")
    return loaded


def _load_stores_unlocked() -> tuple[dict, dict]:
    """Load both stores and migrate system-managed keys from legacy settings.json."""
    legacy_config = _read_json_object(CONFIG_FILE)
    saved_state = _read_json_object(SYSTEM_STATE_FILE)

    settings_values = {
        key: value for key, value in legacy_config.items()
        if key not in SYSTEM_STATE_KEYS
    }
    settings = {**DEFAULT_SETTINGS, **settings_values}
    state_values = {
        key: legacy_config[key]
        for key in SYSTEM_STATE_KEYS
        if key in legacy_config
    }
    state_values.update(saved_state)
    state = {**_default_system_state(), **state_values}

    if not isinstance(settings.get("relative_url_root"), str):
        settings["relative_url_root"] = DEFAULT_SETTINGS["relative_url_root"]
    if not isinstance(settings.get("cron_schedule"), str):
        settings["cron_schedule"] = DEFAULT_SETTINGS["cron_schedule"]
    for token_name in ("api_token", "upload_token"):
        if not isinstance(state.get(token_name), str) or not state[token_name]:
            state[token_name] = secrets.token_hex(32)

    ignored_by_project = state.get("ignored_vulnerabilities_by_project", {})
    if not isinstance(ignored_by_project, dict):
        ignored_by_project = {}
    normalized_ignored: dict[str, list[str]] = {}
    for project, values in ignored_by_project.items():
        if not isinstance(project, str) or not isinstance(values, list):
            continue
        identifiers = sorted({value for value in values if isinstance(value, str) and value})
        if identifiers:
            normalized_ignored[project] = identifiers
    state["ignored_vulnerabilities_by_project"] = normalized_ignored

    legacy_ids: set[str] = set()
    for source in (legacy_config, saved_state):
        values = source.get("ignored_vulnerabilities", [])
        if isinstance(values, list):
            legacy_ids.update(value for value in values if isinstance(value, str) and value)
    if legacy_ids:
        migrated = {
            project: set(identifiers)
            for project, identifiers in normalized_ignored.items()
        }
        for result_file in sorted(RESULTS_DIR.glob("*_results.json")):
            try:
                project_result = json.loads(result_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning("No se pudieron migrar ignores desde %s: %s", result_file.name, exc)
                continue
            if not isinstance(project_result, dict):
                logger.warning("Se omite la migración desde %s: el resultado no es un objeto", result_file.name)
                continue
            project = project_result.get("project")
            if not isinstance(project, str) or not project:
                project = result_file.name[: -len("_results.json")]
            for vuln in project_result.get("vulnerabilities", []):
                if not isinstance(vuln, dict):
                    continue
                identifiers = {
                    value for value in (vuln.get("id"), vuln.get("osv_id"))
                    if isinstance(value, str) and value
                }
                if identifiers & legacy_ids:
                    migrated.setdefault(project, set()).update(identifiers)
        state["ignored_vulnerabilities_by_project"] = {
            project: sorted(identifiers)
            for project, identifiers in migrated.items()
            if identifiers
        }
    state.pop("ignored_vulnerabilities", None)
    if not isinstance(state.get("scan_history"), list):
        state["scan_history"] = []
    else:
        state["scan_history"] = list(state["scan_history"])
    if not isinstance(state.get("vulnerability_lifecycle"), list):
        state["vulnerability_lifecycle"] = []
    else:
        state["vulnerability_lifecycle"] = list(state["vulnerability_lifecycle"])
    if "last_global_scan" not in state:
        state["last_global_scan"] = None

    if not SYSTEM_STATE_FILE.exists() or state != saved_state:
        _atomic_write_json(SYSTEM_STATE_FILE, state)
    if not CONFIG_FILE.exists() or settings != legacy_config:
        _atomic_write_json(CONFIG_FILE, settings)
    return settings, state


def load_settings() -> dict:
    with CONFIG_STATE_LOCK:
        settings, _ = _load_stores_unlocked()
        return settings


def load_system_state() -> dict:
    with CONFIG_STATE_LOCK:
        _, state = _load_stores_unlocked()
        return state


def mutate_system_state(mutator) -> dict:
    """Serialize read-modify-write updates to the system-managed state file."""
    with CONFIG_STATE_LOCK:
        _, state = _load_stores_unlocked()
        mutator(state)
        _atomic_write_json(SYSTEM_STATE_FILE, state)
        return state


active_config = load_settings()
app = FastAPI(
    title="SecOps SCA Monitor API",
    root_path=active_config.get("relative_url_root", ""),
)
app.add_middleware(UploadBodyLimitMiddleware, maximum_request_bytes=MAX_UPLOAD_REQUEST_BYTES)

security_scheme = HTTPBearer(auto_error=False)


def _credential_matches(provided: str, expected: str | None) -> bool:
    return bool(expected) and secrets.compare_digest(provided.encode("utf-8"), expected.encode("utf-8"))


def verify_token(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Security(security_scheme),
):
    del request
    api_token = load_system_state().get("api_token")
    if not api_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token de acceso no configurado",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not credentials or not _credential_matches(credentials.credentials, api_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token de acceso inválido o no proporcionado",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return credentials.credentials


def verify_any_token(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Security(security_scheme),
):
    del request
    state = load_system_state()
    provided_token = credentials.credentials if credentials else ""
    if _credential_matches(provided_token, state.get("api_token")) or _credential_matches(
        provided_token, state.get("upload_token")
    ):
        return provided_token
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token de acceso inválido o no autorizado para esta operación",
        headers={"WWW-Authenticate": "Bearer"},
    )


CVSS_CALCULATORS = {
    "CVSS_V2": (CVSS2, CVSS2Error),
    "CVSS_V3": (CVSS3, CVSS3Error),
    "CVSS_V4": (CVSS4, CVSS4Error),
}


def _cvss_vector_score(vector: str, score_type: str) -> tuple[float | None, str | None]:
    """Return the Base Score and Base Severity for a valid OSV CVSS vector."""
    calculator_info = CVSS_CALCULATORS.get(score_type)
    if calculator_info is None:
        return None, None

    calculator, error_type = calculator_info
    normalized_vector = vector.strip()
    # CVSS v2 vectors are normally unprefixed, but accept the optional OSV prefix.
    if score_type == "CVSS_V2":
        normalized_vector = re.sub(r"^CVSS:2\.0/", "", normalized_vector, flags=re.IGNORECASE)
    try:
        parsed_vector = calculator(normalized_vector)
        score = float(parsed_vector.scores()[0])
        severity = str(parsed_vector.severities()[0]).upper()
    except error_type:
        return None, None
    except (IndexError, TypeError, ValueError):
        return None, None

    if not 0 <= score <= 10:
        return None, None
    return score, severity


def extract_severity(vuln: dict) -> tuple[str, float | None, str]:
    """Prefer OSV's label; calculate CVSS v2/v3/v4 scores from vectors when possible."""
    database_specific = vuln.get("database_specific")
    if not isinstance(database_specific, dict):
        database_specific = {}
    db_severity = str(database_specific.get("severity", "")).upper()
    vector = ""
    numeric_score: float | None = None
    vector_severity: str | None = None
    score_type: str | None = None
    severities = vuln.get("severity", [])
    if not isinstance(severities, list):
        severities = []
    for item in severities:
        if not isinstance(item, dict):
            continue
        score_type = item.get("type")
        if score_type not in CVSS_CALCULATORS:
            continue
        raw_score = item.get("score", "")
        if isinstance(raw_score, (int, float)) and not isinstance(raw_score, bool):
            numeric_score = float(raw_score)
        elif isinstance(raw_score, str):
            vector = raw_score
            try:
                numeric_score = float(raw_score.strip())
            except ValueError:
                numeric_score, vector_severity = _cvss_vector_score(raw_score, score_type)
        break
    if numeric_score is not None and not 0 <= numeric_score <= 10:
        numeric_score = None

    severity_map = {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MODERATE": "MEDIUM",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
    }
    if db_severity in severity_map:
        return severity_map[db_severity], numeric_score, vector
    if vector_severity in severity_map or vector_severity == "NONE":
        # The UI uses four risk bands; CVSS "None" is placed in the lowest band.
        return severity_map.get(vector_severity, "LOW"), numeric_score, vector
    if numeric_score is not None:
        if score_type == "CVSS_V2":
            # CVSS v2 has no Critical band: High starts at 7.0.
            if numeric_score >= 7.0:
                return "HIGH", numeric_score, vector
            if numeric_score >= 4.0:
                return "MEDIUM", numeric_score, vector
            return "LOW", numeric_score, vector
        if numeric_score >= 9.0:
            return "CRITICAL", numeric_score, vector
        if numeric_score >= 7.0:
            return "HIGH", numeric_score, vector
        if numeric_score >= 4.0:
            return "MEDIUM", numeric_score, vector
        return "LOW", numeric_score, vector
    # Conservative category fallback when OSV supplies a vector but no score.
    return "HIGH", None, vector


def extract_fixed_version(vuln: dict, pkg_name: str) -> str:
    for affected in vuln.get("affected", []):
        if affected.get("package", {}).get("name", "").casefold() == pkg_name.casefold():
            for version_range in affected.get("ranges", []):
                for event in version_range.get("events", []):
                    if "fixed" in event:
                        return f">= {event['fixed']}"
    return "Revisar advisory"


def calculate_score(counts: dict) -> tuple[int, str]:
    penalty = (
        counts["CRITICAL"] * 25
        + counts["HIGH"] * 10
        + counts["MEDIUM"] * 3
        + counts["LOW"]
    )
    score = max(0, 100 - penalty)
    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 65:
        grade = "C"
    elif score >= 50:
        grade = "D"
    else:
        grade = "F"
    return score, grade


def _error_message(exc: Exception) -> str:
    if isinstance(exc, HTTPException):
        return str(exc.detail)
    return str(exc) or exc.__class__.__name__


def _ignored_ids(state: dict, project: str) -> set[str]:
    ignored_by_project = state.get("ignored_vulnerabilities_by_project", {})
    if not isinstance(ignored_by_project, dict):
        return set()
    values = ignored_by_project.get(project, [])
    if not isinstance(values, list):
        return set()
    return {value for value in values if isinstance(value, str)}


async def _request_osv_json(
    client: httpx.AsyncClient,
    url: str,
    *,
    payload: dict | None = None,
) -> dict:
    for attempt in range(3):
        try:
            if payload is None:
                response = await client.get(url)
            else:
                response = await client.post(url, json=payload)
        except httpx.RequestError as exc:
            if attempt == 2:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="OSV no está disponible; el escaneo no se guardó como completo.",
                ) from exc
            await asyncio.sleep(0.5 * (2**attempt))
            continue

        if response.status_code == 429 or response.status_code >= 500:
            if attempt < 2:
                await asyncio.sleep(0.5 * (2**attempt))
                continue
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"OSV devolvió HTTP {response.status_code}; el escaneo no se guardó.",
            ) from exc
        try:
            data = response.json()
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="OSV devolvió JSON no válido; el escaneo no se guardó.",
            ) from exc
        if not isinstance(data, dict):
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="OSV devolvió una respuesta inesperada.",
            )
        return data
    raise HTTPException(
        status_code=status.HTTP_502_BAD_GATEWAY,
        detail="OSV no respondió correctamente; el escaneo no se guardó.",
    )


async def _collect_vulnerabilities(
    client: httpx.AsyncClient,
    packages: list[dict],
    batch_results: list[dict],
    ignored_list: set[str],
    detail_cache: dict[str, dict],
    detail_semaphore: asyncio.Semaphore,
) -> list[dict]:
    if len(packages) != len(batch_results):
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="OSV devolvió un número incompleto de resultados; escaneo marcado como fallido.",
        )

    vulnerability_ids: list[str] = []
    for result in batch_results:
        if not isinstance(result, dict):
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="OSV devolvió un resultado inesperado.",
            )
        for stub in result.get("vulns", []) or []:
            osv_id = stub.get("id") if isinstance(stub, dict) else None
            if isinstance(osv_id, str) and osv_id:
                vulnerability_ids.append(osv_id)

    missing_ids = list(dict.fromkeys(v_id for v_id in vulnerability_ids if v_id not in detail_cache))
    async def fetch_detail(osv_id: str) -> tuple[str, dict]:
        async with detail_semaphore:
            encoded_id = quote(osv_id, safe="-_.")
            data = await _request_osv_json(client, f"{OSV_BASE_URL}/vulns/{encoded_id}")
        return osv_id, data

    if missing_ids:
        fetched = await asyncio.gather(*(fetch_detail(v_id) for v_id in missing_ids))
        detail_cache.update(fetched)

    vulnerabilities: list[dict] = []
    for package, result in zip(packages, batch_results, strict=True):
        for stub in result.get("vulns", []) or []:
            osv_id = stub.get("id")
            if not isinstance(osv_id, str) or not osv_id:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="OSV devolvió una vulnerabilidad sin identificador.",
                )
            data = detail_cache[osv_id]
            aliases = data.get("aliases", [])
            cve_id = next(
                (alias for alias in aliases if isinstance(alias, str) and alias.startswith("CVE-")),
                osv_id,
            )
            severity, score, vector = extract_severity(data)
            vulnerabilities.append(
                {
                    "id": cve_id,
                    "osv_id": osv_id,
                    "package": package["name"],
                    "installed_version": package["version"],
                    "fixed_version": extract_fixed_version(data, package["name"]),
                    "severity": severity,
                    "cvss_score": score,
                    "cvss_vector": vector or "N/A",
                    "summary": data.get("summary") or "Vulnerabilidad detectada en componente.",
                    "details": data.get("details") or "Sin descripción adicional.",
                    "references": [
                        ref.get("url")
                        for ref in data.get("references", [])
                        if isinstance(ref, dict)
                        and isinstance(ref.get("url"), str)
                        and ref["url"].startswith(("https://", "http://"))
                    ][:4],
                    "ignored": cve_id in ignored_list or osv_id in ignored_list,
                }
            )
    return vulnerabilities


def _project_result_path(project: str) -> Path:
    if not PROJECT_NAME_RE.fullmatch(project) or project in {".", ".."}:
        raise HTTPException(status_code=400, detail="Nombre de proyecto inválido")
    return RESULTS_DIR / f"{project}_results.json"


def _public_project_result(data: dict) -> dict:
    public = dict(data)
    public.pop("manifest_results", None)
    public.pop("dependency_keys", None)
    return public


def _aggregate_project_results(
    project: str,
    manifest_results: dict[str, dict],
    ignored_list: set[str],
) -> dict:
    ordered_results = [manifest_results[name] for name in sorted(manifest_results)]
    filenames = [item["filename"] for item in ordered_results]
    ecosystems = list(dict.fromkeys(item["ecosystem"] for item in ordered_results))
    file_types = list(dict.fromkeys(item["file_type"] for item in ordered_results))
    vulnerabilities: list[dict] = []
    seen_vulnerabilities: set[tuple[str, str, str, str]] = set()
    dependency_keys: set[str] = set()
    warnings: list[str] = []

    for manifest in ordered_results:
        dependency_keys.update(manifest.get("dependency_keys", []))
        warnings.extend(manifest.get("scan_warnings", []))
        for original in manifest.get("vulnerabilities", []):
            vuln = dict(original)
            vuln["ignored"] = vuln.get("id") in ignored_list or vuln.get("osv_id") in ignored_list
            key = (
                manifest["ecosystem"].casefold(),
                str(vuln.get("osv_id", "")).casefold(),
                str(vuln.get("package", "")).casefold(),
                str(vuln.get("installed_version", "")).casefold(),
            )
            if key not in seen_vulnerabilities:
                seen_vulnerabilities.add(key)
                vuln["ecosystem"] = manifest["ecosystem"]
                vulnerabilities.append(vuln)

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "IGNORED": 0}
    for vuln in vulnerabilities:
        if vuln["ignored"]:
            counts["IGNORED"] += 1
        else:
            counts[vuln["severity"]] = counts.get(vuln["severity"], 0) + 1
    score, grade = calculate_score(counts)
    scanned_at_values = [item.get("scanned_at", "") for item in ordered_results]

    return {
        "project": project,
        "filename": ", ".join(filenames),
        "file_type": file_types[0] if len(file_types) == 1 else "multiple",
        "ecosystem": ecosystems[0] if len(ecosystems) == 1 else "Múltiple",
        "scanned_at": max(scanned_at_values, default=None),
        "manifest_count": len(ordered_results),
        "total_dependencies": len(dependency_keys),
        "security_score": score,
        "grade": grade,
        "counts": counts,
        "vulnerabilities": vulnerabilities,
        "scan_warnings": list(dict.fromkeys(warnings)),
        "manifest_results": manifest_results,
        "dependency_keys": sorted(dependency_keys),
    }


def _lifecycle_key(project: str, ecosystem: str, vuln: dict) -> str:
    advisory_id = str(vuln.get("id") or vuln.get("osv_id") or "").casefold()
    return json.dumps(
        [project.casefold(), ecosystem.casefold(), advisory_id, str(vuln.get("package") or "").casefold()],
        separators=(",", ":"),
    )


def _update_vulnerability_lifecycle(
    state: dict,
    project: str,
    current_vulnerabilities: list[dict],
    observed_at: str,
    *,
    removed_status: str = "resolved",
    reconcile: bool = True,
    close_keys: set[str] | None = None,
) -> None:
    records = state.get("vulnerability_lifecycle")
    if not isinstance(records, list):
        records = []
    state["vulnerability_lifecycle"] = records

    open_records: dict[str, dict] = {}
    for record in records:
        if (
            isinstance(record, dict)
            and record.get("project") == project
            and record.get("status") == "open"
            and isinstance(record.get("key"), str)
        ):
            open_records[record["key"]] = record

    current_by_key: dict[str, dict] = {}
    for vuln in current_vulnerabilities:
        if not isinstance(vuln, dict):
            continue
        if not (vuln.get("id") or vuln.get("osv_id")):
            continue
        ecosystem = str(vuln.get("ecosystem") or "")
        key = _lifecycle_key(project, ecosystem, vuln)
        current_by_key.setdefault(key, vuln)

    if close_keys is not None:
        records_to_close = {
            key: record for key, record in open_records.items() if key in close_keys
        }
    elif reconcile:
        records_to_close = {
            key: record for key, record in open_records.items() if key not in current_by_key
        }
    else:
        records_to_close = {}
    for record in records_to_close.values():
        record["status"] = removed_status
        record["closed_at"] = observed_at
        record["resolved_at"] = observed_at if removed_status == "resolved" else None

    for key, vuln in current_by_key.items():
        record = open_records.get(key)
        if record is None:
            record = {
                "key": key,
                "project": project,
                "id": vuln.get("id"),
                "osv_id": vuln.get("osv_id"),
                "package": vuln.get("package"),
                "ecosystem": vuln.get("ecosystem"),
                "first_seen": observed_at,
                "status": "open",
            }
            records.append(record)
        record["last_seen"] = observed_at
        record["severity"] = vuln.get("severity")
        record["fixed_version"] = vuln.get("fixed_version")

    # Keep open findings and the latest 5,000 closed lifecycle records.
    open_history = [item for item in records if isinstance(item, dict) and item.get("status") == "open"]
    closed_history = [item for item in records if isinstance(item, dict) and item.get("status") != "open"]
    state["vulnerability_lifecycle"] = closed_history[-5000:] + open_history


def _store_manifest_result(manifest_result: dict) -> dict:
    project = manifest_result["project"]
    result_path = _project_result_path(project)
    with RESULTS_LOCK:
        # Re-read ignores under the result lock so a scan cannot undo a concurrent toggle.
        ignored_list = _ignored_ids(load_system_state(), project)
        manifest_results: dict[str, dict] = {}
        if result_path.exists():
            try:
                previous = json.loads(result_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise RuntimeError(f"No se pudo leer el resultado previo de {project}") from exc
            saved_manifests = previous.get("manifest_results")
            if isinstance(saved_manifests, dict):
                manifest_results.update(saved_manifests)
            elif previous.get("filename"):
                # Migrate a legacy one-manifest result without discarding it.
                legacy = dict(previous)
                try:
                    legacy_dependency_count = min(
                        MAX_PACKAGES_PER_MANIFEST,
                        max(0, int(legacy.get("total_dependencies", 0))),
                    )
                except (TypeError, ValueError):
                    legacy_dependency_count = 0
                legacy["dependency_keys"] = [
                    f"legacy:{legacy['filename']}:{index}"
                    for index in range(legacy_dependency_count)
                ]
                legacy["scan_warnings"] = []
                manifest_results[legacy["filename"]] = legacy

        manifest_results[manifest_result["filename"]] = manifest_result
        aggregate = _aggregate_project_results(project, manifest_results, ignored_list)
        _atomic_write_json(result_path, aggregate)
        observed_at = manifest_result.get("scanned_at") or datetime.now(timezone.utc).isoformat()
        observed_vulnerabilities = [
            {**vuln, "ecosystem": manifest_result.get("ecosystem", "")}
            for vuln in manifest_result.get("vulnerabilities", [])
            if isinstance(vuln, dict)
        ]
        mutate_system_state(
            lambda state: _update_vulnerability_lifecycle(
                state,
                project,
                observed_vulnerabilities,
                observed_at,
                reconcile=False,
            )
        )
    return _public_project_result(aggregate)


def _prune_stale_manifest_results(project: str, active_filenames: set[str]) -> dict | None:
    result_path = _project_result_path(project)
    if not result_path.exists():
        return None
    with RESULTS_LOCK:
        ignored = _ignored_ids(load_system_state(), project)
        try:
            previous = json.loads(result_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"No se pudo leer el resultado de {project}") from exc
        manifest_results = previous.get("manifest_results")
        if not isinstance(manifest_results, dict):
            return _public_project_result(previous)
        current = {
            filename: result
            for filename, result in manifest_results.items()
            if filename in active_filenames
        }
        stale = {
            filename: result
            for filename, result in manifest_results.items()
            if filename not in active_filenames
        }
        if not current:
            result_path.unlink(missing_ok=True)
            observed_at = datetime.now(timezone.utc).isoformat()
            mutate_system_state(
                lambda state: _update_vulnerability_lifecycle(
                    state,
                    project,
                    [],
                    observed_at,
                    removed_status="not_monitored",
                )
            )
            return None
        aggregate = _aggregate_project_results(project, current, ignored)
        _atomic_write_json(result_path, aggregate)
        if stale:
            current_keys = {
                _lifecycle_key(project, str(vuln.get("ecosystem") or ""), vuln)
                for vuln in aggregate.get("vulnerabilities", [])
                if isinstance(vuln, dict) and (vuln.get("id") or vuln.get("osv_id"))
            }
            stale_keys = set()
            for manifest in stale.values():
                if not isinstance(manifest, dict):
                    continue
                ecosystem = str(manifest.get("ecosystem") or "")
                for vuln in manifest.get("vulnerabilities", []):
                    if isinstance(vuln, dict) and (vuln.get("id") or vuln.get("osv_id")):
                        stale_keys.add(_lifecycle_key(project, ecosystem, vuln))
            no_longer_monitored = stale_keys - current_keys
            if no_longer_monitored:
                observed_at = datetime.now(timezone.utc).isoformat()
                mutate_system_state(
                    lambda state: _update_vulnerability_lifecycle(
                        state,
                        project,
                        [],
                        observed_at,
                        removed_status="not_monitored",
                        reconcile=False,
                        close_keys=no_longer_monitored,
                    )
                )
        return _public_project_result(aggregate)


async def scan_single_manifest(
    filepath: Path,
    state: dict,
    client: httpx.AsyncClient | None = None,
    detail_cache: dict[str, dict] | None = None,
    detail_semaphore: asyncio.Semaphore | None = None,
) -> dict:
    project, file_type, ecosystem = identify_manifest(filepath.name)
    if filepath.stat().st_size > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"El manifiesto {filepath.name} supera el límite de 5 MiB.",
        )
    packages = parse_manifest(filepath.read_bytes(), file_type)
    if len(packages) > MAX_PACKAGES_PER_MANIFEST:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"El manifiesto supera el límite de {MAX_PACKAGES_PER_MANIFEST} dependencias.",
        )

    if client is None:
        timeout = httpx.Timeout(30.0, connect=10.0)
        async with httpx.AsyncClient(timeout=timeout) as owned_client:
            return await _scan_and_store_manifest(
                filepath,
                project,
                file_type,
                ecosystem,
                packages,
                state,
                owned_client,
                detail_cache if detail_cache is not None else {},
                detail_semaphore or asyncio.Semaphore(MAX_VULN_DETAIL_CONCURRENCY),
            )
    return await _scan_and_store_manifest(
        filepath,
        project,
        file_type,
        ecosystem,
        packages,
        state,
        client,
        detail_cache if detail_cache is not None else {},
        detail_semaphore or asyncio.Semaphore(MAX_VULN_DETAIL_CONCURRENCY),
    )


async def _scan_and_store_manifest(
    filepath: Path,
    project: str,
    file_type: str,
    ecosystem: str,
    packages: list[dict],
    state: dict,
    client: httpx.AsyncClient,
    detail_cache: dict[str, dict],
    detail_semaphore: asyncio.Semaphore,
) -> dict:
    queries = [
        {"package": {"name": package["name"], "ecosystem": ecosystem}, "version": package["version"]}
        for package in packages
    ]
    vulnerabilities: list[dict] = []
    ignored_list = _ignored_ids(state, project)

    for start in range(0, len(queries), OSV_QUERY_BATCH_SIZE):
        query_chunk = queries[start : start + OSV_QUERY_BATCH_SIZE]
        batch_data = await _request_osv_json(
            client,
            f"{OSV_BASE_URL}/querybatch",
            payload={"queries": query_chunk},
        )
        batch_results = batch_data.get("results")
        if not isinstance(batch_results, list) or len(batch_results) != len(query_chunk):
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="OSV devolvió una respuesta incompleta; el escaneo no se guardó.",
            )
        vulnerabilities.extend(
            await _collect_vulnerabilities(
                client,
                packages[start : start + len(query_chunk)],
                batch_results,
                ignored_list,
                detail_cache,
                detail_semaphore,
            )
        )

    warnings: list[str] = []
    if file_type == "composer.json":
        warnings.append("Manifiesto Composer sin bloqueo; usa composer.lock para confirmar versiones resueltas.")
    elif file_type == "pom.xml":
        warnings.append(
            "El POM analiza dependencias directas explícitas; no resuelve transitivas, herencia, perfiles ni BOMs."
        )
    elif file_type == "requirements.txt":
        warnings.append("Se analizan solo dependencias con versión exacta fijada mediante ==.")

    manifest_result = {
        "project": project,
        "filename": filepath.name,
        "file_type": file_type,
        "ecosystem": ecosystem,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "total_dependencies": len(packages),
        "dependency_keys": [
            f"{ecosystem.casefold()}:{package['name'].casefold()}@{package['version'].casefold()}"
            for package in packages
        ],
        "vulnerabilities": vulnerabilities,
        "scan_warnings": warnings,
    }
    return _store_manifest_result(manifest_result)


def _find_project_manifests(project: str) -> list[Path]:
    if not PROJECT_NAME_RE.fullmatch(project) or project in {".", ".."}:
        raise HTTPException(status_code=400, detail="Nombre de proyecto inválido")
    matches = []
    for path in MANIFESTS_DIR.iterdir():
        if not path.is_file():
            continue
        try:
            manifest_project, _, _ = identify_manifest(path.name)
        except ValueError:
            continue
        if manifest_project == project:
            matches.append(path)
    return sorted(matches)


@app.get("/api/dashboard", dependencies=[Depends(verify_token)])
async def get_dashboard():
    settings = load_settings()
    state = load_system_state()
    projects = []
    with RESULTS_LOCK:
        for result_file in sorted(RESULTS_DIR.glob("*_results.json")):
            with result_file.open("r", encoding="utf-8") as stream:
                project_result = _public_project_result(json.load(stream))
            project_name = project_result.get("project")
            if isinstance(project_name, str):
                _recalculate_result(project_result, _ignored_ids(state, project_name))
            projects.append(project_result)
    public_settings = {
        key: settings[key]
        for key in (
            "cron_schedule",
            "scan_history_size",
            "relative_url_root",
            "scan_batch_size",
        )
        if key in settings
    }
    public_settings.update({
        key: state[key]
        for key in ("last_global_scan", "scan_history")
        if key in state
    })
    return {"settings": public_settings, "projects": projects}


def _read_saved_project_result(project: str) -> dict | None:
    result_path = _project_result_path(project)
    with RESULTS_LOCK:
        if not result_path.exists():
            return None
        try:
            result = json.loads(result_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("No se pudo leer el estado de seguimiento de %s: %s", project, exc)
            return None
    return result if isinstance(result, dict) else None


@app.post("/api/scan/all", dependencies=[Depends(verify_token)])
async def scan_all_projects():
    settings = load_settings()
    state = load_system_state()
    try:
        configured_batch_size = int(settings.get("scan_batch_size", 10))
    except (TypeError, ValueError):
        configured_batch_size = 10
    batch_size = min(MAX_PROJECT_CONCURRENCY, max(1, configured_batch_size))

    project_paths: dict[str, list[Path]] = defaultdict(list)
    errors: list[dict[str, str]] = []
    for path in sorted(MANIFESTS_DIR.iterdir()):
        if not path.is_file() or "_" not in path.name:
            continue
        try:
            project, _, _ = identify_manifest(path.name)
            project_paths[project].append(path)
        except ValueError as exc:
            errors.append({"manifest": path.name, "error": str(exc)})

    projects = list(project_paths.items())
    scanned_results: list[dict] = []
    detail_cache: dict[str, dict] = {}
    timeout = httpx.Timeout(30.0, connect=10.0)

    async with httpx.AsyncClient(timeout=timeout) as client:
        detail_semaphore = asyncio.Semaphore(MAX_VULN_DETAIL_CONCURRENCY)
        for start in range(0, len(projects), batch_size):
            project_batch = projects[start : start + batch_size]

            async def scan_project_group(project: str, paths: list[Path]):
                result = None
                group_errors: list[dict[str, str]] = []
                for manifest_path in paths:
                    try:
                        result = await scan_single_manifest(
                            manifest_path,
                            state,
                            client=client,
                            detail_cache=detail_cache,
                            detail_semaphore=detail_semaphore,
                        )
                    except Exception as exc:
                        logger.exception("Error escaneando %s", manifest_path.name)
                        group_errors.append({"manifest": manifest_path.name, "error": _error_message(exc)})
                try:
                    active_filenames = {path.name for path in paths}
                    pruned_result = _prune_stale_manifest_results(
                        project,
                        active_filenames,
                    )
                    if result is not None:
                        result = pruned_result or result
                except Exception as exc:
                    logger.exception("Error actualizando resultados de %s", project)
                    group_errors.append({"manifest": project, "error": _error_message(exc)})
                if not group_errors:
                    with RESULTS_LOCK:
                        latest_result = _read_saved_project_result(project)
                        latest_vulnerabilities = latest_result.get("vulnerabilities", []) if latest_result else []
                        if not isinstance(latest_vulnerabilities, list):
                            latest_vulnerabilities = []
                        observed_at = (
                            latest_result.get("scanned_at")
                            if latest_result and isinstance(latest_result.get("scanned_at"), str)
                            else datetime.now(timezone.utc).isoformat()
                        )
                        mutate_system_state(
                            lambda current: _update_vulnerability_lifecycle(
                                current,
                                project,
                                latest_vulnerabilities,
                                observed_at,
                            )
                        )
                return project, result, group_errors

            outcomes = await asyncio.gather(
                *(scan_project_group(project, paths) for project, paths in project_batch)
            )
            for _, result, group_errors in outcomes:
                if result is not None:
                    scanned_results.append(result)
                errors.extend(group_errors)

    now = datetime.now(timezone.utc).isoformat()
    current_results, _ = _current_project_results()
    dashboard_totals = {
        severity: sum(
            int(result.get("counts", {}).get(severity, 0) or 0)
            for result in current_results
        )
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    }
    historical_score = (
        round(sum(int(result.get("security_score", 100)) for result in current_results) / len(current_results))
        if current_results else 100
    )

    def update_history(current: dict) -> None:
        current["last_global_scan"] = now
        history = current.get("scan_history", [])
        history.append({"date": now, **dashboard_totals, "security_score": historical_score, "status": "partial" if errors else "ok", "errors": len(errors)})
        try:
            history_size = max(1, int(settings.get("scan_history_size", 15)))
        except (TypeError, ValueError):
            history_size = 15
        current["scan_history"] = history[-history_size:]

    mutate_system_state(update_history)
    return {
        "status": "partial" if errors else "ok",
        "scanned_projects": len(scanned_results),
        "failed_manifests": errors,
        "last_global_scan": now,
    }


@app.post(
    "/api/scan/{project}",
    dependencies=[Depends(verify_token)],
    responses={
        400: {"description": "Nombre de proyecto inválido"},
        404: {"description": "Manifiesto de proyecto no encontrado"},
    },
)
async def scan_project_endpoint(project: str):
    matches = _find_project_manifests(project)
    if not matches:
        raise HTTPException(status_code=404, detail="Manifiesto de proyecto no encontrado")
    state = load_system_state()
    detail_cache: dict[str, dict] = {}
    result = None
    timeout = httpx.Timeout(30.0, connect=10.0)
    async with httpx.AsyncClient(timeout=timeout) as client:
        detail_semaphore = asyncio.Semaphore(MAX_VULN_DETAIL_CONCURRENCY)
        for manifest in matches:
            result = await scan_single_manifest(
                manifest, state, client, detail_cache, detail_semaphore
            )
    result = _prune_stale_manifest_results(
        project,
        {path.name for path in matches},
    ) or result
    with RESULTS_LOCK:
        latest_result = _read_saved_project_result(project)
        latest_vulnerabilities = latest_result.get("vulnerabilities", []) if latest_result else []
        if not isinstance(latest_vulnerabilities, list):
            latest_vulnerabilities = []
        observed_at = (
            latest_result.get("scanned_at")
            if latest_result and isinstance(latest_result.get("scanned_at"), str)
            else datetime.now(timezone.utc).isoformat()
        )
        mutate_system_state(
            lambda current: _update_vulnerability_lifecycle(
                current,
                project,
                latest_vulnerabilities,
                observed_at,
            )
        )
    return result


@app.post(
    "/api/upload",
    dependencies=[Depends(verify_any_token)],
    responses={400: {"description": "Tipo de archivo no válido o nombre de proyecto inválido"}},
)
async def upload_manifest(
    request: Request,
    file: UploadFile = File(...),
    project_name: str = Form(""),
):
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            request_size = int(content_length)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Content-Length no válido") from exc
        if request_size > MAX_UPLOAD_REQUEST_BYTES:
            raise HTTPException(status_code=413, detail="La carga supera el límite de 5 MiB")

    original_name = os.path.basename(file.filename or "")
    direct_type = original_name.rsplit("_", 1)[-1].lower() if "_" in original_name else ""
    if direct_type in ECOSYSTEM_MAP:
        project = original_name.rsplit("_", 1)[0]
        if not PROJECT_NAME_RE.fullmatch(project) or project in {".", ".."}:
            raise HTTPException(status_code=400, detail="Nombre de proyecto inválido")
        file_type = direct_type
    else:
        file_type = original_name.lower()
        if file_type not in ECOSYSTEM_MAP:
            raise HTTPException(
                status_code=400,
                detail=f"Tipo de archivo no válido. Soportados: {', '.join(ECOSYSTEM_MAP.keys())}",
            )
        project = re.sub(r"[^a-zA-Z0-9_.-]", "-", project_name.strip()).strip("-._")
        if not PROJECT_NAME_RE.fullmatch(project) or project in {".", ".."}:
            raise HTTPException(status_code=400, detail="Debe indicar un nombre de proyecto válido.")

    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES or (file.size is not None and file.size > MAX_UPLOAD_BYTES):
        raise HTTPException(status_code=413, detail="La carga supera el límite de 5 MiB")
    try:
        packages = parse_manifest(content, file_type)
    except (ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if len(packages) > MAX_PACKAGES_PER_MANIFEST:
        raise HTTPException(
            status_code=413,
            detail=f"El manifiesto supera el límite de {MAX_PACKAGES_PER_MANIFEST} dependencias.",
        )

    target_path = MANIFESTS_DIR / f"{project}_{file_type}"
    _atomic_write_bytes(target_path, content)
    timeout = httpx.Timeout(30.0, connect=10.0)
    async with httpx.AsyncClient(timeout=timeout) as client:
        detail_semaphore = asyncio.Semaphore(MAX_VULN_DETAIL_CONCURRENCY)
        result = await scan_single_manifest(
            target_path,
            load_system_state(),
            client=client,
            detail_cache={},
            detail_semaphore=detail_semaphore,
        )
    return _prune_stale_manifest_results(
        project,
        {path.name for path in _find_project_manifests(project)},
    ) or result


@app.delete(
    "/api/projects/{project}",
    dependencies=[Depends(verify_token)],
    responses={404: {"description": "Proyecto no encontrado"}},
)
async def delete_project(project: str):
    with RESULTS_LOCK:
        manifests = _find_project_manifests(project)
        result_path = _project_result_path(project)
        deleted = False
        for manifest in manifests:
            manifest.unlink(missing_ok=True)
            deleted = True
        if result_path.exists():
            result_path.unlink()
            deleted = True
        if not deleted:
            raise HTTPException(status_code=404, detail="Proyecto no encontrado")

        def remove_project_ignores(state: dict) -> None:
            ignored_by_project = state.get("ignored_vulnerabilities_by_project", {})
            ignored_by_project.pop(project, None)
            state["ignored_vulnerabilities_by_project"] = ignored_by_project
            _update_vulnerability_lifecycle(
                state,
                project,
                [],
                datetime.now(timezone.utc).isoformat(),
                removed_status="not_monitored",
            )

        mutate_system_state(remove_project_ignores)
    return {"status": "deleted", "project": project}


def _recalculate_result(data: dict, ignored: set[str]) -> dict:
    project_ecosystem = data.get("ecosystem", "")
    for vuln in data.get("vulnerabilities", []):
        if not isinstance(vuln, dict):
            continue
        vuln.setdefault("ecosystem", project_ecosystem)
        vuln["ignored"] = vuln.get("id") in ignored or vuln.get("osv_id") in ignored
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "IGNORED": 0}
    for vuln in data.get("vulnerabilities", []):
        if not isinstance(vuln, dict):
            continue
        if vuln["ignored"]:
            counts["IGNORED"] += 1
        else:
            counts[vuln["severity"]] = counts.get(vuln["severity"], 0) + 1
    data["counts"] = counts
    data["security_score"], data["grade"] = calculate_score(counts)
    return data


SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _current_project_results() -> tuple[list[dict], dict]:
    state = load_system_state()
    results: list[dict] = []
    with RESULTS_LOCK:
        for result_file in sorted(RESULTS_DIR.glob("*_results.json")):
            try:
                result = json.loads(result_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning("No se pudo leer el resultado %s: %s", result_file.name, exc)
                continue
            if not isinstance(result, dict):
                logger.warning("Se omite %s porque el resultado no es un objeto", result_file.name)
                continue
            project = result.get("project")
            if not isinstance(project, str) or not project:
                project = result_file.name[: -len("_results.json")]
                result["project"] = project
            results.append(_recalculate_result(result, _ignored_ids(state, project)))
    return results, state


def _project_summary(result: dict) -> dict:
    counts = result.get("counts", {})
    if not isinstance(counts, dict):
        counts = {}
    normalized_counts = {
        severity: int(counts.get(severity, 0) or 0)
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "IGNORED")
    }
    return {
        "project": result.get("project", ""),
        "filename": result.get("filename", ""),
        "ecosystem": result.get("ecosystem", "Desconocido"),
        "file_type": result.get("file_type", ""),
        "total_dependencies": result.get("total_dependencies", 0),
        "security_score": result.get("security_score", 100),
        "grade": result.get("grade", "A"),
        "counts": normalized_counts,
        "scanned_at": result.get("scanned_at"),
        "scan_warnings": result.get("scan_warnings", []),
    }


def _project_ecosystems(result: dict) -> set[str]:
    manifests = result.get("manifest_results")
    ecosystems = {
        str(item.get("ecosystem"))
        for item in manifests.values()
        if isinstance(item, dict) and item.get("ecosystem")
    } if isinstance(manifests, dict) else set()
    if not ecosystems and result.get("ecosystem"):
        ecosystems.add(str(result["ecosystem"]))
    return ecosystems


@app.get("/api/overview", dependencies=[Depends(verify_token)])
async def get_overview():
    results, state = _current_project_results()
    summaries = [_project_summary(result) for result in results]
    project_scores = [int(item["security_score"]) for item in summaries]
    global_score = round(sum(project_scores) / len(project_scores)) if project_scores else 100
    global_grade = "A" if global_score >= 90 else "B" if global_score >= 80 else "C" if global_score >= 65 else "D" if global_score >= 50 else "F"

    unique_advisories: dict[str, str] = {}
    fixed_known = 0
    fix_not_declared = 0
    ignored_exposures = 0
    ignored_advisory_ids: set[str] = set()
    ecosystem_projects: dict[str, set[str]] = defaultdict(set)
    for result in results:
        project = result.get("project", "")
        ignored_exposures += int(result.get("counts", {}).get("IGNORED", 0) or 0)
        for ecosystem in _project_ecosystems(result):
            ecosystem_projects[ecosystem].add(project)

        for vuln in result.get("vulnerabilities", []):
            if not isinstance(vuln, dict):
                continue
            advisory_id = str(vuln.get("id") or vuln.get("osv_id") or "").casefold()
            if vuln.get("ignored"):
                if advisory_id:
                    ignored_advisory_ids.add(advisory_id)
                continue
            if advisory_id:
                severity = str(vuln.get("severity", "HIGH")).upper()
                previous = unique_advisories.get(advisory_id)
                if previous is None or SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(previous, 0):
                    unique_advisories[advisory_id] = severity
            fixed_version = str(vuln.get("fixed_version") or "").strip()
            if fixed_version and fixed_version.casefold() != "revisar advisory":
                fixed_known += 1
            else:
                fix_not_declared += 1

    unique_counts = {severity: 0 for severity in SEVERITY_ORDER}
    for severity in unique_advisories.values():
        if severity in unique_counts:
            unique_counts[severity] += 1

    risk_rank = lambda item: (
        int(item.get("security_score", 100)),
        -int(item.get("counts", {}).get("CRITICAL", 0)),
        -int(item.get("counts", {}).get("HIGH", 0)),
        str(item.get("project", "")).casefold(),
    )
    top_projects = sorted(
        (item for item in summaries if sum(item["counts"][severity] for severity in SEVERITY_ORDER)),
        key=risk_rank,
    )[:5]

    history = []
    for entry in state.get("scan_history", []):
        if not isinstance(entry, dict):
            continue
        snapshot = dict(entry)
        try:
            snapshot["security_score"] = int(entry["security_score"])
        except (KeyError, TypeError, ValueError):
            # Older history has severity totals but not the project-average score.
            snapshot["security_score"] = None
        history.append(snapshot)

    settings = load_settings()
    return {
        "settings": {
            key: settings[key]
            for key in ("cron_schedule", "scan_history_size", "relative_url_root", "scan_batch_size")
            if key in settings
        } | {
            "last_global_scan": state.get("last_global_scan"),
            "scan_history": history,
        },
        "summary": {
            "project_count": len(summaries),
            "projects_with_vulnerabilities": sum(
                1 for item in summaries if sum(item["counts"][severity] for severity in SEVERITY_ORDER)
            ),
            "total_dependencies": sum(int(item.get("total_dependencies", 0) or 0) for item in summaries),
            "security_score": global_score,
            "grade": global_grade,
            "unique_active_vulnerabilities": sum(unique_counts.values()),
            "active_exposures": sum(
                int(item["counts"][severity]) for item in summaries for severity in SEVERITY_ORDER
            ),
            "counts": unique_counts,
            "ignored_exposures": ignored_exposures,
            "ignored_advisories": len(ignored_advisory_ids),
            "quick_wins": {"fixed_version_declared": fixed_known, "fix_not_declared": fix_not_declared},
        },
        "top_projects": top_projects,
        "ecosystem_distribution": [
            {"ecosystem": ecosystem, "projects": len(project_names)}
            for ecosystem, project_names in sorted(ecosystem_projects.items())
        ],
    }


@app.get("/api/projects", dependencies=[Depends(verify_token)])
async def list_projects(
    page: int = 1,
    page_size: int = 25,
    search: str = "",
    ecosystem: str = "",
    severity: str = "",
):
    page = max(1, page)
    page_size = min(100, max(1, page_size))
    severity = severity.upper().strip()
    if severity and severity not in {*SEVERITY_ORDER, "IGNORED"}:
        raise HTTPException(status_code=400, detail="Filtro de severidad inválido")
    results, _ = _current_project_results()
    projects = [_project_summary(result) for result in results]
    ecosystems_by_project: dict[str, set[str]] = {}
    for result in results:
        project = str(result.get("project", ""))
        ecosystems_by_project[project] = _project_ecosystems(result)
    ecosystems = sorted({ecosystem for values in ecosystems_by_project.values() for ecosystem in values})
    query = search.strip().casefold()
    ecosystem_filter = ecosystem.strip().casefold()
    filtered = [
        item for item in projects
        if (not query or query in str(item.get("project", "")).casefold() or query in str(item.get("filename", "")).casefold())
        and (not ecosystem_filter or ecosystem_filter in {value.casefold() for value in ecosystems_by_project.get(str(item.get("project", "")), set())})
        and (not severity or int(item["counts"].get(severity, 0)) > 0)
    ]
    filtered.sort(key=lambda item: (int(item.get("security_score", 100)), str(item.get("project", "")).casefold()))
    start = (page - 1) * page_size
    return {
        "page": page,
        "page_size": page_size,
        "total": len(filtered),
        "ecosystems": ecosystems,
        "projects": filtered[start : start + page_size],
    }


@app.get("/api/projects/{project}", dependencies=[Depends(verify_token)])
async def get_project(project: str):
    result_path = _project_result_path(project)
    with RESULTS_LOCK:
        if not result_path.exists():
            raise HTTPException(status_code=404, detail="Proyecto no encontrado")
        try:
            result = json.loads(result_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=500, detail="No se pudo leer el resultado del proyecto") from exc
    state = load_system_state()
    return _public_project_result(_recalculate_result(result, _ignored_ids(state, project)))


@app.get("/api/intelligence", dependencies=[Depends(verify_token)])
async def get_intelligence():
    results, state = _current_project_results()
    advisory_groups: dict[str, dict] = {}
    dependency_groups: dict[tuple[str, str], dict] = {}
    open_lifecycle = {
        record.get("key"): record
        for record in state.get("vulnerability_lifecycle", [])
        if isinstance(record, dict) and record.get("status") == "open" and isinstance(record.get("key"), str)
    }
    aging_findings = []
    aging_buckets = {"0_7_days": 0, "8_30_days": 0, "31_90_days": 0, "over_90_days": 0, "not_yet_tracked": 0}
    now = datetime.now(timezone.utc)

    for result in results:
        project = str(result.get("project", ""))
        for vuln in result.get("vulnerabilities", []):
            if not isinstance(vuln, dict) or vuln.get("ignored"):
                continue
            advisory_id = str(vuln.get("id") or vuln.get("osv_id") or "N/D")
            severity = str(vuln.get("severity", "HIGH")).upper()
            ecosystem = str(vuln.get("ecosystem") or result.get("ecosystem") or "Desconocido")
            package = str(vuln.get("package") or "Desconocido")
            advisory_key = advisory_id.casefold()
            advisory = advisory_groups.setdefault(advisory_key, {
                "id": advisory_id,
                "osv_id": vuln.get("osv_id"),
                "summary": vuln.get("summary", ""),
                "severity": severity,
                "project_names": set(),
                "packages": set(),
                "occurrences": 0,
                "fixed_version_declared": False,
            })
            if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(advisory["severity"], 0):
                advisory["severity"] = severity
            advisory["project_names"].add(project)
            advisory["packages"].add(package)
            advisory["occurrences"] += 1
            if vuln.get("fixed_version") and str(vuln["fixed_version"]).casefold() != "revisar advisory":
                advisory["fixed_version_declared"] = True

            dependency_key = (ecosystem.casefold(), package.casefold())
            dependency = dependency_groups.setdefault(dependency_key, {
                "ecosystem": ecosystem,
                "package": package,
                "project_names": set(),
                "occurrences": 0,
                "vulnerabilities": set(),
                "severity": severity,
            })
            dependency["project_names"].add(project)
            dependency["occurrences"] += 1
            dependency["vulnerabilities"].add(advisory_id)
            if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(dependency["severity"], 0):
                dependency["severity"] = severity

            lifecycle_key = _lifecycle_key(project, ecosystem, vuln)
            lifecycle = open_lifecycle.get(lifecycle_key)
            first_seen = lifecycle.get("first_seen") if lifecycle else None
            age_days = None
            if isinstance(first_seen, str):
                try:
                    seen_at = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
                    age_days = max(0, (now - seen_at).days)
                except (TypeError, ValueError):
                    first_seen = None
            if age_days is None:
                aging_buckets["not_yet_tracked"] += 1
            elif age_days <= 7:
                aging_buckets["0_7_days"] += 1
            elif age_days <= 30:
                aging_buckets["8_30_days"] += 1
            elif age_days <= 90:
                aging_buckets["31_90_days"] += 1
            else:
                aging_buckets["over_90_days"] += 1
            aging_findings.append({
                "project": project,
                "id": vuln.get("id") or vuln.get("osv_id"),
                "osv_id": vuln.get("osv_id"),
                "package": package,
                "ecosystem": ecosystem,
                "severity": severity,
                "first_seen": first_seen,
                "age_days": age_days,
                "fixed_version": vuln.get("fixed_version"),
            })

    top_advisories = [
        {**item, "project_names": sorted(item["project_names"]), "project_count": len(item["project_names"]), "packages": sorted(item["packages"])}
        for item in advisory_groups.values()
    ]
    top_advisories.sort(key=lambda item: (-item["project_count"], -SEVERITY_ORDER.get(item["severity"], 0), -item["occurrences"], item["id"]))
    top_dependencies = [
        {
            **{key: value for key, value in item.items() if key != "vulnerabilities"},
            "project_names": sorted(item["project_names"]),
            "project_count": len(item["project_names"]),
            "vulnerability_count": len(item["vulnerabilities"]),
        }
        for item in dependency_groups.values()
    ]
    top_dependencies.sort(key=lambda item: (-item["project_count"], -SEVERITY_ORDER.get(item["severity"], 0), -item["occurrences"], item["package"].casefold()))
    aging_findings.sort(key=lambda item: (item["age_days"] is None, -(item["age_days"] or 0), item["project"], item["package"]))

    mttr_days = []
    for record in state.get("vulnerability_lifecycle", []):
        if not isinstance(record, dict) or record.get("status") != "resolved":
            continue
        try:
            first_seen = datetime.fromisoformat(str(record.get("first_seen", "")).replace("Z", "+00:00"))
            resolved_at = datetime.fromisoformat(str(record.get("resolved_at", "")).replace("Z", "+00:00"))
            mttr_days.append(max(0.0, (resolved_at - first_seen).total_seconds() / 86400))
        except (TypeError, ValueError):
            continue

    return {
        "top_advisories": top_advisories[:10],
        "top_dependencies": top_dependencies[:10],
        "aging": {
            "buckets": aging_buckets,
            "findings": aging_findings[:20],
            "tracked_count": len(aging_findings) - aging_buckets["not_yet_tracked"],
            "untracked_count": aging_buckets["not_yet_tracked"],
        },
        "mttr": {
            "mean_days": round(statistics.mean(mttr_days), 1) if mttr_days else None,
            "median_days": round(statistics.median(mttr_days), 1) if mttr_days else None,
            "resolved_sample_size": len(mttr_days),
            "scope": "observaciones registradas desde la activación del seguimiento",
        },
    }


@app.get("/api/ignored-vulnerabilities", dependencies=[Depends(verify_token)])
async def list_ignored_vulnerabilities():
    results, _ = _current_project_results()
    grouped: dict[str, dict] = {}
    for result in results:
        project = str(result.get("project", ""))
        for vuln in result.get("vulnerabilities", []):
            if not isinstance(vuln, dict) or not vuln.get("ignored"):
                continue
            ecosystem = str(vuln.get("ecosystem") or result.get("ecosystem") or "").casefold()
            advisory_id = str(vuln.get("osv_id") or vuln.get("id") or "").casefold()
            package = str(vuln.get("package") or "").casefold()
            group_key = json.dumps([ecosystem, advisory_id, package], separators=(",", ":"))
            group = grouped.setdefault(group_key, {
                **vuln,
                "groupKey": group_key,
                "project_names": set(),
                "installed_versions": set(),
                "fixed_versions": set(),
            })
            group["project_names"].add(project)
            if vuln.get("installed_version"):
                group["installed_versions"].add(str(vuln["installed_version"]))
            if vuln.get("fixed_version"):
                group["fixed_versions"].add(str(vuln["fixed_version"]))

    output = []
    for group in grouped.values():
        project_names = sorted(group.pop("project_names"))
        installed_versions = sorted(group.pop("installed_versions"), key=lambda value: (value.casefold(), value))
        fixed_versions = sorted(group.pop("fixed_versions"))
        group.update({
            "projectNames": project_names,
            "projectCount": len(project_names),
            "installedVersions": installed_versions,
            "fixedVersions": fixed_versions,
            "installedVersionLabel": f"v{installed_versions[0]}" if len(installed_versions) == 1 else f"{len(installed_versions)} versiones" if installed_versions else "Versión N/D",
            "fixedVersionLabel": ", ".join(fixed_versions) or group.get("fixed_version") or "Revisar advisory",
        })
        output.append(group)
    return sorted(output, key=lambda item: (str(item.get("package", "")).casefold(), str(item.get("id") or item.get("osv_id") or "").casefold()))


@app.get("/api/vulnerabilities", dependencies=[Depends(verify_token)])
def list_vulnerabilities(
    page: int = 1,
    page_size: int = 25,
    search: str = "",
    severity: str = "",
    status_filter: str = "all",
    fix_status: str = "all",
    ecosystem: str = "",
):
    page = max(1, page)
    page_size = min(100, max(1, page_size))
    severity = severity.upper().strip()
    status_filter = status_filter.casefold().strip() or "all"
    fix_status = fix_status.casefold().strip() or "all"
    if severity and severity not in {*SEVERITY_ORDER, "ALL"}:
        raise HTTPException(status_code=400, detail="Filtro de severidad inválido")
    if status_filter not in {"all", "active", "ignored"}:
        raise HTTPException(status_code=400, detail="Filtro de estado inválido")
    if fix_status not in {"all", "available", "not_declared"}:
        raise HTTPException(status_code=400, detail="Filtro de corrección inválido")

    results, _ = _current_project_results()
    grouped: dict[str, dict] = {}
    ecosystems: set[str] = set()
    for result in results:
        project = str(result.get("project", ""))
        for vuln in result.get("vulnerabilities", []):
            if not isinstance(vuln, dict):
                continue
            ecosystem_name = str(vuln.get("ecosystem") or result.get("ecosystem") or "Desconocido")
            ecosystem_key = ecosystem_name.casefold()
            advisory_id = str(vuln.get("id") or vuln.get("osv_id") or "N/D")
            package = str(vuln.get("package") or "Desconocido")
            group_key = json.dumps(
                [ecosystem_key, advisory_id.casefold(), package.casefold()],
                separators=(",", ":"),
            )
            group = grouped.setdefault(group_key, {
                "group_key": group_key,
                "id": vuln.get("id") or vuln.get("osv_id"),
                "osv_id": vuln.get("osv_id"),
                "package": package,
                "ecosystem": ecosystem_name,
                "summary": vuln.get("summary", ""),
                "details": vuln.get("details", ""),
                "references": vuln.get("references", []),
                "cvss_score": vuln.get("cvss_score"),
                "cvss_vector": vuln.get("cvss_vector", "N/A"),
                "severity": str(vuln.get("severity", "HIGH")).upper(),
                "active_project_names": set(),
                "ignored_project_names": set(),
                "installed_versions": set(),
                "fixed_versions": set(),
                "fixed_version_declared": False,
                "aliases": set(),
            })
            ecosystems.add(ecosystem_name)
            current_severity = str(vuln.get("severity", "HIGH")).upper()
            if SEVERITY_ORDER.get(current_severity, 0) > SEVERITY_ORDER.get(group["severity"], 0):
                group["severity"] = current_severity
            score = vuln.get("cvss_score")
            if isinstance(score, (int, float)) and not isinstance(score, bool):
                current_score = group.get("cvss_score")
                if not isinstance(current_score, (int, float)) or score > current_score:
                    group["cvss_score"] = score
                    group["cvss_vector"] = vuln.get("cvss_vector", "N/A")
            if vuln.get("ignored"):
                group["ignored_project_names"].add(project)
            else:
                group["active_project_names"].add(project)
            if vuln.get("installed_version"):
                group["installed_versions"].add(str(vuln["installed_version"]))
            fixed_version = str(vuln.get("fixed_version") or "").strip()
            if fixed_version:
                group["fixed_versions"].add(fixed_version)
            if fixed_version and fixed_version.casefold() != "revisar advisory":
                group["fixed_version_declared"] = True
            for alias in (vuln.get("id"), vuln.get("osv_id")):
                if isinstance(alias, str) and alias:
                    group["aliases"].add(alias)

    records = []
    for group in grouped.values():
        active_projects = sorted(group.pop("active_project_names"))
        ignored_projects = sorted(group.pop("ignored_project_names"))
        installed_versions = sorted(group.pop("installed_versions"), key=lambda value: (value.casefold(), value))
        fixed_versions = sorted(group.pop("fixed_versions"))
        aliases = sorted(group.pop("aliases"))
        has_active = bool(active_projects)
        has_ignored = bool(ignored_projects)
        item_status = "mixed" if has_active and has_ignored else "active" if has_active else "ignored"
        group.update({
            "active_project_names": active_projects,
            "ignored_project_names": ignored_projects,
            "project_names": sorted(set(active_projects) | set(ignored_projects)),
            "active_project_count": len(active_projects),
            "ignored_project_count": len(ignored_projects),
            "project_count": len(set(active_projects) | set(ignored_projects)),
            "installed_versions": installed_versions,
            "fixed_versions": [value for value in fixed_versions if value.casefold() != "revisar advisory"],
            "fixed_version_label": ", ".join(value for value in fixed_versions if value.casefold() != "revisar advisory") or "Sin versión corregida declarada",
            "aliases": aliases,
            "status": item_status,
            "fix_status": "available" if group["fixed_version_declared"] else "not_declared",
        })
        records.append(group)

    query = search.strip().casefold()
    ecosystem_filter = ecosystem.strip().casefold()
    filtered = [
        item for item in records
        if (not query or any(query in str(value).casefold() for value in (
            item.get("package"),
            item.get("id"),
            item.get("osv_id"),
            item.get("summary"),
            item.get("details"),
            item.get("ecosystem"),
            *item["project_names"],
            *item["aliases"],
            *item["installed_versions"],
            *item["fixed_versions"],
        )))
        and (not severity or severity == "ALL" or item["severity"] == severity)
        and (not ecosystem_filter or item["ecosystem"].casefold() == ecosystem_filter)
        and (status_filter == "all" or (status_filter == "active" and item["active_project_count"] > 0) or (status_filter == "ignored" and item["ignored_project_count"] > 0))
        and (fix_status == "all" or item["fix_status"] == fix_status)
    ]
    filtered.sort(key=lambda item: (
        -item["project_count"],
        -SEVERITY_ORDER.get(item["severity"], 0),
        -item["active_project_count"],
        str(item["package"]).casefold(),
        str(item["id"]).casefold(),
    ))
    start = (page - 1) * page_size
    return {
        "page": page,
        "page_size": page_size,
        "total": len(filtered),
        "ecosystems": sorted(ecosystems),
        "vulnerabilities": filtered[start : start + page_size],
    }


@app.post(
    "/api/projects/{project}/ignore",
    dependencies=[Depends(verify_token)],
    responses={404: {"description": "Resultado o vulnerabilidad no encontrado"}},
)
async def toggle_ignore_vulnerability(project: str, vuln_id: str = Form(...)):
    result_path = _project_result_path(project)
    if not result_path.exists():
        raise HTTPException(status_code=404, detail="Resultado no encontrado")

    with RESULTS_LOCK:
        data = json.loads(result_path.read_text(encoding="utf-8"))
        matches = [
            vuln
            for vuln in data.get("vulnerabilities", [])
            if vuln.get("id") == vuln_id or vuln.get("osv_id") == vuln_id
        ]
        if not matches:
            raise HTTPException(status_code=404, detail="Vulnerabilidad no encontrada")
        aliases = {
            identifier
            for vuln in matches
            for identifier in (vuln.get("id"), vuln.get("osv_id"))
            if isinstance(identifier, str) and identifier
        }

        updated_result: dict | None = None

        def update_ignored(state: dict) -> None:
            nonlocal updated_result
            ignored_by_project = state.setdefault("ignored_vulnerabilities_by_project", {})
            ignored = _ignored_ids(state, project)
            if aliases & ignored:
                ignored.difference_update(aliases)
            else:
                ignored.update(aliases)
            if ignored:
                ignored_by_project[project] = sorted(ignored)
            else:
                ignored_by_project.pop(project, None)
            state["ignored_vulnerabilities_by_project"] = ignored_by_project

            manifest_results = data.get("manifest_results")
            if isinstance(manifest_results, dict):
                for manifest in manifest_results.values():
                    _recalculate_result(manifest, ignored)
                saved = _aggregate_project_results(project, manifest_results, ignored)
            else:
                saved = _recalculate_result(data, ignored)
            _atomic_write_json(result_path, saved)
            updated_result = _public_project_result(saved)

        mutate_system_state(update_ignored)
    if updated_result is None:
        raise HTTPException(status_code=404, detail="Resultado no encontrado")
    return updated_result


@app.post(
    "/api/ignored-vulnerabilities/restore",
    dependencies=[Depends(verify_token)],
    responses={404: {"description": "Vulnerabilidad ignorada no encontrada"}},
)
async def restore_ignored_vulnerability_globally(vuln_id: str = Form(...)):
    """Remove one vulnerability's ignore from every project where it is set."""
    with RESULTS_LOCK:
        saved_projects: list[tuple[Path, dict, str]] = []
        aliases = {vuln_id}
        for result_path in sorted(RESULTS_DIR.glob("*_results.json")):
            saved = json.loads(result_path.read_text(encoding="utf-8"))
            project = saved.get("project")
            if not isinstance(project, str) or not project:
                project = result_path.name[: -len("_results.json")]
            for vuln in saved.get("vulnerabilities", []):
                if vuln.get("id") == vuln_id or vuln.get("osv_id") == vuln_id:
                    aliases.update(
                        identifier
                        for identifier in (vuln.get("id"), vuln.get("osv_id"))
                        if isinstance(identifier, str) and identifier
                    )
            saved_projects.append((result_path, saved, project))

        updated_projects = 0

        def restore_ignored(state: dict) -> None:
            nonlocal updated_projects
            ignored_by_project = state.setdefault("ignored_vulnerabilities_by_project", {})
            for project, values in list(ignored_by_project.items()):
                remaining = {
                    value for value in values
                    if isinstance(value, str) and value not in aliases
                }
                if remaining:
                    ignored_by_project[project] = sorted(remaining)
                else:
                    ignored_by_project.pop(project, None)
            state["ignored_vulnerabilities_by_project"] = ignored_by_project

            for result_path, saved, project in saved_projects:
                ignored = _ignored_ids(state, project)
                manifest_results = saved.get("manifest_results")
                if isinstance(manifest_results, dict):
                    for manifest in manifest_results.values():
                        _recalculate_result(manifest, ignored)
                    saved = _aggregate_project_results(project, manifest_results, ignored)
                else:
                    saved = _recalculate_result(saved, ignored)
                _atomic_write_json(result_path, saved)
                updated_projects += 1

        mutate_system_state(restore_ignored)
    return {"status": "restored", "vuln_id": vuln_id, "projects_updated": updated_projects}


@app.get("/api/version", dependencies=[Depends(verify_token)])
async def get_version():
    version_file = BASE_DIR / "version.json"
    if version_file.exists():
        return json.loads(version_file.read_text(encoding="utf-8"))
    return {"version": "N/A"}
