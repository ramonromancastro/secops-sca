from __future__ import annotations
import os
import re
import os
import json
import httpx
import secrets
from datetime import datetime, timezone
from fastapi import FastAPI, UploadFile, File, Form, Depends, HTTPException, Security, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from parsers import identify_manifest, parse_manifest, ECOSYSTEM_MAP
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
MANIFESTS_DIR = BASE_DIR / "manifests"
RESULTS_DIR = BASE_DIR / "results"
CONFIG_FILE = BASE_DIR / "config" / "settings.json"

for d in (MANIFESTS_DIR, RESULTS_DIR, CONFIG_FILE.parent):
    d.mkdir(parents=True, exist_ok=True)

def load_settings() -> dict:
    if not CONFIG_FILE.exists():
        default_cfg = {
            "api_token": secrets.token_hex(16),
            "upload_token": secrets.token_hex(16),
            "cron_schedule": "0 */6 * * *",
            "last_global_scan": None,
            "ignored_vulnerabilities": [],
            "scan_history": [],
            "relative_url_root": "",
        }
        save_settings(default_cfg)
        return default_cfg
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_settings(data: dict):
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

active_config = load_settings()
app = FastAPI(title="SecOps SCA Monitor API",
                root_path=active_config["relative_url_root"])
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

security_scheme = HTTPBearer(auto_error=False)

def verify_token(request: Request, credentials: HTTPAuthorizationCredentials = Security(security_scheme)):
    settings = load_settings()
    api_token = settings.get("api_token", None)

    # Si por alguna razón no hay token configurado en settings.json, da error
    if not api_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token de acceso no configurado",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Comprobar si se envió la credencial Bearer y si coincide con el token esperado
    if not credentials or credentials.credentials != api_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token de acceso inválido o no proporcionado",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return credentials.credentials

def verify_any_token(request: Request, credentials: HTTPAuthorizationCredentials = Security(security_scheme)):
    settings = load_settings()

    # Obtener ambos tokens permitidos desde settings.json
    api_token = settings.get("api_token", None)
    upload_token = settings.get("upload_token", None)

    # Recoger el token enviado por la petición
    provided_token = credentials.credentials if credentials else ""

    # Si por alguna razón no hay token configurado en settings.json, da error
    if not api_token or not upload_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token de acceso no configurado",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Comprobar si el token proporcionado coincide con ALGUNO de los dos válidos
    if provided_token == api_token or provided_token == upload_token:
        return provided_token
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token de acceso inválido o no autorizado para esta operación",
            headers={"WWW-Authenticate": "Bearer"},
        )

def extract_severity(vuln: dict) -> tuple[str, float, str]:
    """Calcula Severidad y CVSS desde el esquema OSV."""
    db_sev = vuln.get("database_specific", {}).get("severity", "").upper()
    vector = ""
    for s in vuln.get("severity", []):
        if s.get("type") == "CVSS_V3":
            vector = s.get("score", "")
            break

    # Mapeo de severidad textual a score aproximado si no viene numérico
    mapping = {"CRITICAL": 9.5, "HIGH": 7.8, "MODERATE": 5.5, "MEDIUM": 5.5, "LOW": 2.5}
    if db_sev in mapping:
        sev = "MEDIUM" if db_sev == "MODERATE" else db_sev
        return sev, mapping[db_sev], vector

    # Si hay vector CVSS o sin clasificar, estimar por palabras clave en vector
    if "C:H/I:H/A:H" in vector:
        return "CRITICAL", 9.8, vector
    elif "C:H" in vector or "I:H" in vector:
        return "HIGH", 7.5, vector
    return "MEDIUM", 5.0, vector

def extract_fixed_version(vuln: dict, pkg_name: str) -> str:
    for aff in vuln.get("affected", []):
        if aff.get("package", {}).get("name", "").lower() == pkg_name.lower():
            for rng in aff.get("ranges", []):
                for ev in rng.get("events", []):
                    if "fixed" in ev:
                        return f">= {ev['fixed']}"
    return "Revisar advisory"

def calculate_score(counts: dict) -> tuple[int, str]:
    penalty = (counts["CRITICAL"] * 25) + (counts["HIGH"] * 10) + (counts["MEDIUM"] * 3) + (counts["LOW"] * 1)
    score = max(0, 100 - penalty)
    if score >= 90: grade = "A"
    elif score >= 80: grade = "B"
    elif score >= 65: grade = "C"
    elif score >= 50: grade = "D"
    else: grade = "F"
    return score, grade

async def _build_vulnerability(pkg: dict, v_stub: dict, client: httpx.AsyncClient, ignored_list: set[str]) -> dict | None:
    osv_id = v_stub["id"]
    detail_resp = await client.get(f"https://api.osv.dev/v1/vulns/{osv_id}")
    if detail_resp.status_code != 200:
        return None

    v_data = detail_resp.json()
    aliases = v_data.get("aliases", [])
    cve_id = next((a for a in aliases if a.startswith("CVE-")), osv_id)
    sev, score, vector = extract_severity(v_data)
    fixed_ver = extract_fixed_version(v_data, pkg["name"])
    refs = [r.get("url") for r in v_data.get("references", []) if r.get("url")][:4]
    is_ignored = (cve_id in ignored_list) or (osv_id in ignored_list)

    return {
        "id": cve_id,
        "osv_id": osv_id,
        "package": pkg["name"],
        "installed_version": pkg["version"],
        "fixed_version": fixed_ver,
        "severity": sev,
        "cvss_score": score,
        "cvss_vector": vector or "N/A",
        "summary": v_data.get("summary", "Vulnerabilidad detectada en componente."),
        "details": v_data.get("details", "Sin descripción adicional."),
        "references": refs,
        "ignored": is_ignored
    }


async def _collect_vulnerabilities(client: httpx.AsyncClient, packages: list[dict], batch_results: list[dict], ignored_list: set[str]) -> list[dict]:
    vulnerabilities = []
    for pkg, res in zip(packages, batch_results):
        for v_stub in res.get("vulns", []):
            vuln = await _build_vulnerability(pkg, v_stub, client, ignored_list)
            if vuln is not None:
                vulnerabilities.append(vuln)
    return vulnerabilities


async def scan_single_manifest(filepath: Path, settings: dict) -> dict:
    project, file_type, ecosystem = identify_manifest(filepath.name)
    content = filepath.read_bytes()
    packages = parse_manifest(content, file_type)

    queries = [
        {"package": {"name": p["name"], "ecosystem": ecosystem}, "version": p["version"]}
        for p in packages
    ]

    vulnerabilities = []
    ignored_list = set(settings.get("ignored_vulnerabilities", []))

    if queries:
        async with httpx.AsyncClient(timeout=30.0) as client:
            # 1. Consulta por lotes a OSV.dev
            batch_resp = await client.post("https://api.osv.dev/v1/querybatch", json={"queries": queries})
            batch_results = batch_resp.json().get("results", [])

            # 2. Hidratar detalles de vulnerabilidades detectadas
            vulnerabilities = await _collect_vulnerabilities(client, packages, batch_results, ignored_list)

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "IGNORED": 0}
    for v in vulnerabilities:
        if not v["ignored"]:
            counts[v["severity"]] = counts.get(v["severity"], 0) + 1
        else:
            counts["IGNORED"] = counts.get("IGNORED", 0) + 1

    sec_score, grade = calculate_score(counts)
    result_data = {
        "project": project,
        "filename": filepath.name,
        "file_type": file_type,
        "ecosystem": ecosystem,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "total_dependencies": len(packages),
        "security_score": sec_score,
        "grade": grade,
        "counts": counts,
        "vulnerabilities": vulnerabilities
    }

    out_file = RESULTS_DIR / f"{project}_results.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(result_data, f, indent=2)
    return result_data

@app.get("/api/dashboard", dependencies=[Depends(verify_token)])
async def get_dashboard():
    settings = load_settings()
    projects = []
    for res_file in sorted(RESULTS_DIR.glob("*_results.json")):
        with open(res_file, "r", encoding="utf-8") as f:
            projects.append(json.load(f))
    return {"settings": settings, "projects": projects}

@app.post("/api/scan/all", dependencies=[Depends(verify_token)])
async def scan_all_projects():
    settings = load_settings()
    results = []
    totals = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for manifest in MANIFESTS_DIR.iterdir():
        if manifest.is_file() and "_" in manifest.name:
            try:
                res = await scan_single_manifest(manifest, settings)
                results.append(res)
                for k in totals:
                    totals[k] += res["counts"].get(k, 0)
            except Exception as e:
                print(f"Error escaneando {manifest.name}: {e}")

    now_iso = datetime.now(timezone.utc).isoformat()
    # 1. Añadimos horas y minutos al string para hacerlo único por momento
    timestamp_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    settings["last_global_scan"] = now_iso

    # Actualizar historial de tendencia (máximo 15 puntos)
    history = settings.get("scan_history", [])
    entry = {"date": timestamp_str, **totals}

    # 2. Eliminamos el "if" que sobrescribía. Ahora siempre añadimos el nuevo escaneo.
    history.append(entry)

    settings["scan_history"] = history[-15:]
    save_settings(settings)

    return {"status": "ok", "scanned_projects": len(results), "last_global_scan": now_iso}

@app.post(
    "/api/scan/{project}",
    dependencies=[Depends(verify_token)],
    responses={404: {"description": "Manifiesto de proyecto no encontrado"}},
)
async def scan_project_endpoint(project: str):
    settings = load_settings()
    matches = list(MANIFESTS_DIR.glob(f"{project}_*"))
    if not matches:
        raise HTTPException(status_code=404, detail="Manifiesto de proyecto no encontrado")
    res = await scan_single_manifest(matches[0], settings)
    return res

@app.post(
    "/api/upload",
    dependencies=[Depends(verify_any_token)],
    responses={400: {"description": "Tipo de archivo no válido o nombre de proyecto inválido"}},
)
async def upload_manifest(file: UploadFile = File(...), project_name: str = Form("")):
    orig_name = os.path.basename(file.filename)
    # Comprobar si ya cumple <proyecto>_<tipo>
    valid_direct = False
    target_filename = None
    if "_" in orig_name:
        _, ftype = orig_name.rsplit("_", 1)
        if ftype.lower() in ECOSYSTEM_MAP:
            valid_direct = True
            target_filename = orig_name

    if not valid_direct:
        if orig_name.lower() not in ECOSYSTEM_MAP:
            raise HTTPException(
                status_code=400,
                detail=f"Tipo de archivo no válido ({orig_name}). Soportados: {', '.join(ECOSYSTEM_MAP.keys())}"
            )
        clean_proj = re.sub(r"[^a-zA-Z0-9\-]", "-", project_name.strip())
        if not clean_proj:
            raise HTTPException(status_code=400, detail="Debe indicar un nombre de proyecto válido.")
        target_filename = f"{clean_proj}_{orig_name}"

    if not target_filename:
        raise HTTPException(status_code=400, detail="No se pudo determinar el nombre de archivo de destino.")

    dest_path = MANIFESTS_DIR / target_filename
    content = await file.read()
    dest_path.write_bytes(content)

    settings = load_settings()
    res = await scan_single_manifest(dest_path, settings)
    return res

@app.delete(
    "/api/projects/{project}",
    dependencies=[Depends(verify_token)],
    responses={404: {"description": "Proyecto no encontrado"}},
)
async def delete_project(project: str):
    deleted = False
    for m in MANIFESTS_DIR.glob(f"{project}_*"):
        m.unlink(missing_ok=True)
        deleted = True
    res_file = RESULTS_DIR / f"{project}_results.json"
    if res_file.exists():
        res_file.unlink()
        deleted = True
    if not deleted:
        raise HTTPException(status_code=404, detail="Proyecto no encontrado")
    return {"status": "deleted", "project": project}

@app.post(
    "/api/projects/{project}/ignore",
    dependencies=[Depends(verify_token)],
    responses={404: {"description": "Resultado no encontrado"}},
)
async def toggle_ignore_vulnerability(project: str, vuln_id: str = Form(...)):
    settings = load_settings()
    ignored = set(settings.get("ignored_vulnerabilities", []))
    if vuln_id in ignored:
        ignored.remove(vuln_id)
    else:
        ignored.add(vuln_id)
    settings["ignored_vulnerabilities"] = list(ignored)
    save_settings(settings)

    # Recalcular archivo de resultados sin necesidad de llamar a la API externa
    res_file = RESULTS_DIR / f"{project}_results.json"
    if res_file.exists():
        data = json.loads(res_file.read_text(encoding="utf-8"))
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "IGNORED": 0}
        for v in data.get("vulnerabilities", []):
            v["ignored"] = (v["id"] in ignored) or (v["osv_id"] in ignored)
            if not v["ignored"]:
                counts[v["severity"]] = counts.get(v["severity"], 0) + 1
            else:
                counts["IGNORED"] = counts.get("IGNORED", 0) + 1
        data["counts"] = counts
        data["security_score"], data["grade"] = calculate_score(counts)
        res_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return data
    raise HTTPException(status_code=404, detail="Resultado no encontrado")

@app.get("/api/version", dependencies=[Depends(verify_token)])
async def get_version():
    version_file = BASE_DIR / "version.json"
    if version_file.exists():
        return json.loads(version_file.read_text(encoding="utf-8"))
    return {"version": "N/A"}
