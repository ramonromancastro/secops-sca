from __future__ import annotations
import json
import re
import xml.etree.ElementTree as ET
from typing import List, Dict, Tuple

ECOSYSTEM_MAP = {
    "composer.lock": "Packagist",
    "composer.json": "Packagist",
    "gemfile.lock": "RubyGems",
    "package-lock.json": "npm",
    "requirements.txt": "PyPI",
    "pom.xml": "Maven",
}

def identify_manifest(filename: str) -> Tuple[str, str, str]:
    """Extrae (<nombre_proyecto>, <tipo_archivo>, <ecosistema_osv>)"""
    if "_" not in filename:
        raise ValueError("El archivo debe cumplir el formato <proyecto>_<tipo>")
    project, file_type = filename.rsplit("_", 1)
    ft_lower = file_type.lower()
    if ft_lower not in ECOSYSTEM_MAP:
        raise ValueError(f"Tipo de archivo no soportado: {file_type}")
    return project, file_type, ECOSYSTEM_MAP[ft_lower]

def _dedupe_packages(packages: List[Dict[str, str]]) -> List[Dict[str, str]]:
    seen = set()
    unique_pkgs = []
    for package in packages:
        key = f"{package['name']}@{package['version']}"
        if key not in seen:
            seen.add(key)
            unique_pkgs.append(package)
    return unique_pkgs


def _parse_composer_lock(text: str) -> List[Dict[str, str]]:
    packages = []
    data = json.loads(text)
    for section in ("packages", "packages-dev"):
        for pkg in data.get(section, []):
            version = pkg.get("version", "").lstrip("v")
            if pkg.get("name") and version:
                packages.append({"name": pkg["name"], "version": version})
    return packages


def _parse_composer_json(text: str) -> List[Dict[str, str]]:
    packages = []
    data = json.loads(text)
    for section in ("require", "require-dev"):
        for name, version in data.get(section, {}).items():
            if "/" in name:  # Ignorar php o extensiones ext-*
                clean_ver = re.sub(r"[^0-9.]", "", version)
                if clean_ver:
                    packages.append({"name": name, "version": clean_ver})
    return packages


def _parse_gemfile_lock(text: str) -> List[Dict[str, str]]:
    packages = []
    in_specs = False
    spec_regex = re.compile(r"^ {4}([a-zA-Z0-9_\-\.]+) \((\d[0-9a-zA-Z\.\-]*)\)")
    for line in text.splitlines():
        if line.strip() == "specs:":
            in_specs = True
            continue
        if in_specs:
            if line and not line.startswith(" "):
                in_specs = False
                continue
            match = spec_regex.match(line)
            if match:
                packages.append({"name": match.group(1), "version": match.group(2)})
    return packages


def _parse_package_lock_json(text: str) -> List[Dict[str, str]]:
    packages = []
    data = json.loads(text)
    if "packages" in data:
        for path, info in data["packages"].items():
            if path.startswith("node_modules/") and "version" in info:
                pkg_name = path.split("node_modules/")[-1]
                packages.append({"name": pkg_name, "version": info["version"]})
    elif "dependencies" in data:
        for name, info in data["dependencies"].items():
            if "version" in info:
                packages.append({"name": name, "version": info["version"]})
    return packages


def _parse_requirements_txt(text: str) -> List[Dict[str, str]]:
    packages = []
    req_regex = re.compile(r"^([a-zA-Z0-9_\-\.]+)==([0-9a-zA-Z\.\-]+)")
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            match = req_regex.match(line)
            if match:
                packages.append({"name": match.group(1), "version": match.group(2)})
    return packages


def _parse_maven_dependency(elem: ET.Element) -> Dict[str, str] | None:
    if not elem.tag.endswith("dependency"):
        return None

    values = {}
    for child in elem:
        tag_name = child.tag.split("}")[-1]
        if tag_name in {"groupId", "artifactId", "version"} and child.text:
            values[tag_name] = child.text.strip()

    group_id = values.get("groupId")
    artifact_id = values.get("artifactId")
    version = values.get("version")
    if not group_id or not artifact_id or not version:
        return None

    pkg_name = f"{group_id}:{artifact_id}"
    clean_ver = re.sub(r"\$\{[^}]+\}", "1.0.0", version).lstrip("v")
    return {"name": pkg_name, "version": clean_ver}


def _parse_pom_xml(text: str) -> List[Dict[str, str]]:
    packages = []
    try:
        root = ET.fromstring(text)
        for elem in root.iter():
            dependency = _parse_maven_dependency(elem)
            if dependency:
                packages.append(dependency)
    except ET.ParseError:
        pass
    return packages


PARSER_MAP = {
    "composer.lock": _parse_composer_lock,
    "composer.json": _parse_composer_json,
    "gemfile.lock": _parse_gemfile_lock,
    "package-lock.json": _parse_package_lock_json,
    "requirements.txt": _parse_requirements_txt,
    "pom.xml": _parse_pom_xml,
}


def parse_manifest(content: bytes, file_type: str) -> List[Dict[str, str]]:
    ft = file_type.lower()
    text = content.decode("utf-8", errors="replace")
    parser = PARSER_MAP.get(ft)
    if parser is None:
        return []
    return _dedupe_packages(parser(text))
