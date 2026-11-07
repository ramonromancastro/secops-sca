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

def parse_manifest(content: bytes, file_type: str) -> List[Dict[str, str]]:
    ft = file_type.lower()
    text = content.decode("utf-8", errors="replace")
    packages = []

    if ft == "composer.lock":
        data = json.loads(text)
        for section in ("packages", "packages-dev"):
            for pkg in data.get(section, []):
                ver = pkg.get("version", "").lstrip("v")
                if pkg.get("name") and ver:
                    packages.append({"name": pkg["name"], "version": ver})

    elif ft == "composer.json":
        data = json.loads(text)
        for section in ("require", "require-dev"):
            for name, ver in data.get(section, {}).items():
                if "/" in name:  # Ignorar php o extensiones ext-*
                    clean_ver = re.sub(r"[^0-9.]", "", ver)
                    if clean_ver:
                        packages.append({"name": name, "version": clean_ver})

    elif ft == "gemfile.lock":
        # Parsea la sección GEM -> specs: de Gemfile.lock (4 espacios = gema raíz)
        in_specs = False
        spec_regex = re.compile(r"^ {4}([a-zA-Z0-9_\-\.]+) \(([0-9][0-9a-zA-Z\.\-]*)\)")
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

    elif ft == "package-lock.json":
        data = json.loads(text)
        # Soporte lockfileVersion 2 y 3
        if "packages" in data:
            for path, info in data["packages"].items():
                if path.startswith("node_modules/") and "version" in info:
                    pkg_name = path.split("node_modules/")[-1]
                    packages.append({"name": pkg_name, "version": info["version"]})
        elif "dependencies" in data:
            for name, info in data["dependencies"].items():
                if "version" in info:
                    packages.append({"name": name, "version": info["version"]})

    elif ft == "requirements.txt":
        req_regex = re.compile(r"^([a-zA-Z0-9_\-\.]+)==([0-9a-zA-Z\.\-]+)")
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                match = req_regex.match(line)
                if match:
                    packages.append({"name": match.group(1), "version": match.group(2)})

    elif ft == "pom.xml":
        try:
            # Parsear XML ignorando namespaces mediante un iterparse o limpieza de tags
            root = ET.fromstring(text)

            # Recorrer todos los elementos buscando la etiqueta 'dependency' independientemente del namespace
            for elem in root.iter():
                # ElementTree asigna namespaces como '{http://maven.apache.org/POM/4.0.0}dependency'
                if elem.tag.endswith("dependency"):
                    group_id = None
                    artifact_id = None
                    version = None

                    for child in elem:
                        tag_name = child.tag.split("}")[-1] # Elimina cualquier prefijo de namespace
                        if tag_name == "groupId" and child.text:
                            group_id = child.text.strip()
                        elif tag_name == "artifactId" and child.text:
                            artifact_id = child.text.strip()
                        elif tag_name == "version" and child.text:
                            version = child.text.strip()

                    if group_id and artifact_id and version:
                        # En OSV.dev para Maven el formato del paquete es groupId:artifactId
                        pkg_name = f"{group_id}:{artifact_id}"
                        # Limpiar variables de entorno de Maven tipo ${project.version} si vinieran hardcodeadas
                        clean_ver = re.sub(r"\$\{[^}]+\}", "1.0.0", version).lstrip("v")
                        packages.append({"name": pkg_name, "version": clean_ver})
        except ET.ParseError:
            pass # Si el XML está malformado, se omite silenciosamente

    # Eliminar duplicados manteniendo orden
    seen = set()
    unique_pkgs = []
    for p in packages:
        key = f"{p['name']}@{p['version']}"
        if key not in seen:
            seen.add(key)
            unique_pkgs.append(p)
    return unique_pkgs
