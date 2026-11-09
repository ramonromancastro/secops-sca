from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from typing import Any


ECOSYSTEM_MAP = {
    "composer.lock": "Packagist",
    "composer.json": "Packagist",
    "gemfile.lock": "RubyGems",
    "package-lock.json": "npm",
    "requirements.txt": "PyPI",
    "pom.xml": "Maven",
}

PROJECT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$")
EXACT_COMPOSER_VERSION_RE = re.compile(
    r"^v?(\d+(?:\.\d+){0,3}(?:[-+][0-9A-Za-z.-]+)?)$"
)


def identify_manifest(filename: str) -> tuple[str, str, str]:
    """Return (project name, manifest type, OSV ecosystem)."""
    if "_" not in filename:
        raise ValueError("El archivo debe cumplir el formato <proyecto>_<tipo>")
    project, file_type = filename.rsplit("_", 1)
    file_type_lower = file_type.lower()
    if file_type_lower not in ECOSYSTEM_MAP:
        raise ValueError(f"Tipo de archivo no soportado: {file_type}")
    if not PROJECT_NAME_RE.fullmatch(project) or project in {".", ".."}:
        raise ValueError("Nombre de proyecto inválido")
    return project, file_type_lower, ECOSYSTEM_MAP[file_type_lower]


def _package(name: Any, version: Any) -> dict[str, str] | None:
    if not isinstance(name, str) or not name.strip():
        return None
    if not isinstance(version, str) or not version.strip():
        return None
    return {"name": name.strip(), "version": version.strip()}


def _dedupe_packages(packages: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[tuple[str, str]] = set()
    unique: list[dict[str, str]] = []
    for package in packages:
        key = (package["name"].casefold(), package["version"].casefold())
        if key not in seen:
            seen.add(key)
            unique.append(package)
    return unique


def _parse_composer_lock(text: str) -> list[dict[str, str]]:
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("composer.lock debe contener un objeto JSON")
    packages: list[dict[str, str]] = []
    for section in ("packages", "packages-dev"):
        entries = data.get(section, [])
        if not isinstance(entries, list):
            raise ValueError(f"La sección {section} de composer.lock no es válida")
        for item in entries:
            if not isinstance(item, dict):
                raise ValueError(f"La sección {section} contiene una entrada inválida")
            package = _package(item.get("name"), item.get("version"))
            if not package:
                raise ValueError(f"La sección {section} contiene un paquete sin nombre o versión")
            package["version"] = package["version"].lstrip("v")
            packages.append(package)
    return packages


def _parse_composer_json(text: str) -> list[dict[str, str]]:
    """Only scan exact pins; ranges need composer.lock resolution."""
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("composer.json debe contener un objeto JSON")
    packages: list[dict[str, str]] = []
    for section in ("require", "require-dev"):
        dependencies = data.get(section, {})
        if not isinstance(dependencies, dict):
            raise ValueError(f"La sección {section} de composer.json no es válida")
        for name, constraint in dependencies.items():
            if not isinstance(name, str) or "/" not in name:
                continue  # PHP runtime and extensions are not Packagist packages.
            if not isinstance(constraint, str):
                raise ValueError(f"Restricción de versión inválida para {name}")
            match = EXACT_COMPOSER_VERSION_RE.fullmatch(constraint.strip())
            if not match:
                raise ValueError(
                    "composer.json contiene rangos de versión. Sube composer.lock "
                    "para analizar las versiones realmente resueltas."
                )
            packages.append({"name": name, "version": match.group(1)})
    return packages


def _parse_gemfile_lock(text: str) -> list[dict[str, str]]:
    packages: list[dict[str, str]] = []
    in_specs = False
    spec_regex = re.compile(r"^ {4}([a-zA-Z0-9_\-.]+) \((\d[0-9a-zA-Z.+\-]*)\)")
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


def _parse_package_lock_json(text: str) -> list[dict[str, str]]:
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("package-lock.json debe contener un objeto JSON")
    packages: list[dict[str, str]] = []
    entries = data.get("packages")
    if isinstance(entries, dict):
        for path, info in entries.items():
            if not isinstance(path, str) or not path.startswith("node_modules/"):
                continue
            if not isinstance(info, dict):
                continue
            name = path.rsplit("node_modules/", 1)[-1]
            package = _package(name, info.get("version"))
            if package:
                packages.append(package)
    else:
        def visit_dependencies(dependencies: Any) -> None:
            if not isinstance(dependencies, dict):
                return
            for name, info in dependencies.items():
                if not isinstance(info, dict):
                    continue
                package = _package(name, info.get("version"))
                if package:
                    packages.append(package)
                visit_dependencies(info.get("dependencies"))

        visit_dependencies(data.get("dependencies"))
    return packages


def _parse_requirements_txt(text: str) -> list[dict[str, str]]:
    packages: list[dict[str, str]] = []
    requirement_re = re.compile(
        r"^([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[A-Za-z0-9_,.-]+\])?"
        r"==([A-Za-z0-9][A-Za-z0-9.!+_-]*)\s*(?:;.*)?$"
    )
    supported_options = re.compile(
        r"^--(?:index-url|extra-index-url|trusted-host|find-links)(?:\s+|=)"
    )
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if supported_options.match(line):
            continue
        if line.startswith(("-r ", "--requirement ", "-c ", "--constraint ", "-e ", "--editable ")):
            raise ValueError(
                f"requirements.txt línea {line_number}: incluye otro archivo o una "
                "instalación editable; sube un archivo con las dependencias resueltas."
            )
        line = re.sub(r"\s+#.*$", "", line)
        line = re.sub(r"\s+--hash=sha256:[0-9a-fA-F]+", "", line)
        match = requirement_re.fullmatch(line)
        if not match:
            raise ValueError(
                f"requirements.txt línea {line_number}: solo se aceptan dependencias "
                "con versión exacta usando ==."
            )
        packages.append({"name": match.group(1), "version": match.group(2)})
    return packages


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _direct_child(element: ET.Element, name: str) -> ET.Element | None:
    return next((child for child in element if _local_name(child.tag) == name), None)


def _parse_pom_xml(text: str) -> list[dict[str, str]]:
    if re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", text, flags=re.IGNORECASE):
        raise ValueError("pom.xml no puede contener declaraciones DTD o ENTITY")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError(f"pom.xml no es XML válido: {exc}") from exc

    properties: dict[str, str] = {}
    for coordinate in ("groupId", "artifactId", "version"):
        element = _direct_child(root, coordinate)
        if element is not None and element.text:
            value = element.text.strip()
            properties[f"project.{coordinate}"] = value
            properties[f"pom.{coordinate}"] = value
    properties_element = _direct_child(root, "properties")
    if properties_element is not None:
        for prop in properties_element:
            if prop.text and prop.text.strip():
                properties[_local_name(prop.tag)] = prop.text.strip()

    def resolve_property(value: str, package_name: str) -> str:
        for _ in range(10):
            unresolved = re.search(r"\$\{([^}]+)\}", value)
            if not unresolved:
                break
            property_name = unresolved.group(1)
            replacement = properties.get(property_name)
            if replacement is None:
                raise ValueError(
                    f"No se pudo resolver la propiedad Maven ${{{property_name}}} "
                    f"de {package_name}"
                )
            value = value.replace(unresolved.group(0), replacement)
        if "${" in value:
            raise ValueError(f"No se pudieron resolver las coordenadas Maven de {package_name}")
        return value

    dependencies_element = _direct_child(root, "dependencies")
    if dependencies_element is None:
        return []

    packages: list[dict[str, str]] = []
    for dependency in dependencies_element:
        if _local_name(dependency.tag) != "dependency":
            continue
        values: dict[str, str] = {}
        for child in dependency:
            name = _local_name(child.tag)
            if name in {"groupId", "artifactId", "version"} and child.text:
                values[name] = child.text.strip()
        group_id = values.get("groupId")
        artifact_id = values.get("artifactId")
        version = values.get("version")
        if not group_id or not artifact_id:
            raise ValueError("pom.xml contiene una dependencia sin groupId o artifactId")
        unresolved_package_name = f"{group_id}:{artifact_id}"
        group_id = resolve_property(group_id, unresolved_package_name)
        artifact_id = resolve_property(artifact_id, unresolved_package_name)
        if not group_id.strip() or not artifact_id.strip():
            raise ValueError("pom.xml contiene coordenadas Maven vacías")
        if not version:
            raise ValueError(
                f"La dependencia {group_id}:{artifact_id} no tiene versión explícita. "
                "Usa el POM efectivo o genera un inventario con versiones resueltas."
            )
        version = resolve_property(version, f"{group_id}:{artifact_id}").strip()

        package = _package(f"{group_id}:{artifact_id}", version.lstrip("v"))
        if package:
            packages.append(package)
    return packages


PARSER_MAP = {
    "composer.lock": _parse_composer_lock,
    "composer.json": _parse_composer_json,
    "gemfile.lock": _parse_gemfile_lock,
    "package-lock.json": _parse_package_lock_json,
    "requirements.txt": _parse_requirements_txt,
    "pom.xml": _parse_pom_xml,
}


def parse_manifest(content: bytes, file_type: str) -> list[dict[str, str]]:
    file_type_lower = file_type.lower()
    parser = PARSER_MAP.get(file_type_lower)
    if parser is None:
        raise ValueError(f"Tipo de archivo no soportado: {file_type}")
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("El manifiesto debe estar codificado en UTF-8") from exc
    return _dedupe_packages(parser(text))
