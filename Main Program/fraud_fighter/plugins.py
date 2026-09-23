import json
import re
from pathlib import Path
from .config import PLUGINS_DIR, SCRIPTS_DIR
from .models import PluginInfo

def _parse_script_metadata(script_path: Path) -> dict[str, str]:
    """Read FFT metadata without importing or executing the script."""
    metadata: dict[str, str] = {}
    try:
        header = script_path.read_text(encoding="utf-8-sig", errors="replace")[:16384]
    except Exception:
        return metadata

    aliases = {
        "TITLE": "name",
        "NAME": "name",
        "CATEGORY": "category",
        "VERSION": "version",
        "DESCRIPTION": "description",
        "ICON": "icon",
        "ID": "plugin_id",
        "PASS_CASE_ARGUMENTS": "pass_case_arguments",
    }
    for source_key, target_key in aliases.items():
        patterns = [
            rf"(?im)^\s*#?\s*{source_key}\s*:\s*([^\r\n]+)",
            rf"(?im)^\s*{source_key}\s*=\s*[\"']([^\"']+)[\"']",
        ]
        for pattern in patterns:
            match = re.search(pattern, header)
            if match:
                metadata.setdefault(target_key, match.group(1).strip())
                break
    return metadata


def discover_plugins() -> list[PluginInfo]:
    """Discover legacy manifest plugins and drop-in Python scripts."""
    discovered: list[PluginInfo] = []
    seen_paths: set[Path] = set()
    PLUGINS_DIR.mkdir(exist_ok=True)
    SCRIPTS_DIR.mkdir(exist_ok=True)

    # Legacy manifest plugins remain supported.
    for manifest_path in sorted(PLUGINS_DIR.glob("*/plugin.json")):
        try:
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            executable = (manifest_path.parent / data["executable"]).resolve()
            if not executable.exists():
                continue
            discovered.append(
                PluginInfo(
                    plugin_id=str(data.get("id") or manifest_path.parent.name),
                    name=str(data.get("name") or manifest_path.parent.name),
                    category=str(data.get("category") or "Plugins"),
                    description=str(data.get("description") or ""),
                    icon=str(data.get("icon") or "■"),
                    executable=executable,
                    working_directory=manifest_path.parent,
                    pass_case_arguments=bool(data.get("pass_case_arguments", False)),
                    enabled=bool(data.get("enabled", True)),
                    version=str(data.get("version") or ""),
                )
            )
            seen_paths.add(executable)
        except Exception:
            continue

    # Every Python file in Scripts becomes a launcher option.
    for script_path in sorted(SCRIPTS_DIR.glob("*.py"), key=lambda item: item.name.lower()):
        resolved = script_path.resolve()
        if resolved in seen_paths or script_path.name.startswith("_"):
            continue
        metadata = _parse_script_metadata(script_path)
        name = metadata.get("name") or script_path.stem.replace("_", " ")
        plugin_id = metadata.get("plugin_id") or re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
        category = metadata.get("category") or "Plugins"
        pass_args = metadata.get("pass_case_arguments", "false").lower() in ("1", "true", "yes")
        discovered.append(
            PluginInfo(
                plugin_id=plugin_id,
                name=name,
                category=category,
                description=metadata.get("description", ""),
                icon=metadata.get("icon", "◆"),
                executable=resolved,
                working_directory=SCRIPTS_DIR,
                pass_case_arguments=pass_args,
                enabled=True,
                version=metadata.get("version", ""),
            )
        )
        seen_paths.add(resolved)

    unique: dict[str, PluginInfo] = {}
    for plugin in discovered:
        if plugin.enabled:
            unique.setdefault(plugin.plugin_id, plugin)
    return sorted(unique.values(), key=lambda item: (item.category.lower(), item.name.lower()))


