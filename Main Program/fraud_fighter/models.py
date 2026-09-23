from dataclasses import dataclass
from pathlib import Path

@dataclass
class CaseInfo:
    name: str
    number: str
    examiner: str
    organization: str
    description: str
    folder: Path
    database: Path
    created_utc: str


@dataclass
class PluginInfo:
    plugin_id: str
    name: str
    category: str
    description: str
    icon: str
    executable: Path
    working_directory: Path
    pass_case_arguments: bool
    enabled: bool
    version: str


