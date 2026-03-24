import os
from pathlib import Path


def _default_artifact_path(env_var: str, artifact_name: str) -> Path:
    env_path = os.environ.get(env_var)
    if env_path:
        return Path(env_path)

    root = Path(__file__).resolve().parents[3]
    candidates = [
        root / "build" / "Debug" / artifact_name,
        root / "build" / "Release" / artifact_name,
        root / "build-cmake" / "Debug" / artifact_name,
        root / "build-cmake" / "Release" / artifact_name,
        root / "build-py" / "Debug" / artifact_name,
        root / "build-py" / "Release" / artifact_name,
        root / "x64" / "Debug" / artifact_name,
        root / "x64" / "Release" / artifact_name,
        root / artifact_name,
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[-1]


def default_library_path() -> Path:
    return _default_artifact_path("CPUEAXH_DLL_PATH", "cpueaxh_shared.dll")


def default_bridge_library_path() -> Path:
    return _default_artifact_path("CPUEAXH_BRIDGE_DLL_PATH", "cpueaxh_native_bridges.dll")
