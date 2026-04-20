import csv
import json
import re
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import yaml


ARTIFACTS_DIR = Path("/artifacts")
ARGS_FILE = ARTIFACTS_DIR / "experiment-args.json"
CONFIG_FILE = ARTIFACTS_DIR / "experiment-config.yaml"

RAW_OUT = ARTIFACTS_DIR / "ping.raw.txt"
STDERR_OUT = ARTIFACTS_DIR / "ping.stderr.txt"
COMMAND_OUT = ARTIFACTS_DIR / "ping.command.txt"
RESULT_JSON = ARTIFACTS_DIR / "ping.result.json"
RESULT_CSV = ARTIFACTS_DIR / "ping.result.csv"
METADATA_JSON = ARTIFACTS_DIR / "ping.metadata.json"


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_yaml(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def to_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes", "y"}
    if isinstance(value, (int, float)):
        return bool(value)
    return default


def to_int(value: Any, default: Optional[int] = None) -> Optional[int]:
    if value in (None, ""):
        return default
    return int(value)


def to_float(value: Any, default: Optional[float] = None) -> Optional[float]:
    if value in (None, ""):
        return default
    return float(value)


def extract_from_config_yaml(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Flexible fallback parser for experiment-config.yaml.

    Recommended convention:
      params:
        target: 8.8.8.8
        count: 4
        ...

    Also supports:
      docker:
        execute:
          params:
            ...
    """
    params = config.get("params")
    if isinstance(params, dict):
        return params

    docker_section = config.get("docker", {})
    if isinstance(docker_section, dict):
        execute_section = docker_section.get("execute", {})
        if isinstance(execute_section, dict):
            nested_params = execute_section.get("params")
            if isinstance(nested_params, dict):
                return nested_params

    return {}


def load_runtime_inputs() -> Dict[str, Any]:
    """
    Prefer experiment-args.json because it is LEOScope-normalized.
    Fall back to experiment-config.yaml because that is the user-facing file.
    """
    metadata: Dict[str, Any] = {
        "experiment_id": "unknown",
        "node_id": "unknown",
        "user_id": "unknown",
        "experiment_type": "unknown",
        "start_date": "",
        "end_date": "",
    }
    params: Dict[str, Any] = {}

    if ARGS_FILE.exists():
        args = load_json(ARGS_FILE)
        metadata.update(
            {
                "experiment_id": args.get("id", "unknown"),
                "node_id": args.get("nodeid", "unknown"),
                "user_id": args.get("userid", "unknown"),
                "experiment_type": args.get("type", "unknown"),
                "start_date": args.get("startDate", ""),
                "end_date": args.get("endDate", ""),
            }
        )
        args_params = args.get("params", {})
        if isinstance(args_params, dict):
            params.update(args_params)

    if CONFIG_FILE.exists():
        config = load_yaml(CONFIG_FILE)

        if metadata["experiment_id"] == "unknown":
            metadata["experiment_id"] = config.get("id", "unknown")
        if metadata["node_id"] == "unknown":
            metadata["node_id"] = config.get("nodeid", "unknown")
        if metadata["user_id"] == "unknown":
            metadata["user_id"] = config.get("userid", "unknown")
        if metadata["experiment_type"] == "unknown":
            metadata["experiment_type"] = config.get("type", "unknown")
        if not metadata["start_date"]:
            metadata["start_date"] = config.get("startDate", "")
        if not metadata["end_date"]:
            metadata["end_date"] = config.get("endDate", "")

        yaml_params = extract_from_config_yaml(config)
        for key, value in yaml_params.items():
            params.setdefault(key, value)

    return {
        "metadata": metadata,
        "params": params,
    }


def validate_params(params: Dict[str, Any]) -> Dict[str, Any]:
    validated = {
        "target": params.get("target", "8.8.8.8"),
        "count": to_int(params.get("count", 4), 4),
        "interval": to_float(params.get("interval", 1), 1.0),
        "deadline": to_int(params.get("deadline")),
        "packet_size": to_int(params.get("packet_size")),
        "timeout": to_int(params.get("timeout")),
        "family": params.get("family"),
        "numeric": to_bool(params.get("numeric", False), False),
    }

    if not validated["target"]:
        raise ValueError("params.target must not be empty")

    if validated["count"] is None or validated["count"] < 0:
        raise ValueError("params.count must be a non-negative integer")

    if validated["interval"] is None or validated["interval"] <= 0:
        raise ValueError("params.interval must be a positive number")

    if validated["deadline"] is not None and validated["deadline"] < 0:
        raise ValueError("params.deadline must be a non-negative integer")

    if validated["packet_size"] is not None and validated["packet_size"] < 0:
        raise ValueError("params.packet_size must be a non-negative integer")

    if validated["timeout"] is not None and validated["timeout"] < 0:
        raise ValueError("params.timeout must be a non-negative integer")

    if validated["family"] not in (None, "", "ipv4", "ipv6"):
        raise ValueError("params.family must be one of: ipv4, ipv6")

    return validated


def build_ping_command(params: Dict[str, Any]) -> list[str]:
    cmd = ["ping"]

    if params["family"] == "ipv4":
        cmd.append("-4")
    elif params["family"] == "ipv6":
        cmd.append("-6")

    if params["numeric"]:
        cmd.append("-n")

    cmd.extend(["-c", str(params["count"])])
    cmd.extend(["-i", str(params["interval"])])

    if params["deadline"] is not None:
        cmd.extend(["-w", str(params["deadline"])])

    if params["packet_size"] is not None:
        cmd.extend(["-s", str(params["packet_size"])])

    if params["timeout"] is not None:
        cmd.extend(["-W", str(params["timeout"])])

    cmd.append(str(params["target"]))
    return cmd


def parse_ping_output(raw_text: str) -> Dict[str, Optional[float]]:
    result: Dict[str, Optional[float]] = {
        "packets_transmitted": None,
        "packets_received": None,
        "packet_loss_percent": None,
        "total_time_ms": None,
        "rtt_min_ms": None,
        "rtt_avg_ms": None,
        "rtt_max_ms": None,
        "rtt_mdev_ms": None,
    }

    summary_match = re.search(
        r"(?P<tx>\d+)\s+packets transmitted,\s+"
        r"(?P<rx>\d+)\s+(?:packets )?received,.*?"
        r"(?P<loss>[\d.]+)%\s+packet loss"
        r"(?:,\s+time\s+(?P<time>\d+)ms)?",
        raw_text,
        re.MULTILINE,
    )
    if summary_match:
        result["packets_transmitted"] = int(summary_match.group("tx"))
        result["packets_received"] = int(summary_match.group("rx"))
        result["packet_loss_percent"] = float(summary_match.group("loss"))
        if summary_match.group("time") is not None:
            result["total_time_ms"] = float(summary_match.group("time"))

    rtt_match = re.search(
        r"(?:rtt|round-trip).*?=\s*"
        r"(?P<min>[\d.]+)/(?P<avg>[\d.]+)/(?P<max>[\d.]+)/(?P<mdev>[\d.]+)",
        raw_text,
        re.MULTILINE,
    )
    if rtt_match:
        result["rtt_min_ms"] = float(rtt_match.group("min"))
        result["rtt_avg_ms"] = float(rtt_match.group("avg"))
        result["rtt_max_ms"] = float(rtt_match.group("max"))
        result["rtt_mdev_ms"] = float(rtt_match.group("mdev"))

    return result


def write_text(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def write_json(path: Path, data: Dict[str, Any]) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def write_csv(path: Path, row: Dict[str, Any]) -> None:
    fieldnames = [
        "measurement",
        "experiment_id",
        "node_id",
        "user_id",
        "experiment_type",
        "start_date",
        "end_date",
        "target",
        "exit_code",
        "success",
        "packets_transmitted",
        "packets_received",
        "packet_loss_percent",
        "total_time_ms",
        "rtt_min_ms",
        "rtt_avg_ms",
        "rtt_max_ms",
        "rtt_mdev_ms",
        "command",
    ]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerow({k: row.get(k) for k in fieldnames})


def main() -> int:
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

    try:
        runtime = load_runtime_inputs()
        metadata = runtime["metadata"]
        params = validate_params(runtime["params"])
        cmd = build_ping_command(params)
        command_str = " ".join(shlex.quote(part) for part in cmd)

        write_text(COMMAND_OUT, command_str + "\n")

        metadata_json = {
            "measurement": "ping",
            **metadata,
            "params": params,
            "command": command_str,
            "input_sources": {
                "experiment_args_json_exists": ARGS_FILE.exists(),
                "experiment_config_yaml_exists": CONFIG_FILE.exists(),
            },
        }
        write_json(METADATA_JSON, metadata_json)

        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
        )

        raw_stdout = completed.stdout or ""
        raw_stderr = completed.stderr or ""

        write_text(RAW_OUT, raw_stdout)
        write_text(STDERR_OUT, raw_stderr)

        parsed = parse_ping_output(raw_stdout)

        result = {
            "measurement": "ping",
            **metadata,
            "target": params["target"],
            "exit_code": completed.returncode,
            "success": completed.returncode == 0,
            "command": command_str,
            **parsed,
        }

        write_json(RESULT_JSON, result)
        write_csv(RESULT_CSV, result)

        return completed.returncode

    except Exception as exc:
        error_text = f"{type(exc).__name__}: {exc}\n"
        write_text(STDERR_OUT, error_text)

        failure_result = {
            "measurement": "ping",
            "experiment_id": "unknown",
            "node_id": "unknown",
            "user_id": "unknown",
            "experiment_type": "unknown",
            "start_date": "",
            "end_date": "",
            "target": "",
            "exit_code": 1,
            "success": False,
            "packets_transmitted": None,
            "packets_received": None,
            "packet_loss_percent": None,
            "total_time_ms": None,
            "rtt_min_ms": None,
            "rtt_avg_ms": None,
            "rtt_max_ms": None,
            "rtt_mdev_ms": None,
            "command": "",
            "error": str(exc),
        }
        write_json(RESULT_JSON, failure_result)
        write_csv(RESULT_CSV, failure_result)
        return 1


if __name__ == "__main__":
    sys.exit(main())
