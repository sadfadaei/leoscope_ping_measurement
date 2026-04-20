import csv
import json
import re
import shlex
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import yaml


ARTIFACTS_DIR = Path("/artifacts")
RESULTS_DIR = ARTIFACTS_DIR / "execution_results"

ARGS_FILE = ARTIFACTS_DIR / "experiment-args.json"
CONFIG_FILE = ARTIFACTS_DIR / "experiment-config.yaml"

LOG_FILE = RESULTS_DIR / "container.log"
RAW_OUT = RESULTS_DIR / "ping.raw.txt"
STDERR_OUT = RESULTS_DIR / "ping.stderr.txt"
COMMAND_OUT = RESULTS_DIR / "ping.command.txt"
RESULT_JSON = RESULTS_DIR / "ping.result.json"
RESULT_CSV = RESULTS_DIR / "ping.result.csv"
METADATA_JSON = RESULTS_DIR / "ping.metadata.json"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def write_log_line(line: str):
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def log(message: str):
    line = f"[LEOSCOPE][INFO] {utc_now_iso()} - {message}"
    print(line, flush=True)
    write_log_line(line)


def log_error(message: str):
    line = f"[LEOSCOPE][ERROR] {utc_now_iso()} - {message}"
    print(line, file=sys.stderr, flush=True)
    write_log_line(line)


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


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
    metadata: Dict[str, Any] = {
        "experiment_id": "unknown",
        "node_id": "unknown",
        "user_id": "unknown",
        "experiment_type": "unknown",
        "start_date": "",
        "end_date": "",
    }
    params: Dict[str, Any] = {}

    args_exists = ARGS_FILE.exists()
    yaml_exists = CONFIG_FILE.exists()

    if args_exists:
        args = load_json(ARGS_FILE)
        metadata = {
            "experiment_id": args.get("id", "unknown"),
            "node_id": args.get("nodeid", "unknown"),
            "user_id": args.get("userid", "unknown"),
            "experiment_type": args.get("type", "unknown"),
            "start_date": args.get("startDate", ""),
            "end_date": args.get("endDate", ""),
        }

    if yaml_exists:
        config = load_yaml(CONFIG_FILE)
        yaml_params = extract_from_config_yaml(config)
        if isinstance(yaml_params, dict):
            params.update(yaml_params)

    return {
        "metadata": metadata,
        "params": params,
        "input_sources": {
            "experiment_args_json_exists": args_exists,
            "experiment_config_yaml_exists": yaml_exists,
            "params_source": "experiment-config.yaml" if params else "defaults",
            "metadata_source": "experiment-args.json" if args_exists else "defaults",
        },
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
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerow({k: row.get(k) for k in fieldnames})


def build_failure_result(error_message: str) -> Dict[str, Any]:
    return {
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
        "error": error_message,
    }


def main() -> int:
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    log("Starting ping measurement")
    
    if LOG_FILE.exists():
        LOG_FILE.unlink()

    try:
        runtime = load_runtime_inputs()
        metadata = runtime["metadata"]
        params = validate_params(runtime["params"])
        input_sources = runtime["input_sources"]

        log(f"Using experiment-args.json: {input_sources['experiment_args_json_exists']}")
        log(f"Using experiment-config.yaml: {input_sources['experiment_config_yaml_exists']}")
        log(f"Resolved params source: {input_sources['params_source']}")

        log(f"Target: {params['target']}")
        log(f"Count: {params['count']}, Interval: {params['interval']}")

        cmd = build_ping_command(params)
        command_str = " ".join(shlex.quote(part) for part in cmd)

        log(f"Executing command: {command_str}")
        write_text(COMMAND_OUT, command_str + "\n")

        metadata_json = {
            "measurement": "ping",
            **metadata,
            "params": params,
            "command": command_str,
            "input_sources": input_sources,
            "results_directory": str(RESULTS_DIR),
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

        log(f"Execution finished with exit code: {completed.returncode}")

        parsed = parse_ping_output(raw_stdout)
        log("Parsing ping output completed")

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

        log(f"Results written to: {RESULTS_DIR}")

        if completed.returncode == 0:
            log("Measurement completed successfully")
        else:
            log_error("Measurement failed")

        return completed.returncode

    except Exception as exc:
        error_text = f"{type(exc).__name__}: {exc}"
        log_error(error_text)

        write_text(STDERR_OUT, error_text + "\n")

        failure_result = build_failure_result(str(exc))
        write_json(RESULT_JSON, failure_result)
        write_csv(RESULT_CSV, failure_result)

        return 1


if __name__ == "__main__":
    sys.exit(main())
