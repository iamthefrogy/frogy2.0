from __future__ import annotations

import csv
import io
import json
import os
import re
import shutil
import threading
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from subprocess import PIPE, Popen
from typing import Any, Deque, Dict, List, Optional, Tuple
import zipfile

from flask import (
    Flask,
    abort,
    jsonify,
    render_template,
    request,
    send_file,
    send_from_directory,
)


BASE_DIR = Path(__file__).resolve().parent
REPO_ROOT = BASE_DIR.parent
OUTPUT_DIR = REPO_ROOT / "output"
PROJECTS_DIR = OUTPUT_DIR / "projects"
FROGY_SCRIPT = REPO_ROOT / "frogy.sh"

TOTAL_PIPELINE_STEPS = 17
MAX_LOG_LINES = 2000
QUEUE_HISTORY_LIMIT = 20

ANSI_ESCAPE_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
STEP_RE = re.compile(r"\[(\d{1,2})/(\d{1,2})\]")
RUN_DIR_RE = re.compile(r"(output/run-\d{14})/report\.html", re.IGNORECASE)
SLUG_SANITISE_RE = re.compile(r"[^a-zA-Z0-9_-]+")
DOMAIN_RE = re.compile(r"^[A-Za-z0-9.-]+$")

DATASET_FILES: Dict[str, str] = {
    "dnsx": "dnsx.json",
    "naabu": "naabu.json",
    "httpx": "httpx.json",
    "login": "login.json",
    "tls_inventory": "tls_inventory.json",
    "security_compliance": "securitycompliance.json",
    "security_headers": "sec_headers.json",
    "api_identification": "api_identification.json",
    "colleague_identification": "colleague_identification.json",
    "cloud_infrastructure": "cloud_infrastructure.json",
    "ip_enrichment": "ip_enrichment.json",
    "katana_links": "katana_links.json",
    "screenshot_map": "screenshot_map.json",
    "portscan": "portscan.json",
}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def isoformat(dt: Optional[datetime]) -> Optional[str]:
    if not dt:
        return None
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def slugify(value: str) -> str:
    value = value.strip().lower()
    value = value.replace(" ", "-")
    return SLUG_SANITISE_RE.sub("-", value) or "project"


def ensure_unique_slug(base: str) -> str:
    slug = base
    counter = 1
    while (PROJECTS_DIR / slug).exists():
        slug = f"{base}-{counter}"
        counter += 1
    return slug


def ensure_structure() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    PROJECTS_DIR.mkdir(parents=True, exist_ok=True)


def parse_targets(raw: str) -> List[str]:
    cleaned: List[str] = []
    for line in raw.splitlines():
        candidate = line.strip()
        if not candidate:
            continue
        if not DOMAIN_RE.match(candidate):
            raise ValueError(f"Invalid domain entry: {candidate}")
        cleaned.append(candidate)
    if not cleaned:
        raise ValueError("At least one valid domain is required.")
    return cleaned


def parse_iso_datetime(raw: str) -> datetime:
    normalized = raw.strip()
    if normalized.endswith("Z"):
        normalized = normalized.replace("Z", "+00:00")
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def load_metadata(project_dir: Path) -> Dict:
    meta_file = project_dir / "metadata.json"
    if meta_file.exists():
        try:
            return json.loads(meta_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
    return {}


def save_metadata(project_dir: Path, data: Dict) -> None:
    meta_file = project_dir / "metadata.json"
    meta_file.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def load_json_file(path: Path) -> Any:
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        records: List[Any] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return records


def load_run_datasets(run_dir: Path) -> Dict[str, Any]:
    datasets: Dict[str, Any] = {}
    for label, filename in DATASET_FILES.items():
        file_path = run_dir / filename
        if not file_path.exists():
            continue
        try:
            datasets[label] = load_json_file(file_path)
        except OSError:
            continue
    metadata_file = run_dir.parent / "metadata.json"
    if metadata_file.exists():
        try:
            datasets["metadata"] = json.loads(metadata_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            pass
    return datasets


def normalise_dataset_rows(label: str, data: Any) -> Tuple[List[Dict[str, Any]], List[str]]:
    if data is None:
        return [], []
    if isinstance(data, dict):
        rows: List[Dict[str, Any]] = []
        for key, value in data.items():
            if isinstance(value, list):
                for item in value:
                    rows.append(
                        {
                            "key": key,
                            "value": json.dumps(item, ensure_ascii=False, sort_keys=True) if isinstance(item, (dict, list)) else item,
                        }
                    )
            else:
                rows.append(
                    {
                        "key": key,
                        "value": json.dumps(value, ensure_ascii=False, sort_keys=True) if isinstance(value, (dict, list)) else value,
                    }
                )
        return rows, ["key", "value"]
    if isinstance(data, list):
        if not data:
            return [], []
        if all(not isinstance(item, (dict, list)) for item in data):
            return [{"value": item} for item in data], ["value"]
        rows: List[Dict[str, Any]] = []
        fieldnames: List[str] = []
        key_set = set()
        for item in data:
            if isinstance(item, dict):
                key_set.update(item.keys())
        fieldnames = sorted(key_set)
        if not fieldnames:
            fieldnames = ["value"]
            rows = [{"value": json.dumps(item, ensure_ascii=False, sort_keys=True)} for item in data]
            return rows, fieldnames
        for item in data:
            row: Dict[str, Any] = {}
            if isinstance(item, dict):
                for key in fieldnames:
                    value = item.get(key)
                    if isinstance(value, (dict, list)):
                        row[key] = json.dumps(value, ensure_ascii=False, sort_keys=True)
                    else:
                        row[key] = value
            else:
                row[fieldnames[0]] = json.dumps(item, ensure_ascii=False, sort_keys=True)
            rows.append(row)
        return rows, fieldnames
    return (
        [
            {
                "value": json.dumps(data, ensure_ascii=False, sort_keys=True)
                if isinstance(data, (dict, list))
                else data
            }
        ],
        ["value"],
    )


def build_csv_archive(datasets: Dict[str, Any]) -> io.BytesIO:
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for label, data in datasets.items():
            rows, headers = normalise_dataset_rows(label, data)
            if not rows or not headers:
                continue
            csv_buffer = io.StringIO()
            writer = csv.DictWriter(csv_buffer, fieldnames=headers)
            writer.writeheader()
            for row in rows:
                writer.writerow({key: row.get(key, "") for key in headers})
            zf.writestr(f"{label}.csv", csv_buffer.getvalue())
    archive.seek(0)
    return archive


@dataclass
class FrogyJob:
    project_name: str
    project_slug: str
    targets: List[str]
    targets_file: Path
    start_mode: str = "immediate"
    scheduled_for: Optional[datetime] = None
    id: str = field(default_factory=lambda: f"job-{datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8]}")
    created_at: datetime = field(default_factory=utc_now)
    enqueued_at: datetime = field(default_factory=utc_now)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    status: str = "pending"
    status_message: str = "Queued"
    run_dir_name: Optional[str] = None
    return_code: Optional[int] = None
    error_message: Optional[str] = None
    queue_position: Optional[int] = None
    progress_step: int = 0
    progress_total: int = TOTAL_PIPELINE_STEPS
    progress_label: str = "Queued"
    _logs: Deque[str] = field(default_factory=lambda: deque(maxlen=MAX_LOG_LINES), repr=False)
    _log_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _log_path: Optional[Path] = field(default=None, repr=False)
    _log_handle: Optional[Any] = field(default=None, repr=False, compare=False)
    process: Optional[Popen] = field(default=None, repr=False, compare=False)
    cancel_event: threading.Event = field(default_factory=threading.Event, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.scheduled_for:
            self.scheduled_for = self.scheduled_for.astimezone(timezone.utc)
        self.enqueued_at = self.created_at

    def progress_percent(self) -> int:
        if self.progress_total <= 0:
            return 0
        percent = int((self.progress_step / self.progress_total) * 100)
        return max(0, min(100, percent))

    def open_log(self, path: Path) -> None:
        self._log_path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._log_handle = path.open("a", encoding="utf-8")

    def close_log(self) -> None:
        if self._log_handle:
            self._log_handle.close()
            self._log_handle = None

    def append_log(self, line: str, stream: str = "stdout") -> None:
        cleaned = ANSI_ESCAPE_RE.sub("", line).rstrip()
        if not cleaned:
            return
        if stream == "stderr":
            cleaned = f"[stderr] {cleaned}"
        with self._log_lock:
            self._logs.append(cleaned)
        if self._log_handle:
            self._log_handle.write(cleaned + "\n")
            self._log_handle.flush()
        self._update_progress(cleaned)
        self._capture_run_dir(cleaned)

    def _update_progress(self, line: str) -> None:
        match = STEP_RE.search(line)
        if match:
            try:
                step = int(match.group(1))
                total = int(match.group(2))
            except ValueError:
                return
            self.progress_step = step
            self.progress_total = total
            label = line.split("]", 3)[-1].strip()
            if label:
                self.progress_label = label
                self.status_message = label

    def _capture_run_dir(self, line: str) -> None:
        if self.run_dir_name:
            return
        match = RUN_DIR_RE.search(line)
        if match:
            self.run_dir_name = Path(match.group(1)).name

    def get_logs(self, since: int = 0) -> Tuple[List[str], int]:
        with self._log_lock:
            logs_list = list(self._logs)
        total = len(logs_list)
        if since < 0 or since > total:
            since = 0
        return logs_list[since:], total

    def to_dict(self, *, include_logs: bool = False, queue_position: Optional[int] = None) -> Dict[str, Any]:
        progress = {
            "step": self.progress_step,
            "total": self.progress_total,
            "label": self.progress_label,
            "percent": self.progress_percent(),
        }
        data: Dict[str, Any] = {
            "id": self.id,
            "project_name": self.project_name,
            "project_slug": self.project_slug,
            "status": self.status,
            "status_message": self.status_message,
            "created_at": isoformat(self.created_at),
            "enqueued_at": isoformat(self.enqueued_at),
            "scheduled_for": isoformat(self.scheduled_for),
            "started_at": isoformat(self.started_at),
            "finished_at": isoformat(self.finished_at),
            "run_dir": self.run_dir_name,
            "return_code": self.return_code,
            "error_message": self.error_message,
            "progress": progress,
        }
        if queue_position is not None:
            data["queue_position"] = queue_position
        if include_logs:
            logs, total = self.get_logs()
            data["logs"] = logs
            data["cursor"] = total
        return data


class JobManager:
    def __init__(self, max_workers: int, record_callback):
        self.max_workers = max(1, max_workers)
        self.record_callback = record_callback
        self.lock = threading.Lock()
        self.running: Dict[str, FrogyJob] = {}
        self.queue: List[FrogyJob] = []
        self.recent: Deque[FrogyJob] = deque(maxlen=QUEUE_HISTORY_LIMIT)
        self.event = threading.Event()
        self.scheduler_thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        self.scheduler_thread.start()

    def submit(self, job: FrogyJob, start_mode: str) -> Tuple[FrogyJob, str]:
        now = utc_now()
        with self.lock:
            job.start_mode = start_mode
            if (
                start_mode == "immediate"
                and (job.scheduled_for is None or job.scheduled_for <= now)
                and len(self.running) < self.max_workers
            ):
                self._start_job_locked(job)
                return job, "Run started immediately."

            if job.scheduled_for and job.scheduled_for > now:
                job.status = "scheduled"
                job.status_message = f"Scheduled for {isoformat(job.scheduled_for)}"
            else:
                job.status = "queued"
                job.status_message = "Queued; waiting for an available slot."

            self.queue.append(job)
            self._sort_queue_locked()
            self._update_queue_positions_locked()
            message = self._queue_message(job)
            self.event.set()
            return job, message

    def snapshot(self) -> Dict[str, Any]:
        with self.lock:
            running = [job.to_dict() for job in self.running.values()]
            queued = [job.to_dict(queue_position=index + 1) for index, job in enumerate(self.queue)]
            recent = [job.to_dict() for job in list(self.recent)]
            stats = {
                "max_concurrent": self.max_workers,
                "running": len(self.running),
                "queued": len(self.queue),
            }
        return {
            "timestamp": isoformat(utc_now()),
            "running": running,
            "queued": queued,
            "recent": recent,
            "stats": stats,
        }

    def active_status_for_slug(self, slug: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            for job in self.running.values():
                if job.project_slug == slug:
                    return job.to_dict()
            for index, job in enumerate(self.queue, start=1):
                if job.project_slug == slug:
                    info = job.to_dict(queue_position=index)
                    info["status"] = "queued"
                    info["status_message"] = job.status_message or "Queued"
                    return info
        return None

    def has_active_job(self, slug: str) -> bool:
        return self.active_status_for_slug(slug) is not None

    def cancel_pending(self, slug: str) -> int:
        removed = 0
        with self.lock:
            new_queue: List[FrogyJob] = []
            for job in self.queue:
                if job.project_slug == slug:
                    removed += 1
                    continue
                new_queue.append(job)
            if removed:
                self.queue = new_queue
                self._update_queue_positions_locked()
                self.event.set()
        return removed

    def cancel_job(self, slug: str) -> Tuple[bool, str]:
        with self.lock:
            running_job = None
            for job in self.running.values():
                if job.project_slug == slug:
                    running_job = job
                    break
            if running_job:
                running_job.cancel_event.set()
                proc = running_job.process
                if proc and proc.poll() is None:
                    try:
                        proc.terminate()
                    except Exception:
                        pass
                running_job.status_message = "Cancellation requested..."
                self.event.set()
                return True, "Cancellation requested."

            for idx, job in enumerate(self.queue):
                if job.project_slug == slug:
                    cancelled_job = self.queue.pop(idx)
                    self._update_queue_positions_locked()
                    cancelled_job.status = "cancelled"
                    cancelled_job.status_message = "Run cancelled before start."
                    self.recent.appendleft(cancelled_job)
                    self.event.set()
                    return True, "Queued run removed."

        return False, "No active or queued run found."

    def _queue_message(self, job: FrogyJob) -> str:
        if job.status == "scheduled" and job.scheduled_for:
            return f"Run scheduled for {isoformat(job.scheduled_for)}."
        position = job.queue_position or self.queue.index(job) + 1
        return f"Run queued in position {position}."

    def _sort_queue_locked(self) -> None:
        self.queue.sort(key=lambda job: ((job.scheduled_for or job.enqueued_at), job.enqueued_at))

    def _update_queue_positions_locked(self) -> None:
        for idx, job in enumerate(self.queue, start=1):
            job.queue_position = idx

    def _scheduler_loop(self) -> None:
        while True:
            job_to_start: Optional[FrogyJob] = None
            wait_timeout: Optional[float] = None

            with self.lock:
                self._sort_queue_locked()
                self._update_queue_positions_locked()
                if len(self.running) < self.max_workers:
                    job_to_start = self._pop_ready_job_locked()
                if job_to_start:
                    self._start_job_locked(job_to_start)
                    continue
                wait_timeout = self._next_timeout_locked()

            self.event.wait(timeout=wait_timeout)
            self.event.clear()

    def _pop_ready_job_locked(self) -> Optional[FrogyJob]:
        now = utc_now()
        for index, job in enumerate(self.queue):
            if job.scheduled_for and job.scheduled_for > now:
                continue
            ready_job = self.queue.pop(index)
            self._update_queue_positions_locked()
            return ready_job
        return None

    def _next_timeout_locked(self) -> Optional[float]:
        now = utc_now()
        future_times = [
            (job.scheduled_for - now).total_seconds()
            for job in self.queue
            if job.scheduled_for and job.scheduled_for > now
        ]
        if not future_times:
            return None
        timeout = max(0.0, min(future_times))
        return timeout if timeout > 0 else 0.5

    def _start_job_locked(self, job: FrogyJob) -> None:
        job.status = "running"
        job.status_message = "frogy.sh started"
        job.started_at = utc_now()
        job.queue_position = None
        worker = threading.Thread(target=self._run_job, args=(job,), daemon=True)
        self.running[job.id] = job
        worker.start()

    def _run_job(self, job: FrogyJob) -> None:
        project_dir = PROJECTS_DIR / job.project_slug
        project_dir.mkdir(parents=True, exist_ok=True)
        existing_runs = {p.name for p in OUTPUT_DIR.glob("run-*") if p.is_dir()}
        inflight_log = project_dir / "logs" / f"{job.id}.log"
        final_log_path: Optional[Path] = None

        try:
            job.open_log(inflight_log)
            env = os.environ.copy()
            cmd = ["bash", str(FROGY_SCRIPT), str(job.targets_file)]

            def stream_reader(pipe, tag: str) -> None:
                try:
                    for chunk in iter(pipe.readline, ""):
                        job.append_log(chunk, stream=tag)
                finally:
                    pipe.close()

            with Popen(
                cmd,
                cwd=str(REPO_ROOT),
                stdout=PIPE,
                stderr=PIPE,
                text=True,
                bufsize=1,
                env=env,
            ) as proc:
                job.process = proc
                job.cancel_event.clear()
                stdout_thread = threading.Thread(target=stream_reader, args=(proc.stdout, "stdout"), daemon=True)
                stderr_thread = threading.Thread(target=stream_reader, args=(proc.stderr, "stderr"), daemon=True)
                stdout_thread.start()
                stderr_thread.start()
                return_code = proc.wait()
                stdout_thread.join(timeout=2)
                stderr_thread.join(timeout=2)
            job.process = None

            job.return_code = return_code
            job.finished_at = utc_now()
            job.close_log()
            final_log_path = self._finalize_run(job, project_dir, existing_runs, inflight_log)

            if job.cancel_event.is_set():
                job.status = "cancelled"
                job.status_message = "Run cancelled by user."
                job.error_message = "Run cancelled by user."
                self.record_callback(job, "cancelled", job.error_message, final_log_path)
            elif return_code == 0:
                job.status = "succeeded"
                job.status_message = "Run completed successfully."
                job.progress_step = job.progress_total
                job.error_message = None
                self.record_callback(job, "succeeded", None, final_log_path)
            else:
                job.status = "failed"
                job.status_message = f"Run failed with exit code {return_code}."
                job.error_message = f"frogy.sh exited with {return_code}."
                self.record_callback(job, "failed", job.error_message, final_log_path)

        except Exception as exc:  # pylint: disable=broad-except
            job.error_message = str(exc)
            job.status = "failed"
            job.status_message = "Run failed unexpectedly."
            job.finished_at = job.finished_at or utc_now()
            try:
                job.close_log()
            except Exception:
                pass
            final_log_path = inflight_log if inflight_log.exists() else None
            self.record_callback(job, "failed", job.error_message, final_log_path)

        finally:
            with self.lock:
                self.running.pop(job.id, None)
                self.recent.appendleft(job)
                self._update_queue_positions_locked()
            self.event.set()

    def _finalize_run(
        self,
        job: FrogyJob,
        project_dir: Path,
        existing_runs: set[str],
        inflight_log: Path,
    ) -> Optional[Path]:
        new_runs = {p.name for p in OUTPUT_DIR.glob("run-*") if p.is_dir()} - existing_runs
        if job.run_dir_name is None:
            if len(new_runs) == 1:
                job.run_dir_name = new_runs.pop()
            elif len(new_runs) > 1:
                job.error_message = "Multiple run directories detected; unable to determine which to archive."
            else:
                job.error_message = job.error_message or "Run directory could not be determined."

        final_log_path: Optional[Path] = None
        if job.run_dir_name:
            run_src = OUTPUT_DIR / job.run_dir_name
            run_dst = project_dir / job.run_dir_name
            if run_src.exists():
                run_dst.parent.mkdir(parents=True, exist_ok=True)
                if not run_dst.exists():
                    shutil.move(str(run_src), str(run_dst))
            final_log_path = project_dir / "logs" / f"{job.run_dir_name}.log"
        elif inflight_log.exists():
            final_log_path = inflight_log

        if inflight_log.exists() and final_log_path:
            if final_log_path != inflight_log:
                final_log_path.parent.mkdir(parents=True, exist_ok=True)
                try:
                    inflight_log.rename(final_log_path)
                except OSError:
                    final_log_path = inflight_log
        return final_log_path


def create_app() -> Flask:
    ensure_structure()
    app = Flask(
        __name__,
        template_folder=str(BASE_DIR / "templates"),
        static_folder=str(BASE_DIR / "static"),
    )

    def projects_overview() -> List[Dict]:
        projects: List[Dict] = []
        for project_dir in sorted(PROJECTS_DIR.glob("*")):
            if not project_dir.is_dir():
                continue
            slug = project_dir.name
            metadata = load_metadata(project_dir)
            display_name = metadata.get("name") or slug
            runs_meta = metadata.get("runs") or []
            runs: List[Dict] = []
            for run in runs_meta:
                run_id = run.get("id")
                exists = False
                if run_id:
                    exists = (project_dir / run_id).is_dir()
                runs.append(
                    {
                        "id": run_id,
                        "exists": exists,
                        "status": run.get("status", "unknown"),
                        "started_at": run.get("started_at"),
                        "completed_at": run.get("completed_at"),
                        "error": run.get("error"),
                        "report_path": f"/projects/{slug}/runs/{run_id}/report" if run_id and exists else None,
                    }
                )
            projects.append(
                {
                    "name": display_name,
                    "slug": slug,
                    "runs": runs,
                    "created_at": metadata.get("created_at"),
                }
            )
        return projects

    def record_run(job: FrogyJob, status: str, error: Optional[str], log_path: Optional[Path]) -> None:
        project_dir = PROJECTS_DIR / job.project_slug
        project_dir.mkdir(parents=True, exist_ok=True)
        metadata = load_metadata(project_dir)
        metadata.setdefault("name", job.project_name)
        metadata.setdefault("slug", job.project_slug)
        metadata.setdefault("created_at", isoformat(job.created_at))
        runs: List[Dict] = metadata.setdefault("runs", [])

        run_identifier = job.run_dir_name or f"incomplete-{job.id}"
        try:
            targets_rel = str(job.targets_file.relative_to(project_dir))
        except ValueError:
            targets_rel = str(job.targets_file)

        entry: Dict = {
            "id": run_identifier,
            "status": status,
            "started_at": isoformat(job.started_at or job.created_at),
            "completed_at": isoformat(job.finished_at or utc_now()),
            "targets_file": targets_rel,
        }
        if log_path:
            try:
                entry["log_file"] = str(log_path.relative_to(project_dir))
            except ValueError:
                entry["log_file"] = str(log_path)
        if error:
            entry["error"] = error
        entry["report"] = f"runs/{job.run_dir_name}/report.html" if job.run_dir_name else None
        runs.append(entry)
        runs.sort(key=lambda item: item.get("started_at", ""), reverse=True)
        metadata["last_run"] = {
            "id": run_identifier,
            "status": status,
            "started_at": entry["started_at"],
            "completed_at": entry["completed_at"],
            "report": entry["report"],
            "error": error,
        }
        metadata["latest_targets"] = job.targets
        save_metadata(project_dir, metadata)

    max_concurrent = max(1, int(os.getenv("FROGY_MAX_CONCURRENT", "1")))
    manager = JobManager(max_concurrent, record_run)
    app.config["JOB_MANAGER"] = manager

    def load_project_metadata(slug: str) -> Dict:
        project_dir = PROJECTS_DIR / slug
        if not project_dir.is_dir():
            raise FileNotFoundError(f"Project '{slug}' not found.")
        metadata = load_metadata(project_dir)
        metadata.setdefault("name", slug)
        metadata.setdefault("slug", slug)
        metadata.setdefault("runs", [])
        metadata.setdefault("created_at", metadata.get("created_at") or isoformat(utc_now()))
        latest_targets = metadata.get("latest_targets")
        if isinstance(latest_targets, str):
            latest_targets = [line.strip() for line in latest_targets.splitlines() if line.strip()]
            metadata["latest_targets"] = latest_targets
        elif latest_targets is None:
            metadata["latest_targets"] = []
        return metadata

    def assemble_scan_rows() -> List[Dict[str, Any]]:
        snapshot = manager.snapshot()
        running_map: Dict[str, Dict[str, Any]] = {}
        queued_map: Dict[str, Dict[str, Any]] = {}
        for job in snapshot.get("running", []):
            running_map[job["project_slug"]] = job
        for job in snapshot.get("queued", []):
            queued_map[job["project_slug"]] = job
            running_map.setdefault(job["project_slug"], job)

        rows: List[Dict[str, Any]] = []
        for project_dir in sorted(PROJECTS_DIR.glob("*")):
            if not project_dir.is_dir():
                continue
            slug = project_dir.name
            metadata = load_project_metadata(slug)
            name = metadata.get("name") or slug
            latest_targets = metadata.get("latest_targets") or []
            if isinstance(latest_targets, str):
                targets_list = [line.strip() for line in latest_targets.splitlines() if line.strip()]
            else:
                targets_list = list(latest_targets)
            targets_text = "\n".join(targets_list)

            last_run = metadata.get("last_run") or {}
            status = "never"
            status_message = "No run recorded yet."
            ran_at = last_run.get("completed_at") or last_run.get("started_at")
            report = None
            run_id = last_run.get("id")
            queue_position = None
            scheduled_for_display = None
            progress = {
                "percent": 0,
                "step": 0,
                "total": TOTAL_PIPELINE_STEPS,
                "label": "Not started",
            }

            if run_id and last_run.get("status") == "succeeded":
                report_rel = last_run.get("report")
                if report_rel:
                    report = f"/projects/{slug}/{report_rel}"

            active = running_map.get(slug)
            if active:
                status = active.get("status", "queued")
                status_message = active.get("status_message") or status.capitalize()
                ran_at = active.get("started_at") or active.get("enqueued_at") or ran_at
                queue_position = active.get("queue_position")
                raw_scheduled = active.get("scheduled_for")
                if raw_scheduled:
                    scheduled_for_display = format_status_time(raw_scheduled)
                progress_payload = active.get("progress") or {}
                prog_step = progress_payload.get("step") or 0
                prog_total = progress_payload.get("total") or TOTAL_PIPELINE_STEPS
                prog_percent = progress_payload.get("percent")
                if prog_percent is None and prog_total:
                    prog_percent = int((prog_step / prog_total) * 100)
                progress_label = progress_payload.get("label") or status_message
                progress = {
                    "percent": max(0, min(100, prog_percent or 0)),
                    "step": prog_step,
                    "total": prog_total,
                    "label": progress_label,
                }
                if status == "queued" and queue_position:
                    status_message = f"In queue (#{queue_position})"
                elif status == "scheduled" and scheduled_for_display:
                    status_message = f"Scheduled for {scheduled_for_display}"
                report = None
                run_id = active.get("run_dir") or run_id
            elif last_run:
                status = last_run.get("status", "unknown")
                if status == "succeeded":
                    status_message = "Run completed successfully."
                    progress = {
                        "percent": 100,
                        "step": TOTAL_PIPELINE_STEPS,
                        "total": TOTAL_PIPELINE_STEPS,
                        "label": "Completed",
                    }
                elif status == "failed":
                    status_message = last_run.get("error") or "Run failed."
                    progress = {
                        "percent": 0,
                        "step": 0,
                        "total": TOTAL_PIPELINE_STEPS,
                        "label": "Failed",
                    }
                else:
                    status_message = status.capitalize()

            queued = queued_map.get(slug)
            if queued and not active:
                queue_position = queued.get("queue_position")
                raw_scheduled = queued.get("scheduled_for")
                if raw_scheduled:
                    scheduled_for_display = format_status_time(raw_scheduled)

            rows.append(
                {
                    "slug": slug,
                    "name": name,
                    "targets": targets_text,
                    "targets_count": len(targets_list),
                    "targets_preview": targets_list[:5],
                    "status": status,
                    "status_message": status_message,
                    "ran_at": ran_at,
                    "report": report,
                    "run_id": run_id,
                    "created_at": metadata.get("created_at"),
                    "queue_position": queue_position,
                    "scheduled_for": scheduled_for_display,
                    "progress": progress,
                    "locked": manager.has_active_job(slug),
                    "is_running": status == "running",
                    "is_queued": status == "queued",
                    "is_scheduled": status == "scheduled",
                }
            )

        rows.sort(key=lambda row: row.get("ran_at") or row.get("created_at") or "", reverse=True)
        for index, row in enumerate(rows, start=1):
            row["index"] = index
        return rows

    def format_status_time(value: Optional[str]) -> str:
        if not value:
            return ""
        try:
            dt = parse_iso_datetime(value) if isinstance(value, str) else value
        except Exception:  # pylint: disable=broad-except
            return str(value)
        local_dt = dt.astimezone()
        return local_dt.strftime("%Y-%m-%d %H:%M %Z")

    def write_targets_file(project_dir: Path, targets: List[str]) -> Path:
        targets_dir = project_dir / "targets"
        targets_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        targets_file = targets_dir / f"targets-{timestamp}.txt"
        targets_file.write_text("\n".join(targets) + "\n", encoding="utf-8")
        return targets_file

    def submit_scan_job(
        project_name: str,
        project_slug: str,
        targets: List[str],
        targets_file: Path,
        start_mode: str,
        scheduled_for: Optional[datetime],
    ) -> Tuple[FrogyJob, str]:
        job = FrogyJob(
            project_name=project_name,
            project_slug=project_slug,
            targets=targets,
            targets_file=targets_file,
            start_mode=start_mode,
            scheduled_for=scheduled_for,
        )
        job.status = "pending"
        job.status_message = "Queued"
        return manager.submit(job, start_mode)

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/api/status", methods=["GET"])
    def api_status():
        return jsonify(manager.snapshot())

    @app.route("/api/scans", methods=["GET"])
    def api_scans():
        return jsonify({"scans": assemble_scan_rows(), "timestamp": isoformat(utc_now())})

    @app.route("/api/scans", methods=["POST"])
    def api_create_scan():
        payload = request.get_json(force=True, silent=False) or {}
        project_name = (payload.get("project_name") or "").strip()
        targets_raw = payload.get("targets") or ""
        start_mode = (payload.get("start_mode") or "immediate").strip().lower()
        scheduled_raw = (payload.get("scheduled_for") or "").strip()

        if not project_name:
            return jsonify({"error": "Company name is required."}), 400
        if start_mode not in {"immediate", "queue", "schedule", "none"}:
            return jsonify({"error": "start_mode must be run-now, queue, schedule, or none."}), 400

        try:
            targets = parse_targets(targets_raw)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        scheduled_for: Optional[datetime] = None
        if scheduled_raw:
            try:
                scheduled_for = parse_iso_datetime(scheduled_raw)
            except ValueError:
                return jsonify({"error": "scheduled_for must be a valid ISO-8601 datetime."}), 400
        if start_mode == "schedule" and not scheduled_for:
            return jsonify({"error": "scheduled_for is required when start_mode is schedule."}), 400
        if scheduled_for and scheduled_for < utc_now():
            return jsonify({"error": "scheduled_for must be in the future."}), 400

        base_slug = slugify(project_name)
        slug = ensure_unique_slug(base_slug)
        project_dir = PROJECTS_DIR / slug
        project_dir.mkdir(parents=True, exist_ok=False)

        metadata = {
            "name": project_name,
            "slug": slug,
            "created_at": isoformat(utc_now()),
            "latest_targets": targets,
            "runs": [],
        }
        save_metadata(project_dir, metadata)

        targets_file = write_targets_file(project_dir, targets)
        job_info = None
        message = "Scan saved."

        if start_mode in {"immediate", "queue", "schedule"}:
            job, message = submit_scan_job(project_name, slug, targets, targets_file, start_mode, scheduled_for)
            job_info = job.to_dict()

        metadata["latest_targets"] = targets
        save_metadata(project_dir, metadata)

        rows = assemble_scan_rows()
        scan_row = next((row for row in rows if row["slug"] == slug), None)
        response = {"message": message, "scan": scan_row, "slug": slug}
        if job_info:
            response["job"] = job_info
        return jsonify(response), 201 if start_mode == "immediate" else 202

    @app.route("/api/scans/<slug>", methods=["PUT"])
    def api_update_scan(slug: str):
        payload = request.get_json(force=True, silent=False) or {}
        project_name = (payload.get("project_name") or "").strip()
        targets_raw = payload.get("targets") or ""
        start_mode = (payload.get("start_mode") or "none").strip().lower()
        scheduled_raw = (payload.get("scheduled_for") or "").strip()

        if not project_name:
            return jsonify({"error": "Company name is required."}), 400
        if start_mode not in {"immediate", "queue", "schedule", "none"}:
            return jsonify({"error": "start_mode must be run-now, queue, schedule, or none."}), 400

        try:
            targets = parse_targets(targets_raw)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        scheduled_for: Optional[datetime] = None
        if scheduled_raw:
            try:
                scheduled_for = parse_iso_datetime(scheduled_raw)
            except ValueError:
                return jsonify({"error": "scheduled_for must be a valid ISO-8601 datetime."}), 400
        if start_mode == "schedule" and not scheduled_for:
            return jsonify({"error": "scheduled_for is required when start_mode is schedule."}), 400
        if scheduled_for and scheduled_for < utc_now():
            return jsonify({"error": "scheduled_for must be in the future."}), 400

        try:
            metadata = load_project_metadata(slug)
        except FileNotFoundError:
            return jsonify({"error": f"Scan '{slug}' not found."}), 404

        if manager.has_active_job(slug):
            return jsonify({"error": "Cannot modify scan while a run is active or queued."}), 409

        new_slug = slugify(project_name)
        if new_slug != slug:
            if (PROJECTS_DIR / new_slug).exists():
                return jsonify({"error": "Another scan already uses that name. Choose a different company name."}), 409
            (PROJECTS_DIR / slug).rename(PROJECTS_DIR / new_slug)
            slug = new_slug

        project_dir = PROJECTS_DIR / slug
        metadata["name"] = project_name
        metadata["slug"] = slug
        metadata["latest_targets"] = targets
        save_metadata(project_dir, metadata)

        targets_file = write_targets_file(project_dir, targets)

        message = "Scan updated."
        job_info = None
        if start_mode in {"immediate", "queue", "schedule"}:
            job, message = submit_scan_job(project_name, slug, targets, targets_file, start_mode, scheduled_for)
            job_info = job.to_dict()

        save_metadata(project_dir, metadata)

        rows = assemble_scan_rows()
        scan_row = next((row for row in rows if row["slug"] == slug), None)
        response = {"message": message, "scan": scan_row, "slug": slug}
        if job_info:
            response["job"] = job_info
        return jsonify(response)

    @app.route("/api/scans/<slug>", methods=["DELETE"])
    def api_delete_scan(slug: str):
        project_dir = PROJECTS_DIR / slug
        if not project_dir.is_dir():
            return jsonify({"error": f"Scan '{slug}' not found."}), 404

        if manager.has_active_job(slug):
            return jsonify({"error": "Cannot delete while a run is active or queued."}), 409

        removed = manager.cancel_pending(slug)
        try:
            shutil.rmtree(project_dir)
        except OSError as exc:
            return jsonify({"error": f"Failed to delete scan directory: {exc}"}), 500

        message = "Scan deleted."
        if removed:
            message = f"Scan deleted and {removed} queued job(s) removed."
        return jsonify({"message": message})

    @app.route("/projects/<slug>/runs/<run_id>/download/json", methods=["GET"])
    def download_run_json(slug: str, run_id: str):
        run_dir = (PROJECTS_DIR / slug / run_id).resolve()
        expected = (PROJECTS_DIR / slug).resolve()
        if not expected.exists() or not run_dir.is_dir():
            abort(404, description=f"{run_id} folder was deleted or not found.")
        if expected not in run_dir.parents and run_dir != expected:
            abort(404, description="Invalid run path.")

        datasets = load_run_datasets(run_dir)
        payload = {
            "project": slug,
            "run_id": run_id,
            "generated_at": isoformat(utc_now()),
            "datasets": datasets,
        }
        buffer = io.BytesIO(json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8"))
        buffer.seek(0)
        filename = f"{slug}-{run_id}.json"
        return send_file(buffer, mimetype="application/json", as_attachment=True, download_name=filename)

    @app.route("/projects/<slug>/runs/<run_id>/download/csv", methods=["GET"])
    def download_run_csv(slug: str, run_id: str):
        run_dir = (PROJECTS_DIR / slug / run_id).resolve()
        expected = (PROJECTS_DIR / slug).resolve()
        if not expected.exists() or not run_dir.is_dir():
            abort(404, description=f"{run_id} folder was deleted or not found.")
        if expected not in run_dir.parents and run_dir != expected:
            abort(404, description="Invalid run path.")

        datasets = load_run_datasets(run_dir)
        archive = build_csv_archive(datasets)
        filename = f"{slug}-{run_id}-datasets.zip"
        return send_file(archive, mimetype="application/zip", as_attachment=True, download_name=filename)

    @app.route("/api/scans/<slug>/cancel", methods=["POST"])
    def api_cancel_scan(slug: str):
        success, message = manager.cancel_job(slug)
        if not success:
            return jsonify({"error": message}), 404
        rows = assemble_scan_rows()
        scan_row = next((row for row in rows if row["slug"] == slug), None)
        return jsonify({"message": message, "scan": scan_row})

    @app.route("/api/scans/bulk-delete", methods=["POST"])
    def api_bulk_delete():
        payload = request.get_json(force=True, silent=False) or {}
        slugs = payload.get("slugs") or []
        if not isinstance(slugs, list) or not slugs:
            return jsonify({"error": "Provide a non-empty 'slugs' array."}), 400

        deleted: List[str] = []
        blocked: List[str] = []
        errors: Dict[str, str] = {}

        for raw_slug in slugs:
            slug = str(raw_slug)
            project_dir = PROJECTS_DIR / slug
            if not project_dir.is_dir():
                errors[slug] = "Not found."
                continue
            if manager.has_active_job(slug):
                blocked.append(slug)
                continue
            manager.cancel_pending(slug)
            try:
                shutil.rmtree(project_dir)
                deleted.append(slug)
            except OSError as exc:
                errors[slug] = f"Deletion failed: {exc}"

        message_parts: List[str] = []
        if deleted:
            message_parts.append(f"Deleted {len(deleted)} scan(s).")
        if blocked:
            message_parts.append(f"{len(blocked)} scan(s) are running or queued and were skipped.")
        if errors:
            message_parts.append(f"{len(errors)} scan(s) returned errors.")
        if not message_parts:
            message_parts.append("No scans deleted.")

        return jsonify(
            {
                "deleted": deleted,
                "blocked": blocked,
                "errors": errors,
                "message": " ".join(message_parts),
            }
        )

    @app.route("/api/scans/<slug>/rescan", methods=["POST"])
    def api_rescan(slug: str):
        try:
            metadata = load_project_metadata(slug)
        except FileNotFoundError:
            return jsonify({"error": f"Scan '{slug}' not found."}), 404

        if manager.has_active_job(slug):
            return jsonify({"error": "Scan already running or queued."}), 409

        targets = metadata.get("latest_targets") or []
        if isinstance(targets, str):
            targets = [line.strip() for line in targets.splitlines() if line.strip()]
        if not targets:
            return jsonify({"error": "No target list saved for this scan."}), 400

        project_dir = PROJECTS_DIR / slug
        project_dir.mkdir(parents=True, exist_ok=True)
        targets_file = write_targets_file(project_dir, targets)

        job, message = submit_scan_job(metadata.get("name", slug), slug, targets, targets_file, "immediate", None)
        rows = assemble_scan_rows()
        scan_row = next((row for row in rows if row["slug"] == slug), None)
        return jsonify({"message": message, "scan": scan_row, "job": job.to_dict()})

    @app.route("/projects/<slug>/runs/<run_id>/report", methods=["GET"])
    def serve_report(slug: str, run_id: str):
        run_dir = (PROJECTS_DIR / slug / run_id).resolve()
        expected = (PROJECTS_DIR / slug).resolve()
        if not expected.exists() or not run_dir.is_dir():
            abort(404, description=f"{run_id} folder was deleted or not found.")
        if expected not in run_dir.parents and run_dir != expected:
            abort(404, description="Invalid run path.")
        report_file = run_dir / "report.html"
        if not report_file.exists():
            abort(404, description="report.html not found in selected run.")
        return send_from_directory(run_dir, "report.html")

    @app.route("/projects/<slug>/runs/<run_id>/<path:asset_path>", methods=["GET"])
    def serve_run_asset(slug: str, run_id: str, asset_path: str):
        run_dir = (PROJECTS_DIR / slug / run_id).resolve()
        expected = (PROJECTS_DIR / slug).resolve()
        if not expected.exists() or not run_dir.is_dir():
            abort(404, description=f"{run_id} folder was deleted or not found.")
        if expected not in run_dir.parents and run_dir != expected:
            abort(404, description="Invalid run path.")
        target = run_dir / asset_path
        if not target.exists():
            abort(404, description=f"{asset_path} not found within run {run_id}.")
        return send_from_directory(run_dir, asset_path)

    return app
