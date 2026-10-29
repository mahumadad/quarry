"""Async tool execution with task tracking.

Manages concurrent subprocess executions with budget awareness.
Uses threading (not asyncio) — the plugin runs in a sync context.
"""

import json
import subprocess
import threading
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path


class TaskState(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


@dataclass
class ToolTask:
    task_id: str = ""
    command: str = ""
    phase: str = ""
    state: str = TaskState.QUEUED.value
    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = None
    submitted_at: str = ""
    started_at: str = ""
    finished_at: str = ""
    timeout_seconds: int = 120
    error: str = ""

    def __post_init__(self):
        if not self.task_id:
            self.task_id = f"T-{uuid.uuid4().hex[:8].upper()}"
        if not self.submitted_at:
            self.submitted_at = datetime.now(timezone.utc).isoformat()


class AsyncToolRunner:
    def __init__(self, max_concurrent: int = 4, default_timeout: int = 120):
        self._tasks: dict[str, ToolTask] = {}
        self._threads: dict[str, threading.Thread] = {}
        self._events: dict[str, threading.Event] = {}
        self._semaphore = threading.Semaphore(max_concurrent)
        self._lock = threading.Lock()
        self._default_timeout = default_timeout

    def submit(self, command: str, phase: str = "",
               timeout: int | None = None) -> str:
        task = ToolTask(
            command=command,
            phase=phase,
            timeout_seconds=timeout or self._default_timeout,
        )
        event = threading.Event()
        with self._lock:
            self._tasks[task.task_id] = task
            self._events[task.task_id] = event

        thread = threading.Thread(target=self._run_task,
                                  args=(task.task_id,), daemon=True)
        self._threads[task.task_id] = thread
        thread.start()
        return task.task_id

    def _run_task(self, task_id: str):
        self._semaphore.acquire()
        try:
            with self._lock:
                task = self._tasks[task_id]
                task.state = TaskState.RUNNING.value
                task.started_at = datetime.now(timezone.utc).isoformat()
            try:
                result = subprocess.run(
                    task.command, shell=True,
                    capture_output=True, text=True,
                    timeout=task.timeout_seconds,
                )
                with self._lock:
                    task.stdout = result.stdout
                    task.stderr = result.stderr
                    task.exit_code = result.returncode
                    task.state = (TaskState.COMPLETED.value if result.returncode == 0
                                  else TaskState.FAILED.value)
            except subprocess.TimeoutExpired:
                with self._lock:
                    task.state = TaskState.TIMEOUT.value
                    task.error = f"Timeout after {task.timeout_seconds}s"
            except Exception as exc:
                with self._lock:
                    task.state = TaskState.FAILED.value
                    task.error = f"{type(exc).__name__}: {exc}"
            finally:
                with self._lock:
                    task.finished_at = datetime.now(timezone.utc).isoformat()
        finally:
            self._semaphore.release()
            self._events[task_id].set()

    def wait(self, task_id: str, timeout: float | None = None) -> ToolTask | None:
        event = self._events.get(task_id)
        if not event:
            return None
        event.wait(timeout=timeout)
        return self._tasks.get(task_id)

    def wait_any(self, task_ids: list[str], timeout: float | None = None) -> str | None:
        """Block until any of the given tasks completes. Returns its task_id."""
        result_event = threading.Event()
        completed_id: list[str] = []

        def _watcher(tid: str):
            event = self._events.get(tid)
            if event and event.wait(timeout=timeout):
                completed_id.append(tid)
                result_event.set()

        watchers = []
        for tid in task_ids:
            if self._events.get(tid) and self._events[tid].is_set():
                return tid
            t = threading.Thread(target=_watcher, args=(tid,), daemon=True)
            watchers.append(t)
            t.start()

        result_event.wait(timeout=timeout)
        return completed_id[0] if completed_id else None

    def results(self, task_id: str) -> dict | None:
        task = self._tasks.get(task_id)
        if not task:
            return None
        return asdict(task)

    def active_count(self) -> int:
        with self._lock:
            return sum(1 for t in self._tasks.values()
                       if t.state in (TaskState.QUEUED.value, TaskState.RUNNING.value))

    def summary(self) -> dict:
        with self._lock:
            by_state: dict[str, int] = {}
            for t in self._tasks.values():
                by_state[t.state] = by_state.get(t.state, 0) + 1
            return {
                "total": len(self._tasks),
                "by_state": by_state,
                "by_phase": self._count_by_phase(),
            }

    def _count_by_phase(self) -> dict[str, int]:
        by_phase: dict[str, int] = {}
        for t in self._tasks.values():
            if t.phase:
                by_phase[t.phase] = by_phase.get(t.phase, 0) + 1
        return by_phase
