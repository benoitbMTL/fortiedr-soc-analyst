from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from fortiedr_mcp.errors import FortiEDRPersistenceError
from fortiedr_mcp.models import AnalysisRunRecord


class AnalysisRunRepository:
    """SQLite-backed storage for persisted analysis runs."""

    def __init__(self, database_path: str | Path):
        self._database_path = Path(database_path)
        self._database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_schema()

    @property
    def database_path(self) -> Path:
        return self._database_path

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._database_path, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize_schema(self) -> None:
        ddl = """
        CREATE TABLE IF NOT EXISTS analysis_runs (
            run_id TEXT PRIMARY KEY,
            incident_id TEXT NOT NULL,
            skill_name TEXT NOT NULL,
            skill_version TEXT NOT NULL,
            llm_provider TEXT,
            model_name TEXT,
            status TEXT NOT NULL,
            validation_status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            completed_at TEXT,
            idempotency_key TEXT NOT NULL,
            source_fingerprint TEXT,
            record_json TEXT NOT NULL
        );
        """
        try:
            with self._connect() as connection:
                connection.executescript(ddl)
                existing_columns = {
                    row["name"]
                    for row in connection.execute("PRAGMA table_info(analysis_runs)").fetchall()
                }
                if "source_fingerprint" not in existing_columns:
                    connection.execute("ALTER TABLE analysis_runs ADD COLUMN source_fingerprint TEXT")

                connection.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_analysis_runs_incident_created
                        ON analysis_runs (incident_id, created_at DESC)
                    """
                )
                connection.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_analysis_runs_incident_success
                        ON analysis_runs (incident_id, status, completed_at DESC)
                    """
                )
                connection.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_analysis_runs_incident_idempotency
                        ON analysis_runs (
                            incident_id,
                            idempotency_key,
                            source_fingerprint,
                            status,
                            completed_at DESC
                        )
                    """
                )
        except sqlite3.Error as exc:
            raise FortiEDRPersistenceError("Failed to initialize the analysis run database.") from exc

    @staticmethod
    def _deserialize_row(row: sqlite3.Row | None) -> AnalysisRunRecord | None:
        if row is None:
            return None
        payload = json.loads(row["record_json"])
        return AnalysisRunRecord.model_validate(payload)

    def save_run(self, run: AnalysisRunRecord) -> AnalysisRunRecord:
        payload = run.model_dump(mode="json")
        query = """
        INSERT INTO analysis_runs (
            run_id,
            incident_id,
            skill_name,
            skill_version,
            llm_provider,
            model_name,
            status,
            validation_status,
            created_at,
            completed_at,
            idempotency_key,
            source_fingerprint,
            record_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        values = (
            run.run_id,
            run.incident_id,
            run.skill_name,
            run.skill_version,
            run.llm_provider,
            run.model_name,
            run.status.value,
            run.validation_status.value,
            payload["created_at"],
            payload["completed_at"],
            run.idempotency_key,
            run.source_fingerprint,
            json.dumps(payload, sort_keys=True),
        )
        try:
            with self._connect() as connection:
                connection.execute(query, values)
        except sqlite3.Error as exc:
            raise FortiEDRPersistenceError("Failed to persist the analysis run.") from exc
        return run

    def get_run(self, run_id: str) -> AnalysisRunRecord | None:
        query = "SELECT record_json FROM analysis_runs WHERE run_id = ?"
        try:
            with self._connect() as connection:
                row = connection.execute(query, (run_id,)).fetchone()
        except sqlite3.Error as exc:
            raise FortiEDRPersistenceError("Failed to load the requested analysis run.") from exc
        return self._deserialize_row(row)

    def get_latest_successful_run(
        self,
        *,
        incident_id: str,
        idempotency_key: str | None = None,
        source_fingerprint: str | None = None,
    ) -> AnalysisRunRecord | None:
        query = """
        SELECT record_json
        FROM analysis_runs
        WHERE incident_id = ?
          AND status = 'success'
        """
        params: list[str] = [incident_id]
        if idempotency_key is not None:
            query += " AND idempotency_key = ?"
            params.append(idempotency_key)
        if source_fingerprint is not None:
            query += " AND source_fingerprint = ?"
            params.append(source_fingerprint)
        query += " ORDER BY completed_at DESC, created_at DESC LIMIT 1"
        try:
            with self._connect() as connection:
                row = connection.execute(query, tuple(params)).fetchone()
        except sqlite3.Error as exc:
            raise FortiEDRPersistenceError("Failed to load the latest analysis run.") from exc
        return self._deserialize_row(row)

    def list_runs_for_incident(
        self,
        *,
        incident_id: str,
        limit: int = 20,
    ) -> list[AnalysisRunRecord]:
        query = """
        SELECT record_json
        FROM analysis_runs
        WHERE incident_id = ?
        ORDER BY created_at DESC
        LIMIT ?
        """
        try:
            with self._connect() as connection:
                rows = connection.execute(query, (incident_id, limit)).fetchall()
        except sqlite3.Error as exc:
            raise FortiEDRPersistenceError("Failed to load analysis history.") from exc
        return [AnalysisRunRecord.model_validate(json.loads(row["record_json"])) for row in rows]

    def get_latest_successful_runs_for_incidents(
        self,
        *,
        incident_ids: list[str],
    ) -> dict[str, AnalysisRunRecord]:
        if not incident_ids:
            return {}

        placeholders = ", ".join("?" for _ in incident_ids)
        query = f"""
        SELECT record_json
        FROM analysis_runs
        WHERE status = 'success'
          AND incident_id IN ({placeholders})
        ORDER BY incident_id ASC, completed_at DESC, created_at DESC
        """
        try:
            with self._connect() as connection:
                rows = connection.execute(query, tuple(incident_ids)).fetchall()
        except sqlite3.Error as exc:
            raise FortiEDRPersistenceError("Failed to load analysis run summaries.") from exc

        summaries: dict[str, AnalysisRunRecord] = {}
        for row in rows:
            run = AnalysisRunRecord.model_validate(json.loads(row["record_json"]))
            summaries.setdefault(run.incident_id, run)
        return summaries

    def get_latest_runs_for_incidents(
        self,
        *,
        incident_ids: list[str],
    ) -> dict[str, AnalysisRunRecord]:
        if not incident_ids:
            return {}

        placeholders = ", ".join("?" for _ in incident_ids)
        query = f"""
        SELECT record_json
        FROM analysis_runs
        WHERE incident_id IN ({placeholders})
        ORDER BY incident_id ASC, created_at DESC
        """
        try:
            with self._connect() as connection:
                rows = connection.execute(query, tuple(incident_ids)).fetchall()
        except sqlite3.Error as exc:
            raise FortiEDRPersistenceError("Failed to load latest analysis runs.") from exc

        summaries: dict[str, AnalysisRunRecord] = {}
        for row in rows:
            run = AnalysisRunRecord.model_validate(json.loads(row["record_json"]))
            summaries.setdefault(run.incident_id, run)
        return summaries

    def update_run(self, run: AnalysisRunRecord) -> AnalysisRunRecord:
        payload = run.model_dump(mode="json")
        query = """
        UPDATE analysis_runs
        SET incident_id = ?,
            skill_name = ?,
            skill_version = ?,
            llm_provider = ?,
            model_name = ?,
            status = ?,
            validation_status = ?,
            created_at = ?,
            completed_at = ?,
            idempotency_key = ?,
            source_fingerprint = ?,
            record_json = ?
        WHERE run_id = ?
        """
        values = (
            run.incident_id,
            run.skill_name,
            run.skill_version,
            run.llm_provider,
            run.model_name,
            run.status.value,
            run.validation_status.value,
            payload["created_at"],
            payload["completed_at"],
            run.idempotency_key,
            run.source_fingerprint,
            json.dumps(payload, sort_keys=True),
            run.run_id,
        )
        try:
            with self._connect() as connection:
                cursor = connection.execute(query, values)
                if cursor.rowcount == 0:
                    raise FortiEDRPersistenceError("The requested analysis run does not exist.")
        except sqlite3.Error as exc:
            if isinstance(exc, FortiEDRPersistenceError):
                raise
            raise FortiEDRPersistenceError("Failed to update the analysis run.") from exc
        return run

    def clear_all_runs(self) -> int:
        try:
            with self._connect() as connection:
                cursor = connection.execute("DELETE FROM analysis_runs")
        except sqlite3.Error as exc:
            raise FortiEDRPersistenceError("Failed to clear persisted analysis runs.") from exc
        return cursor.rowcount if cursor.rowcount is not None else 0
