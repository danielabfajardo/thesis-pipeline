import json
import logging
import os
import re
from pathlib import Path

import anthropic
import pandas as pd

log = logging.getLogger(__name__)

PROMPTS_DIR = Path(__file__).parent.parent / "prompts"


class LLMRanker:
    def __init__(self, config: dict, results_path: Path):
        self.config = config
        self.results_path = results_path
        llm = config.get("llm", {})
        self.model = llm.get("model", "claude-sonnet-4-6")
        self.max_tokens = llm.get("max_tokens", 8192)
        self.client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY", ""))

    def _json_value(self, value):
        """Convert pandas NA/NaN to Python None so JSON serializes as null."""
        if pd.isna(value):
            return None
        if hasattr(value, "item"):
            return value.item()
        return value

    def _load_prompt_template(self, condition: str) -> str:
        path = PROMPTS_DIR / f"system_prompt_{condition}.txt"
        return path.read_text()

    def _build_c2_issue(self, row: pd.Series, alert_id: int) -> dict:
        return {
            "alert_id": alert_id,
            "issue_key": str(row.get("issue_key", "")),
            "file": str(row.get("file", "")),
            "file_path": str(row.get("file_path", "")),
            "rule": str(row.get("rule", "")),
            "type": str(row.get("type", "")),
            "message": str(row.get("message", "")),
            "line": int(row["line"]) if pd.notna(row.get("line")) else None,
            "effort": str(row.get("effort", "") or ""),
            "file_bugs": int(row.get("bugs", 0) or 0),
            "file_vulnerabilities": int(row.get("vulnerabilities", 0) or 0),
            "file_code_smells": int(row.get("code_smells", 0) or 0),
            "file_violations": int(row.get("violations", 0) or 0),
            "file_complexity": int(row.get("complexity", 0) or 0),
            "file_cognitive_complexity": int(row.get("cognitive_complexity", 0) or 0),
            "file_sqale_index": int(row.get("sqale_index", 0) or 0),
            "file_lines": int(row.get("lines", 0) or 0),
            "file_reliability_rating": str(row.get("reliability_rating", "") or ""),
            "file_security_rating": str(row.get("security_rating", "") or ""),
        }

    def _build_c3_issue(self, row: pd.Series, alert_id: int) -> dict:
        """Build C3 LLM input: C2 fields + development activity + SATD context."""
        obj = self._build_c2_issue(row, alert_id)
        satd_text = self._json_value(row.get("satd_text"))
        obj.update({
            "file_commit_count": self._json_value(row.get("commit_count")),
            "file_unique_authors": self._json_value(row.get("unique_authors")),
            "file_churn": self._json_value(row.get("churn")),
            "file_days_since_modified": self._json_value(row.get("days_since_modified")),
            "file_satd_count": self._json_value(row.get("satd_count")),
            "file_satd_text": satd_text if satd_text else None,
        })
        return obj

    def _call_api(self, issues_json: str, condition: str) -> str:
        from datetime import datetime, timezone

        template = self._load_prompt_template(condition)
        prompt = template.replace("{issues_json}", issues_json)

        message = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            temperature=0,
            messages=[{"role": "user", "content": prompt}],
        )

        full_text = ""
        for block in message.content:
            if getattr(block, "type", None) == "text":
                full_text += block.text

        archive = {
            "id": getattr(message, "id", None),
            "model": getattr(message, "model", None),
            "stop_reason": getattr(message, "stop_reason", None),
            "usage": {
                "input_tokens": getattr(message.usage, "input_tokens", None),
                "output_tokens": getattr(message.usage, "output_tokens", None),
            },
            "request": {"temperature": 0, "max_tokens": self.max_tokens},
            "received_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "text": full_text,
        }

        response_path = self.results_path / f"llm_response_{condition}.json"
        with open(response_path, "w") as f:
            json.dump(archive, f, indent=2, ensure_ascii=False)

        log.info(
            f"llm_response_{condition}.json written "
            f"({archive['usage']['input_tokens']}→{archive['usage']['output_tokens']} tokens, "
            f"stop_reason={archive['stop_reason']})"
        )

        return full_text

    def _parse_response(self, raw: str, fallback_df: pd.DataFrame, condition: str) -> list[dict]:
        """
        Extract and validate LLM ranking output.

        The LLM must return a valid JSON array where:
        - Each element has alert_id, rank (1 to N), and llm_reasoning
        - All expected alert_ids (1..N) are present exactly once
        - Ranks are 1 to N with no duplicates

        Narrow normalization: when the model emits extra entries for alert_ids
        that already appear in the output (a reproducible artifact where the
        model inserts a duplicate "placeholder" entry to "maintain count
        integrity"), the extras are dropped, keeping the first occurrence.
        No ranks or reasoning are altered. All other validation remains strict.
        """
        # Extract JSON array from LLM response (strips markdown fences, trailing text)
        start = raw.find("[")
        if start == -1:
            raise ValueError(f"LLM response contains no JSON array ({condition})")

        depth = 0
        end = -1
        in_string = False
        escape = False
        for i in range(start, len(raw)):
            ch = raw[i]
            if escape:
                escape = False
                continue
            if ch == "\\" and in_string:
                escape = True
                continue
            if ch == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if ch == "[":
                depth += 1
            elif ch == "]":
                depth -= 1
                if depth == 0:
                    end = i
                    break
        if end == -1:
            raise ValueError(f"Unterminated JSON array in LLM response ({condition})")

        array_str = raw[start:end + 1]
        try:
            parsed = json.loads(array_str)
        except json.JSONDecodeError as e:
            raise ValueError(f"JSON parse failed ({condition}): {e}")

        if not isinstance(parsed, list):
            raise ValueError(f"LLM response is not a JSON array ({condition})")

        n = len(fallback_df)
        expected_ids = set(range(1, n + 1))

        # Narrow normalization: drop extra entries for alert_ids already seen.
        # See docstring — this addresses a reproducible model artifact.
        deduped: list[dict] = []
        seen_aids_pre: set = set()
        dropped: list = []
        for item in parsed:
            aid_raw = item.get("alert_id") if isinstance(item, dict) else None
            if isinstance(aid_raw, int) and aid_raw in seen_aids_pre:
                dropped.append(aid_raw)
                continue
            if isinstance(aid_raw, int):
                seen_aids_pre.add(aid_raw)
            deduped.append(item)
        if dropped:
            log.warning(
                f"Dropped {len(dropped)} duplicate entry/entries from LLM output "
                f"({condition}) for alert_id(s) {dropped}. First occurrence kept; "
                f"ranks and reasoning preserved."
            )

        # Parse each item from the deduped list with strict validation.
        items: list[dict] = []
        seen_ids: set[int] = set()
        seen_ranks: set[int] = set()

        for item in deduped:
            # Validate alert_id
            aid_raw = item.get("alert_id")
            if not isinstance(aid_raw, int):
                raise ValueError(f"Invalid alert_id type {type(aid_raw).__name__} in LLM output ({condition})")
            
            aid = aid_raw
            if aid not in expected_ids:
                raise ValueError(f"Unknown alert_id {aid} (expected 1..{n}, {condition})")
            if aid in seen_ids:
                raise ValueError(f"Duplicate alert_id {aid} in LLM output ({condition})")
            
            # Validate rank
            rk_raw = item.get("rank")
            if isinstance(rk_raw, float) and rk_raw.is_integer():
                rk = int(rk_raw)
            elif isinstance(rk_raw, int):
                rk = rk_raw
            else:
                raise ValueError(f"Invalid rank {rk_raw!r} for alert_id {aid} ({condition})")
            
            if rk < 1 or rk > n:
                raise ValueError(f"Rank {rk} out of bounds [1, {n}] for alert_id {aid} ({condition})")
            if rk in seen_ranks:
                raise ValueError(f"Duplicate rank {rk} in LLM output ({condition})")
            
            seen_ids.add(aid)
            seen_ranks.add(rk)
            items.append({
                "alert_id": aid,
                "llm_rank": rk,
                "llm_reasoning": str(item.get("llm_reasoning", "")),
            })

        # Verify all expected alert_ids were ranked
        if seen_ids != expected_ids:
            missing = sorted(expected_ids - seen_ids)
            raise ValueError(f"Missing alert_ids in LLM output ({condition}): {missing}")

        return items

    def _call_single(self, issues: pd.DataFrame, condition: str) -> list[dict]:
        log.info(f"Calling LLM (single prompt, {condition}): {len(issues)} issues")
        issue_list = []
        for alert_id, (_, row) in enumerate(issues.iterrows(), start=1):
            if condition == "c2":
                issue = self._build_c2_issue(row, alert_id)
            else:
                issue = self._build_c3_issue(row, alert_id)
            issue_list.append(issue)
        input_path = self.results_path / f"llm_input_{condition}.json"
        with open(input_path, "w") as f:
            json.dump(issue_list, f, indent=2, ensure_ascii=False)
        log.info(f"llm_input_{condition}.json written: {len(issue_list)} issues")

        # Every run calls the API fresh and overwrites cached responses.
        # This ensures prompts are always evaluated with the current setup.
        raw = self._call_api(json.dumps(issue_list, ensure_ascii=False), condition)
        return self._parse_response(raw, issues, condition)

    def _rank_and_save(self, enriched: pd.DataFrame, llm_results: list[dict], condition: str) -> None:
        # Create alert_id column (1..N) based on row position in enriched DataFrame
        enriched_with_id = enriched.reset_index(drop=True).copy()
        enriched_with_id["alert_id"] = range(1, len(enriched_with_id) + 1)
        
        # Merge LLM results by alert_id
        llm_df = pd.DataFrame(llm_results)
        merged = enriched_with_id.merge(llm_df, on="alert_id", how="left")
        merged = merged.sort_values("llm_rank", ascending=True).reset_index(drop=True)
        merged = merged.rename(columns={"llm_rank": f"{condition}_rank"})
        
        # Drop alert_id (internal use only); preserve original issue_key
        merged = merged.drop(columns=["alert_id"])
        
        out_path = self.results_path / f"ranking_{condition}.csv"
        merged.to_csv(out_path, index=False)
        log.info(f"ranking_{condition}.csv written: {len(merged)} issues ranked")

    def run(self) -> None:
        pool_path = self.results_path / "alert_pool_50.csv"
        if not pool_path.exists():
            raise FileNotFoundError("alert_pool_50.csv must exist before running LLM ranker — run pool builder first")

        enriched_pool_path = self.results_path / "enriched_pool_50.csv"
        if not enriched_pool_path.exists():
            raise FileNotFoundError("enriched_pool_50.csv must exist before running LLM ranker — run enrichment first")
        source_path = enriched_pool_path
        enriched = pd.read_csv(source_path)
        log.info(f"LLM ranker: {len(enriched)} issues loaded from {source_path.name}")
        
        for condition in ("c2", "c3"):
            log.info(f"--- Condition {condition.upper()} ---")
            results = self._call_single(enriched, condition)
            self._rank_and_save(enriched, results, condition)
