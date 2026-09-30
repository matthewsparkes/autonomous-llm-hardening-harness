import os
import sys
import sqlite3
import datetime
import json
import asyncio
import streamlit as st
import pandas as pd

# import process_target_query directly from Project A
PROJECT_A_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "enterprise-llm-security-gateway"))
if PROJECT_A_DIR not in sys.path:
    sys.path.insert(0, PROJECT_A_DIR)

from main import process_target_query

from harness import (
    DB_FILE,
    init_db,
    list_available_profiles,
    load_profile_by_name
)

# ensure database tables and indexes exist
init_db()

with sqlite3.connect(DB_FILE) as conn:
    conn.cursor().execute("CREATE INDEX IF NOT EXISTS idx_arena_time ON arena_logs(timestamp);")
    conn.cursor().execute("CREATE INDEX IF NOT EXISTS idx_arena_mode ON arena_logs(defense_mode);")
    conn.commit()

st.set_page_config(page_title="Enterprise LLM Security Gateway: Evaluation Arena 💂", layout="wide")

st.title("Enterprise LLM Security Gateway: Evaluation Arena 💂")
st.caption("Interactive prompt evaluation console with swappable defensive profiles.")


# (1) profile selection

try:
    available_snapshots = list_available_profiles()
except Exception:
    available_snapshots = []

profile_choices = [
    "Live Database State ⚡",
    "Baseline"
] + available_snapshots

selected_profile = st.selectbox(
    "Target Defence Profile:",
    profile_choices,
    index=0,
    help="Select whether to evaluate queries using baseline rules, live database state, or an archived hardened snapshot."
)

try:
    active_rules, active_regexes = load_profile_by_name(selected_profile)
except Exception as e:
    st.error(f"Error loading profile '{selected_profile}': {e}")
    active_rules, active_regexes = [], []


# (2) interactive prompt console

def log_manual_test(user_id: str, profile_name: str, prompt: str, sanitized: str, response: str, is_safe: bool, violations: list):
    with sqlite3.connect(DB_FILE) as conn:
        conn.cursor().execute("""
            INSERT INTO arena_logs (timestamp, user_id, defense_mode, prompt_text, sanitized_text, llm_response, is_safe, violations)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.datetime.now(datetime.timezone.utc).isoformat(),
            user_id,
            profile_name,
            prompt,
            sanitized,
            response,
            1 if is_safe else 0,
            json.dumps(violations)
        ))
        conn.commit()

with st.container(border=True):
    col_u, col_p = st.columns([1, 4])
    with col_u:
        user_id = st.text_input("User ID", value="auditor_01")
    with col_p:
        user_prompt = st.text_input("Prompt", placeholder="Enter your test query or injection probe here...")

    if st.button("Evaluate Prompt", type="primary", use_container_width=True):
        if not user_prompt.strip():
            st.warning("Please enter a prompt.")
        else:
            with st.spinner("Processing request through Enterprise LLM Security Gateway..."):
                try:
                    gw_result = asyncio.run(
                        process_target_query(
                            prompt=user_prompt,
                            extra_rules=active_rules,
                            extra_egress_regexes=active_regexes
                        )
                    )

                    is_blocked = gw_result.get("is_blocked", False)
                    violations = gw_result.get("violations", [])
                    sanitized_text = gw_result.get("sanitized_prompt", user_prompt)
                    llm_response = gw_result.get("response", "")
                    is_safe = (not is_blocked) and ("restricted credentials" not in llm_response)

                    log_manual_test(user_id, selected_profile, user_prompt, sanitized_text, llm_response, is_safe, violations)

                    if is_blocked:
                        st.error("Status: 403 Forbidden — Blocked by Ingress Gateway")
                        st.markdown(f"**Violations Detected:** `{', '.join(violations)}`")
                    elif "restricted credentials" in llm_response:
                        st.warning("Status: 200 OK — Fail-Closed Egress Guard Intercepted Output")
                        st.markdown(f"**Gateway Response:**\n\n{llm_response}")
                    else:
                        st.success("Status: 200 OK — Allowed")
                        if violations:
                            st.info(f"Redactions applied: {', '.join(violations)}")
                        st.caption(f"Sanitised prompt sent to model: `{sanitized_text}`")
                        st.markdown(f"**Model Response:**\n\n{llm_response}")
                except Exception as e:
                    st.error(f"Execution failed: {e}")

st.divider()


# (3) manuual test audit log table

st.subheader("Arena Audit Logs")

def load_arena_data():
    with sqlite3.connect(DB_FILE) as conn:
        try:
            df = pd.read_sql_query("SELECT * FROM arena_logs ORDER BY id DESC LIMIT 200", conn)
            if not df.empty:
                if "is_safe" in df.columns:
                    df["is_safe"] = df["is_safe"].map({1: "Yes", 0: "No"}).fillna(df["is_safe"])
                if "timestamp" in df.columns:
                    df["timestamp"] = pd.to_datetime(df["timestamp"], format="mixed", utc=True).dt.strftime("%H:%M:%S")
            return df
        except Exception:
            return pd.DataFrame()

df_arena = load_arena_data()

if not df_arena.empty:
    display_cols = [c for c in ["id", "timestamp", "user_id", "defense_mode", "is_safe", "prompt_text", "sanitized_text", "llm_response", "violations"] if c in df_arena.columns]
    st.dataframe(df_arena[display_cols], width="stretch", hide_index=True)
else:
    st.info("No arena logs recorded yet.")

if st.button("Refresh Table"):
    st.rerun()

with st.expander("Inspect Loaded Profile Defences"):
    st.markdown("**Active Prompt Invariants:**")
    if active_rules:
        for r in active_rules:
            st.info(f"• {r}")
    else:
        st.caption("No dynamic prompt invariants active for this profile.")

    st.markdown("**Dynamic Egress Regex Filters:**")
    if active_regexes:
        for pat in active_regexes:
            st.code(pat, language="python")
    else:
        st.caption("No dynamic egress regex filters active for this profile.")