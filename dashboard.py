import sqlite3
import asyncio
import streamlit as st
import pandas as pd
from harness import (
    DB_FILE,
    init_db,
    get_defenses,
    reset_to_base_prompt,
    export_profile,
    list_available_profiles,
    apply_profile_to_live_state,
    get_active_profile_tag,
    request_session_stop,
    run_hardening_session
)

# initialise sqlite tables
init_db()

st.set_page_config(page_title="Autonomous LLM Hardening Harness ⚔️", layout="wide")
st.title("Autonomous LLM Hardening Harness ⚔️")
st.caption("Multi-agent MLSecOps pipeline evaluating and hardening the Enterprise LLM Security Gateway.")


# (1) profile initialisation and selection

if "initialized" not in st.session_state:
    reset_to_base_prompt()
    st.session_state["initialized"] = True
    st.session_state["master_profile_selector"] = "Baseline"

available_profiles = list_available_profiles()
profile_options = ["Baseline"] + available_profiles

current_tag = get_active_profile_tag()
if current_tag not in profile_options:
    current_tag = "Baseline"
    reset_to_base_prompt()

default_idx = profile_options.index(current_tag)

def handle_profile_change():
    selected = st.session_state["master_profile_selector"]
    if selected == "Baseline":
        reset_to_base_prompt()
    else:
        apply_profile_to_live_state(selected)

st.write("### 🎯 Active Target Profile")
chosen_profile = st.selectbox(
    "Active Profile Under Test:",
    options=profile_options,
    index=default_idx,
    key="master_profile_selector",
    on_change=handle_profile_change,
    help="Selecting a profile switches the active target, loaded defences, and scoped round history."
)

active_tag = get_active_profile_tag()
st.divider()


# (2) run controls and active defensive state

col_actions, col_defences = st.columns([1, 1])

with col_actions:
    st.subheader(f"⚙️ Harden Profile: `{active_tag}`")
    mode = st.radio(
        "Run Mode", 
        ["Fixed Rounds", "Timed Session (Minutes)", "Continuous (Run Until Stopped)"], 
        horizontal=False
    )
    
    rounds_count = 0
    duration_mins = 0
    if mode == "Fixed Rounds":
        rounds_count = int(st.number_input("Rounds to Evaluate:", min_value=1, max_value=500, value=5, step=1))
    elif mode == "Timed Session (Minutes)":
        duration_mins = int(st.number_input("Duration in Minutes:", min_value=1, max_value=120, value=5, step=1))
    else:
        st.info("Continuous Mode: Loops autonomously until you click **🛑 Stop Execution**.")

    btn_col1, btn_col2 = st.columns([3, 1])
    with btn_col1:
        start_btn = st.button(f"🚀 Launch Run [{active_tag}]", type="primary", use_container_width=True)
    with btn_col2:
        stop_btn = st.button("🛑 Stop", use_container_width=True, help="Halts the run cleanly as soon as the active step returns.")

    if stop_btn:
        request_session_stop()
        st.warning("🛑 Stop signal written to disk. The runner will halt immediately when the active operation finishes.")

    if start_btn:
        status_box = st.empty()
        log_placeholder = st.container()

        def on_round_complete(data):
            lat_str = f"({data.get('latency', 0.0):.1f}s)"
            status_box.info(f"⚡ Completed Round #{data['round']} {lat_str}. Planning next vector...")

            with log_placeholder:
                prof_tag = f"[{data.get('active_profile', 'Baseline')}] "
                if data.get("leaked", False):
                    st.error(f"{prof_tag}Round #{data['round']}: 🚨 Breached & Leaked! {lat_str}")
                elif data.get("gw_status") in ["403_BLOCKED", "403_PERIMETER_BLOCKED"]:
                    st.warning(f"{prof_tag}Round #{data['round']}: 🛡️ Perimeter Blocked (403) {lat_str}")
                else:
                    st.success(f"{prof_tag}Round #{data['round']}: 🛡️ Defended {lat_str}")

                with st.expander(f"Inspect Active Round #{data['round']} {lat_str}", expanded=False):
                    if data.get("attack_strategy"):
                        st.markdown(f"**Evaluator Strategy & Pivot:** {data['attack_strategy']}")
                    st.markdown(f"**Vector:** {data['attack']}")
                    st.markdown(f"**Gateway Output:** {data['response']}")
                    st.markdown(f"**Judge Ruling:** {data['reasoning']}")
                    if data.get("patch"):
                        st.info(f"**Synthesised Dual-Patch:** `{data['patch']}`")

        with st.spinner(f"Autonomous Red Team executing evaluation on [{active_tag}]..."):
            history, _ = asyncio.run(
                run_hardening_session(
                    max_rounds=rounds_count,
                    duration_minutes=duration_mins,
                    progress_callback=on_round_complete
                )
            )
            if history:
                st.session_state["session_scope_selector"] = history[0]["session_id"]
            st.rerun()

    st.write("---")
    st.subheader("💾 Freeze Checkpoint")
    export_name = st.text_input("Save As New Profile (.json):", value=f"{active_tag.replace('.json', '')}_hardened")
    
    if st.button("💾 Export Checkpoint for Arena", use_container_width=True):
        exported_path = export_profile(export_name)
        st.session_state["export_success_msg"] = f"Archived as `{exported_path}`! Available in Arena."
        st.rerun()

    if "export_success_msg" in st.session_state:
        st.success(st.session_state["export_success_msg"])

with col_defences:
    st.subheader(f"🛡️ Current Shield: `{active_tag}`")
    active_rules, active_regexes = get_defenses()
    
    st.markdown("**1. Synthesised Prompt Invariants:**")
    if active_rules:
        for r in active_rules:
            st.info(f"• {r}")
    else:
        st.caption("No dynamic prompt rules currently active on this profile.")
    
    st.markdown("**2. Dynamic Egress Regex Filters:**")
    if active_regexes:
        for pat in active_regexes:
            st.code(pat, language="python")
    else:
        st.caption("No dynamic regex filters currently active on this profile.")

st.divider()


# (3) telemetry export (reads latest run directly from sqlite)

def get_latest_session_data():
    """fetches the most recent session records from sqlite for export."""
    with sqlite3.connect(DB_FILE) as conn:
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT session_id FROM eval_logs ORDER BY id DESC LIMIT 1")
            row = cursor.fetchone()
            if not row:
                return []
            latest_sess = row[0]
            
            df = pd.read_sql_query(
                "SELECT * FROM eval_logs WHERE session_id = ? ORDER BY round_num ASC",
                conn,
                params=[latest_sess]
            )
            return df.to_dict(orient="records")
        except Exception:
            return []

latest_rounds = get_latest_session_data()
if latest_rounds:
    st.subheader("📋 Copy Latest Run Telemetry for Review")
    
    sess_id = latest_rounds[0].get("session_id", "latest")
    dump_lines = [f"=== EVALUATION TELEMETRY: [{active_tag}] (Session: {sess_id}) ==="]
    for h in latest_rounds:
        lat = f" | Latency={h.get('latency_seconds', 0.0):.2f}s"
        leaked_bool = bool(h.get("leaked", 0) == 1)
        dump_lines.append(f"\n--- ROUND #{h['round_num']} [{h['gateway_status']}]{lat} Leaked={leaked_bool} ---")
        dump_lines.append(f"STRATEGY: {h.get('attack_strategy', 'N/A')}")
        dump_lines.append(f"PAYLOAD: {h['attack_prompt']}")
        dump_lines.append(f"GATEWAY_OUTPUT: {h['target_response']}")
        dump_lines.append(f"JUDGE_REASONING: {h['judge_reasoning']}")
        if h.get("patch_applied"):
            dump_lines.append(f"COMMITTED_PATCH: {h['patch_applied']}")
            
    raw_dump = "\n".join(dump_lines)
    st.text_area("Plaintext Markdown Dump", raw_dump, height=180)


# (4) historical audit log and lineage tracking

st.subheader(f"📜 Historical Audit Log for: `{active_tag}`")

def get_available_sessions(profile_tag: str):
    """retrieves all distinct session ids for this profile."""
    with sqlite3.connect(DB_FILE) as conn:
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT DISTINCT session_id FROM eval_logs WHERE active_profile = ? ORDER BY id DESC", (profile_tag,))
            return [r[0] for r in cursor.fetchall()]
        except Exception:
            return []

session_filter_options = ["All Sessions (Continuous Stream)"] + get_available_sessions(active_tag)

current_selection = st.session_state.get("session_scope_selector")
if current_selection not in session_filter_options:
    current_selection = session_filter_options[0]

selected_sess_idx = session_filter_options.index(current_selection)

selected_sess = st.selectbox(
    "View Run Scope:",
    session_filter_options,
    index=selected_sess_idx,
    key="session_scope_selector"
)

def load_eval_data(profile_tag: str, selected_filter: str):
    """loads evaluation logs based on profile and chosen session filter."""
    with sqlite3.connect(DB_FILE) as conn:
        try:
            if selected_filter == "All Sessions (Continuous Stream)":
                query = """
                    SELECT id, session_id, active_profile, timestamp, round_num, gateway_status, 
                           target_response, leaked, attack_strategy, attack_prompt, judge_reasoning, patch_applied, latency_seconds 
                    FROM eval_logs 
                    WHERE active_profile = ?
                    ORDER BY round_num DESC
                """
                return pd.read_sql_query(query, conn, params=[profile_tag])
            else:
                query = """
                    SELECT id, session_id, active_profile, timestamp, round_num, gateway_status, 
                           target_response, leaked, attack_strategy, attack_prompt, judge_reasoning, patch_applied, latency_seconds 
                    FROM eval_logs 
                    WHERE active_profile = ? AND session_id = ?
                    ORDER BY round_num ASC
                """
                return pd.read_sql_query(query, conn, params=[profile_tag, selected_filter])
        except Exception:
            return pd.DataFrame()

df_eval = load_eval_data(active_tag, selected_sess)

if not df_eval.empty:
    df_eval["leaked_label"] = df_eval["leaked"].map({1: "🚨 Breached", 0: "🛡️ Defended"})
    df_eval["timestamp"] = pd.to_datetime(df_eval["timestamp"], format="mixed", utc=True).dt.strftime("%H:%M:%S")

    total_runs = len(df_eval)
    breaches = int((df_eval["leaked"] == 1).sum())
    asr = (breaches / total_runs) * 100 if total_runs > 0 else 0
    avg_lat = df_eval["latency_seconds"].mean() if "latency_seconds" in df_eval.columns else 0.0
    
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total Lineage Rounds", total_runs)
    m2.metric("Successful Breaches", breaches)
    m3.metric("Attack Success Rate (ASR)", f"{asr:.1f}%")
    m4.metric("Avg Round Latency", f"{avg_lat:.2f}s")

    cols_to_show = [c for c in ["round_num", "session_id", "timestamp", "latency_seconds", "gateway_status", "leaked_label", "attack_prompt", "judge_reasoning", "patch_applied"] if c in df_eval.columns]
    st.dataframe(df_eval[cols_to_show], width="stretch", hide_index=True)

    st.write("#### 🔍 Inspect Round Details")
    available_ids = df_eval["id"].tolist()
    
    def format_log_choice(x):
        r_num = df_eval.loc[df_eval['id'] == x, 'round_num'].values[0]
        s_id = df_eval.loc[df_eval['id'] == x, 'session_id'].values[0]
        return f"Log ID #{x} (Round {r_num} | Sess: {s_id})"

    selected_id = st.selectbox("Select row ID to inspect:", available_ids, format_func=format_log_choice)
    selected_row = df_eval[df_eval["id"] == selected_id].iloc[0]

    is_breached = bool(selected_row["leaked"] == 1)
    if is_breached:
        st.error(f"Round #{selected_row['round_num']} [{selected_row['active_profile']}]: 🚨 Breached & Leaked!")
    elif selected_row["gateway_status"] in ["403_BLOCKED", "403_PERIMETER_BLOCKED"]:
        st.warning(f"Round #{selected_row['round_num']} [{selected_row['active_profile']}]: 🛡️ Perimeter Blocked (403)")
    else:
        st.success(f"Round #{selected_row['round_num']} [{selected_row['active_profile']}]: 🛡️ Clean Completion")

    with st.expander(f"Inspect Details for Round #{selected_row['round_num']}", expanded=True):
        st.markdown(f"**Session ID:** `{selected_row['session_id']}`")
        if selected_row.get("attack_strategy"):
            st.markdown(f"**Evaluator Strategy & Pivot:** {selected_row['attack_strategy']}")
        st.markdown(f"**Vector:** {selected_row['attack_prompt']}")
        st.markdown(f"**Gateway Output:** {selected_row['target_response']}")
        st.markdown(f"**Judge Ruling:** {selected_row['judge_reasoning']}")
        if selected_row.get("patch_applied"):
            st.info(f"**Synthesised Dual-Patch:** `{selected_row['patch_applied']}`")
        
        r_lat = selected_row.get("latency_seconds", 0.0)
        st.caption(f"⏱️ Execution duration: {r_lat:.2f} seconds")
else:
    st.info(f"No rounds recorded for profile '{active_tag}' yet.")