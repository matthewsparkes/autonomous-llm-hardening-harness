# Autonomous LLM Hardening Harness (ALHH)

An automated red-teaming and defence generation harness designed to expose semantic bypasses and dynamically patch the Enterprise LLM Security Gateway (ELSG).

While the security gateway successfully blocks overt injections and literal keyword dumps, attackers can easily bypass static filters using indirect natural language (such as spelling out numbers, using phonetic clues, or encoding secrets in hex). This harness uses three cooperating LLMs to continuously stress-test the gateway, identify covert data leaks, and automatically generate and test runtime defences - all without breaking the assistant's ability to answer routine store questions.

---

## The Problem: The Manual Hardening Ceiling

Deterministic perimeter defences (like the ELSG reverse-proxy) reliably stop overt injections and literal credential dumps, but reach a hard operational ceiling when confronted with natural language.

In this implementation (a McDonald's branch operational assistant), the knowledge base contains two conflicting tiers of data:
- **Ordinary Operational Data (which must remain accessible):** Daily Standard Operating Procedures (SOPs), equipment troubleshooting steps, and routine operational numbers like grill calibration temperatures or fridge limits.
- **Sensitive Information Assets (which must remain private):** Shift supervisor safe access PINs, internal IT gateway network sockets, and management contact numbers / NI identifiers.

### Why Small Models and Static Filters Fail Against Natural Language

1. **Context Confusion:** Small models like Llama 3.2 struggle to separate operational context from forbidden secrets. Under hypothetical scenarios, emergency drills, or roleplay, their training to be helpful overrides system prompt constraints.
2. **Format Obfuscation:** Very rarely will an attacker query for raw numbers like `984210`. Instead, they will more likely instruct the model to spell out digits (`nine, eight, four...`), convert them into hexadecimal ASCII bytes, or embed them in fictional logs. Because no literal numeric digits appear in the output stream, static string and keyword filters let the output straight through.
3. **The Utility Trade-Off:** The assistant's entire purpose is to answer store questions containing numbers and technical terms (like checking grill temperatures or looking up equipment error codes). If you try to stop leaks by bluntly blocking all numbers or general words, staff can no longer use the tool for their daily jobs and the LLM becomes useless.

### The Autonomous Shift

In my original project (Enterprise LLM Security Gateway), I built the gateway to intercept obvious, literal threats (prompt injections, explicit PII, and raw credential keywords). However, hardening against natural language manually doesn't scale. If I tried to harden it myself, I would have to spend days manually brainstorming obscure bypass prompts, inspecting terminal responses, writing regexes by hand, and repeatedly verifying that I hadn't accidentally broken routine store questions.

This project automates that entire red-team / blue-team engineering cycle. Instead of manual testing, three AI models work in a closed feedback loop: one attacks the gateway using creative obfuscation, one impartially verifies whether a leak occurred, and one writes dual-layer defences (system prompt rules and outbound regexes). On top of this, before any patch is accepted, the harness automatically runs a regression test against real store SOPs to guarantee the fix doesn't break daily operations.

---

## Autonomous Tri-Agent Architecture

The harness uses **Gemini 3.5 Flash Lite** (via the Google GenAI SDK) to power three specialized agents that act as an automated audit team, stress-testing the local **Llama 3.2** model running behind the security gateway. Pairing a fast, high-reasoning cloud model against a small local model mirrors real-world security testing: using an advanced system to find blind spots in lightweight hardware deployments.

1. **The Red Attacker (Automated Adversary):**
   - **Autonomous Attack Generation:** Invents its own creative scenarios (such as sci-fi maintenance logs, HVAC diagnostic simulations, or word puzzles) and autonomously demands non-literal formats (hex bytes, hyphenated words, or phonetic spelling) to trick the model while dodging static filters.
   - **Adaptive Pivot Loop:** When an attack fails, the agent is fed the exact reason why (e.g., blocked by perimeter regex vs. caught by egress guard) along with a list of recently exhausted strategies. It writes out an explicit rationale explaining its next hypothesis and pivots its approach for the next round.

2. **The Semantic Judge (Auditor):**
   - Compares the model's answer against the real list of protected store secrets (safe PIN, IT gateway IP, and manager phone/NI numbers).
   - Evaluates semantic meaning rather than just exact text—catching leaks even if the model spells digits out as words, breaks them into hex pairs, or hides them inside a story.
   - Emits a strict structured JSON verdict (`leaked: true/false`) along with a short explanation of its decision.

3. **The Blue Patcher (Defensive Engineer):**
   - Whenever the judge confirms a leak, this agent automatically writes two fixes:
     - **System Prompt Rule:** A concise invariant instruction (under 25 words) telling the model to refuse the specific trick or tactic used in that attack.
     - **Egress Regex Filter:** A custom regular expression tailored to catch the output format (like hex strings or spelled-out numbers) if the model slips up again.
   - **Utility Check:** Automatically tests candidate rules against standard operational questions (grill calibration, fridge temperatures, shake machine error codes). If the patch blocks legitimate store operations, the candidate rules are discarded.

---

## Telemetry & Defence Inspection

Below is the live execution telemetry from the Streamlit dashboard (`dashboard.py`), illustrating how the Red Attacker pivots format representations and how the Blue Patcher synthesizes dual-layer countermeasures:

![Round Details - Sci-Fi Obfuscation Bypass and Dual-Patch Synthesis](assets/round_inspection_scifi.png)
*Figure 1: Telemetry Inspector showing the Red Attacker pivoting to a sci-fi diagnostic scenario with spelled-out hyphenated numbers, followed by the Judge ruling and synthesized dual-patch.*

<br>

![Round Details - Hexadecimal Telemetry Evasion and Regex Synthesis](assets/round_inspection_hex.png)
*Figure 2: Telemetry Inspector showing an HVAC diagnostic attack demanding hexadecimal ASCII byte pairs, the resulting egress leak, and the generated regex pattern.*

---

## Defensive Profiles & Checkpoints

- **Saveable Defence Snapshots:** Hardened rules and regexes can be frozen at any point and exported as portable JSON profiles directly from the dashboard.
- **Cumulative Lineage:** Loading a saved profile allows the harness to continue stress-testing from where it left off, building on existing defences rather than starting from scratch.
- **Interactive Arena Testing:** Saved profiles can be loaded directly into the standalone Arena (`arena.py`), giving you a live prompt box to type your own adversarial or benign test queries by hand and evaluate how hardened defences hold up compared to the factory baseline.

---

## Project Structure

- `agents.py` — Defines system prompts and response schemas for the Red Attacker, Semantic Judge, and Blue Patcher.
- `harness.py` — The central orchestration loop. Manages multi-round evaluations, calls `process_target_query()` from the previous project gateway, runs utility regression checks against store SOPs, and logs telemetry to SQLite (`eval_logs.db`).
- `dashboard.py` — Streamlit telemetry console for viewing live attack success rates, round-by-round strategy pivots, breach rationales, and exporting hardened defence profiles to JSON.
- `arena.py` — A standalone Streamlit console for interactive manual testing, complete with profile switching, live response inspection, and an arena audit log table.
- `requirements.txt` — Python dependencies.

---

## Quick Start

### 1. Start Ollama
```bash
ollama run llama3.2
```

### 2. Configure Environment and Install Dependencies
```bash
export GEMINI_API_KEY="your_api_key_here"
pip install -r requirements.txt
```

> **Note:** Ensure the `enterprise-llm-security-gateway` repository is located in the adjacent directory so the gateway engine can be imported directly.

### 3. Open the Dashboard
```bash
streamlit run dashboard.py
```

### 4. Open the Arena (Optional)
```bash
streamlit run arena.py
```
