import sys
import os
import time
import json
import requests
from thehive4py.client import TheHiveApi

# ==========================================
# ⚙️ CONFIGURATION
# ==========================================
#
# SECURITY NOTE (2026-08-22): this file previously had a live TheHive API key
# hardcoded on the line below. That key was found during a repository-hygiene
# pass, reported, and has since been manually revoked and confirmed dead —
# see docs/SECURITY.md for the incident record. The key is no longer read
# from source; it must be exported as THEHIVE_API_KEY before running this
# script. There is no default and no fallback — the script fails closed
# (main() exits with an error) if the variable is unset.
#
# NOTE ALSO: this is an early prototype pipeline (mock-LLM triage, no
# deterministic policy gate, no idempotency, no kill switch, no dry-run
# mode) predating soar/e2e_soc_orchestrator.py, which is the actively
# maintained, hardened orchestrator actually used by this project (see
# docs/REPOSITORY-MAP.md). It is kept here as a historical/reference
# artifact, not as a second production entry point.
THEHIVE_URL = 'http://100.124.232.121:9000'
API_KEY = os.environ.get('THEHIVE_API_KEY')

TARGET_ALERT_ID = None  # Replaced by automated polling

# How long to wait for a Cortex analyzer job to finish before giving up
ANALYZER_JOB_TIMEOUT_SECONDS = 120
ANALYZER_POLL_INTERVAL_SECONDS = 3

# Analyzers to run, matched by name PREFIX (so version suffixes like
# _2_0 / _3_1 don't matter). Add/remove entries here to control which
# analyzers get run against every observable.
ANALYZER_NAME_PREFIXES = [
    "VirusTotal_GetReport",
    "AbuseIPDB",
    "AlienVault_OTX",
    "URLhaus",
]

# ==========================================
# 🤖 LLM CONFIGURATION (Ollama - Local mistral:7b)
# ==========================================
OLLAMA_API_URL = "http://100.96.231.95:11434/api/generate"
OLLAMA_MODEL = "mistral:7b"


def call_llm(system_prompt, user_prompt):
    """
    Generic call to the local Ollama LLM API. Asks for JSON-only output and parses it.
    """
    prompt = f"{system_prompt}\n\n{user_prompt}\n\nPlease output strict JSON only without any markdown formatting wrappers."
    
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "format": "json"  # Forces native JSON output from Ollama 
    }
    
    try:
        t0 = time.time()
        print(f"   [LLM debug] Sending prompt to Ollama ({OLLAMA_MODEL})...")
        response = requests.post(OLLAMA_API_URL, json=payload, timeout=120)
        response.raise_for_status()
        data = response.json()
        
        t1 = time.time()
        print(f"   [LLM debug] Response received in {t1-t0:.1f}s")
        
        raw_text = data.get('response', '{}')
        return json.loads(raw_text)
        
    except Exception as e:
        print(f"❌ [LLM Error]: {e}")
        return {"verdict": "unknown", "action": "promote", "reason": f"Fallback due to Error: {e}"}

def mock_llm_triage(alert_data):
    """
    Step 4 & 5: First LLM call. The LLM acts as Tier 1 Analyst (Triage).
    It looks at the RAW alert and decides whether it's worth investigating.
    """
    print("\n[AI - Phase 1] 🧠 Analyzing raw alert data...")

    system_prompt = (
        "You are a Tier 1 SOC analyst performing initial alert triage. "
        "Given a raw security alert (JSON), decide whether it warrants deeper "
        "investigation. Respond ONLY with a JSON object with exactly these keys: "
        '"verdict" (one of: "suspicious", "benign", "needs_more_info"), '
        '"action" (one of: "promote", "dismiss"), '
        '"reason" (a short one or two sentence explanation).'
    )
    # Trim the alert to the fields useful for triage to keep the prompt small
    alert_summary = {
        "title": alert_data.get("title"),
        "description": alert_data.get("description"),
        "severity": alert_data.get("severity"),
        "source": alert_data.get("source"),
        "sourceRef": alert_data.get("sourceRef"),
        "tags": alert_data.get("tags"),
        "observables_count": len(alert_data.get("observables", []) or []),
    }
    user_prompt = f"Raw alert:\n{json.dumps(alert_summary, indent=2)}"

    try:
        result = call_llm(system_prompt, user_prompt)
    except Exception as e:
        print(f"   ⚠️ LLM call failed ({e}); falling back to safe default (dismiss).")
        return {
            "verdict": "needs_more_info",
            "action": "dismiss",
            "reason": f"LLM unavailable, could not triage automatically: {e}",
        }

    return result


def mock_llm_final_decision(analyzer_results):
    """
    Step 8 & 9: Second LLM call. The LLM acts as Tier 2 Analyst/Responder.
    It looks at the REAL Cortex analyzer results and makes a final decision.
    """
    print("\n[AI - Phase 2] 🧠 Reading Cortex analyzer results...")

    system_prompt = (
        "You are a Tier 2 SOC analyst making a final response decision. "
        "Given a list of real Cortex threat-intel analyzer reports (JSON), decide "
        "whether the observable is malicious and what action to take. "
        "Respond ONLY with a JSON object with exactly these keys: "
        '"verdict" (one of: "malicious", "benign", "inconclusive"), '
        '"action" (one of: "block", "monitor", "none"), '
        '"reason" (a short one or two sentence explanation citing the evidence).'
    )
    user_prompt = f"Analyzer reports:\n{json.dumps(analyzer_results, indent=2, default=str)}"

    try:
        result = call_llm(system_prompt, user_prompt)
    except Exception as e:
        print(f"   ⚠️ LLM call failed ({e}); falling back to safe default (no action).")
        return {
            "verdict": "inconclusive",
            "action": "none",
            "reason": f"LLM unavailable, could not make a final decision automatically: {e}",
        }

    return result


def wait_for_analyzer_job(api, job_id, timeout_seconds=ANALYZER_JOB_TIMEOUT_SECONDS,
                           poll_interval=ANALYZER_POLL_INTERVAL_SECONDS):
    """
    Polls a Cortex analyzer job until it reaches a terminal state
    (Success or Failure), or until timeout_seconds elapses.

    Returns the final job_status dict, or raises TimeoutError if the
    job never reaches a terminal state in time.
    """
    elapsed = 0
    last_status = None

    while elapsed <= timeout_seconds:
        try:
            job_status = api.cortex.get_analyzer_job(job_id)
        except Exception as poll_err:
            print(f"   ⚠️ Error while polling job status: {poll_err}")
            time.sleep(poll_interval)
            elapsed += poll_interval
            continue

        status = job_status.get('status')

        if status != last_status:
            print(f"   ⏳ Job status: {status} (elapsed: {elapsed}s)")
            last_status = status

        if status in ('Success', 'Failure'):
            return job_status

        # Anything else (Waiting, InProgress, Deleted, etc.) -> keep polling
        time.sleep(poll_interval)
        elapsed += poll_interval

    raise TimeoutError(
        f"Analyzer job {job_id} did not finish within {timeout_seconds}s "
        f"(last known status: {last_status})"
    )


def print_analyzer_report(job_status):
    """
    Pretty-prints the full report from a finished Cortex analyzer job,
    including taxonomies/summary if present, without truncating.
    """
    status = job_status.get('status')
    report = job_status.get('report', {}) or {}

    print("\n📊 ---------------- REAL ANALYZER REPORT -----------------")

    if status == 'Failure':
        error_message = report.get('errorMessage') or job_status.get('errorMessage') or 'Unknown error'
        print(f"   ❌ Analyzer job failed: {error_message}")
        # Print whatever raw context we do have, in case it's useful for debugging
        input_data = job_status.get('input')
        if input_data:
            print("\n   Raw input sent to analyzer:")
            print(json.dumps(input_data, indent=2))
    else:
        # Full report, unabridged
        print(json.dumps(report, indent=2))

        # If the analyzer produced taxonomies (short summary tags like
        # "VT:GetReport = 15/90"), surface those clearly too
        summary = report.get('summary', {})
        taxonomies = summary.get('taxonomies', [])
        if taxonomies:
            print("\n   🏷️  Taxonomy summary:")
            for tax in taxonomies:
                level = tax.get('level', '?')
                namespace = tax.get('namespace', '?')
                predicate = tax.get('predicate', '?')
                value = tax.get('value', '?')
                print(f"      [{level}] {namespace}:{predicate} = {value}")

    print("----------------------------------------------------------")
    return report


def process_single_alert(api, alert):
    target_alert_id = alert.get('_id', alert.get('id'))
    print(f"\n▶ STEP 3: Processing Alert ID: {target_alert_id}")
    print(f"✅ Alert fetched: '{alert.get('title')}'")

    # ---------------------------------------------------------
    # STEP 4 & 5: Send raw alert to LLM -> LLM says "promote"
    # ---------------------------------------------------------
    print("\n▶ STEP 4: Sending RAW alert to the LLM for Initial Triage...")
    triage_response = mock_llm_triage(alert)

    print(f"🤖 AI Verdict: {triage_response['verdict'].upper()}")
    print(f"🤖 AI Reason: {triage_response['reason']}")

    if triage_response['action'] != 'promote':
        print("\n✅ AI dismissed the alert. False Positive. Marking as Ignored.")
        try:
            api.alert.update(target_alert_id, status='Ignored')
        except Exception as e:
            print(f"⚠️ Could not update alert to Ignored: {e}")
        return

    # ---------------------------------------------------------
    # STEP 6: Promote Alert to Case
    # ---------------------------------------------------------
    print("\n▶ STEP 6: AI said 'promote'. Promoting Alert to Case...")
    case = api.alert.promote_to_case(target_alert_id)
    case_id = case.get('id', case.get('_id'))
    print(f"✅ Successfully created Case ID: {case_id}")

    # ---------------------------------------------------------
    # STEP 7: Run ALL configured Cortex Analyzers (real jobs, real waits, real reports)
    # ---------------------------------------------------------
    print("\n▶ STEP 7: Triggering Cortex Analyzers for Enrichment...")
    print("Fetching Observables for Case...")

    observables = api.alert.find_observables(target_alert_id)
    all_reports = []  # collect real reports here to pass to the LLM later
    target_observable_id = None

    if len(observables) == 0:
        print("⚠️ No observables found in this alert. Cannot run analyzers.")
    else:
        # Fetch the full analyzer catalog once, then filter to the ones we
        # actually want to run (by name prefix) and that support each
        # observable's dataType.
        try:
            available_analyzers = api.cortex.list_analyzers()
        except Exception as e:
            print(f"❌ FATAL: could not list analyzers from Cortex: {e}")
            available_analyzers = []

        for obs in observables:
            obs_id = obs.get('id', obs.get('_id'))
            obs_data = obs.get('data')
            obs_data_type = obs.get('dataType')
            target_observable_id = obs_id

            print(f"\n=== Observable: {obs_data} (type: {obs_data_type}) ===")

            # Match analyzers by configured name prefix AND dataType support
            # (falls back to running it anyway if dataTypeList isn't present
            # in the API response, since some Cortex versions omit it here).
            matching_analyzers = []
            for a in available_analyzers:
                name = a.get('name', '')
                if not any(name.startswith(prefix) for prefix in ANALYZER_NAME_PREFIXES):
                    continue
                supported_types = a.get('dataTypeList')
                if supported_types and obs_data_type not in supported_types:
                    continue
                matching_analyzers.append(a)

            if not matching_analyzers:
                print(f"   ⚠️ No configured/enabled analyzers matched dataType '{obs_data_type}' for this observable.")
                continue

            print(f"   Found {len(matching_analyzers)} matching analyzer(s): "
                  f"{', '.join(a.get('name') for a in matching_analyzers)}")

            for analyzer in matching_analyzers:
                analyzer_name = analyzer.get('name')
                internal_analyzer_uuid = analyzer.get('id')

                try:
                    print(f"\n   -> Enqueuing {analyzer_name} analyzer job via API...")
                    job = api.cortex.create_analyzer_job({
                        "analyzerId": internal_analyzer_uuid,
                        "cortexId": "Cortex-DevoteamSOC",
                        "artifactId": obs_id
                    })
                    job_id = job.get('id', job.get('_id'))
                    print(f"   ✅ Job created! Cortex Job ID: {job_id}")

                    print(f"   ⏳ Waiting for {analyzer_name} to finish...")
                    try:
                        job_status = wait_for_analyzer_job(api, job_id)
                    except TimeoutError as timeout_err:
                        print(f"   ⏱️ {timeout_err}")
                        continue

                    final_status = job_status.get('status')
                    print(f"   🏁 {analyzer_name} finished with status: {final_status}")

                    report = print_analyzer_report(job_status)

                    if final_status == 'Success':
                        all_reports.append({
                            "observable": obs_data,
                            "analyzer": analyzer_name,
                            "report": report
                        })

                except Exception as api_err:
                    print(f"   ⚠️ REAL Analyzer API call failed for {analyzer_name}: {api_err}")

        print(f"\n✅ Cortex Analysis phase completed. {len(all_reports)} successful report(s) collected.")

    # ---------------------------------------------------------
    # STEP 8 & 9: Send REAL results back to LLM -> LLM gives final verdict
    # ---------------------------------------------------------
    print("\n▶ STEP 8: Sending Threat Intel Reports back to the LLM...")
    if all_reports:
        print(f"   Passing {len(all_reports)} real analyzer report(s) to the LLM.")
    else:
        print("   ⚠️ No successful analyzer reports were collected — LLM will decide with limited data.")

    final_decision = mock_llm_final_decision(all_reports)
    print(f"🤖 AI Final Verdict: {final_decision['verdict'].upper()}")
    print(f"🤖 AI Reason: {final_decision['reason']}")

    # ---------------------------------------------------------
    # STEP 10: Run PfSense_Blocker Responder
    # ---------------------------------------------------------
    print("\n▶ STEP 10: AI Final Action...")
    if final_decision['action'] == 'block':
        print(f"🚨 Executing '{final_decision['action']}' action!")
        print("Triggering PfSense_Blocker Cortex Responder via REAL API Call...")

        try:
            api.cortex.create_responder_action({
                "responderId": "PfSense_Blocker_1_0",
                "cortexId": "Cortex-DevoteamSOC",
                "objectType": "case_artifact",
                "objectId": target_observable_id
            })
            print("✅ REAL Responder triggered API success! PfSense should be blocking the target IP.")
        except Exception as api_err:
            print(f"⚠️ REAL Responder API call failed: {api_err}")

    print("\n🎉 ==========================================")
    print("🎉 FULL 10-STEP CLOSED LOOP COMPLETED")
    print("🎉 ==========================================\n")


def main():
    if not API_KEY:
        sys.exit("THEHIVE_API_KEY is not set. Export it before running:\n"
                 "    export THEHIVE_API_KEY='<key>'")

    print("==========================================")
    print("🚀 FULL 10-STEP SOAR AI PIPELINE DAEMON")
    print("==========================================")

    api = TheHiveApi(THEHIVE_URL, apikey=API_KEY)
    
    print("⏳ Polling TheHive for new alerts every 10 seconds...")
    while True:
        try:
            alerts = api.alert.find()
            new_alerts = [a for a in alerts if a.get('status') == 'New']
            
            for alert in new_alerts:
                print(f"\n\n🚨 NEW ALERT DETECTED! 🚨")
                process_single_alert(api, alert)
                
            time.sleep(10)
        except Exception as e:
            print(f"❌ Polling loop error: {e}")
            time.sleep(10)

if __name__ == "__main__":
    main()
