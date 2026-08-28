import os
import sys
import json
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from backend.app.db.database import Base, engine, SessionLocal
from backend.app.db.models import NetworkFlow, AuthLog, WafLog, ComplianceFinding, SessionTrust, AttackSequence
from backend.app.ingest import ingest_cicids2017_csv, ingest_lanl_auth_csv, ingest_compliance_json
from backend.app.ml.waf import waf_engine
from backend.app.ml.behavior import insider_engine
from backend.app.ml.forecast import forecasting_engine
from backend.app.ml.trust import compute_trust_score
from backend.app.ml.compliance import compliance_engine

app = typer.Typer(help="SIH26153 AI-Based Network Attack Forecasting Mini-SOC CLI")
console = Console()

@app.command("init-env")
def init_env():
    """Initialize database tables, directories, and default environment configuration."""
    console.print("[bold green]Initializing SOC Environment & Database Schemas...[/bold green]")
    Base.metadata.create_all(bind=engine)
    console.print("[green][OK] Database created successfully at soc_beacon.db[/green]")
    
    # Check sample files
    data_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "data"))
    os.makedirs(data_dir, exist_ok=True)
    console.print(f"[green][OK] Data directory verified at {data_dir}[/green]")

@app.command("ingest")
def ingest_dataset(name: str = typer.Option(..., "--name", help="Dataset name (CICIDS2017, LANL, WAF, COMPLIANCE)"),
                   path: str = typer.Option(..., "--path", help="Path to dataset file")):
    """Ingest network flow, auth log, or compliance datasets into database."""
    console.print(f"[bold cyan]Ingesting dataset [yellow]{name}[/yellow] from {path}...[/bold cyan]")
    if not os.path.exists(path):
        console.print(f"[bold red]Error: File {path} does not exist.[/bold red]")
        raise typer.Exit(code=1)

    name_upper = name.upper()
    if "CIC" in name_upper or "FLOW" in name_upper:
        count = ingest_cicids2017_csv(path, force=True)
        console.print(f"[bold green][OK] Ingested {count} network flow records into DB.[/bold green]")
    elif "LANL" in name_upper or "AUTH" in name_upper:
        count = ingest_lanl_auth_csv(path, force=True)
        console.print(f"[bold green][OK] Ingested {count} auth log records into DB.[/bold green]")
    elif "COMPLIANCE" in name_upper:
        count = ingest_compliance_json(path, force=True)
        console.print(f"[bold green][OK] Ingested {count} compliance findings into DB.[/bold green]")
    else:
        console.print(f"[bold red]Unknown dataset name {name}. Supported: CICIDS2017, LANL, COMPLIANCE[/bold red]")

@app.command("train-waf")
def train_waf(path: str = typer.Option("data/http_waf_payloads.csv", "--path", help="Path to HTTP payloads CSV")):
    """Train Smart WAF sequence/text classification model on HTTP request payloads."""
    console.print("[bold magenta]Training Smart WAF (DistilBERT/TF-IDF) Model...[/bold magenta]")
    import csv
    if not os.path.exists(path):
        console.print(f"[red]Payloads file {path} not found. Ingesting defaults...[/red]")
        return

    payloads = []
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        payloads = list(reader)

    res = waf_engine.train(payloads)
    console.print(Panel(f"[bold green]Smart WAF Training Complete![/bold green]\nSamples: {res['samples']}\nAccuracy: {res['accuracy'] * 100}%", title="WAF Model Training"))

@app.command("train-behavior")
def train_behavior():
    """Build heterogeneous graph and train Insider Threat GNN / Isolation Forest model."""
    console.print("[bold magenta]Building Behavioral Graph & Training Insider Threat Model...[/bold magenta]")
    session = SessionLocal()
    try:
        logs = session.query(AuthLog).all()
        log_dicts = [
            {
                "user_id": l.user_id,
                "device_id": l.device_id,
                "ip": l.ip,
                "resource": l.resource,
                "login_time": l.login_time,
                "success": l.success,
                "sensitive_access": l.sensitive_access
            }
            for l in logs
        ]
    finally:
        session.expunge_all()
        session.close()

    if not log_dicts:
        console.print("[yellow]No auth logs found in DB. Run 'soc ingest --name LANL --path data/lanl_auth_sample.csv' first.[/yellow]")
        return

    res = insider_engine.train(log_dicts)
    console.print(Panel(f"[bold green]Behavior Model Training Complete![/bold green]\nUsers Modeled: {res.get('users_modeled')}\nGraph Nodes: {res.get('nodes')}\nGraph Edges: {res.get('edges')}", title="Behavior Engine"))

@app.command("train-forecast")
def train_forecast():
    """Train PyTorch dual-head LSTM attack forecasting engine on flow sequences."""
    console.print("[bold magenta]Training PyTorch Attack Forecasting Engine (LSTM Dual-Head)...[/bold magenta]")
    session = SessionLocal()
    try:
        flows = session.query(NetworkFlow).all()
        flow_dicts = [
            {
                "src_ip": f.src_ip,
                "duration": f.duration,
                "total_fwd_packets": f.total_fwd_packets,
                "total_bwd_packets": f.total_bwd_packets,
                "total_length_fwd_packets": f.total_length_fwd_packets,
                "total_length_bwd_packets": f.total_length_bwd_packets,
                "flow_bytes_s": f.flow_bytes_s,
                "syn_flag_count": f.syn_flag_count,
                "rst_flag_count": f.rst_flag_count,
                "waf_risk": f.waf_risk,
                "behavior_risk": f.behavior_risk,
                "compliance_score": f.compliance_score,
                "attack_stage": f.attack_stage
            }
            for f in flows
        ]
    finally:
        session.expunge_all()
        session.close()

    if not flow_dicts:
        console.print("[yellow]No flows found in DB. Ingest CICIDS2017 dataset first.[/yellow]")
        return

    res = forecasting_engine.train(flow_dicts)
    console.print(Panel(f"[bold green]Forecasting Model Training Complete![/bold green]\nSequences Trained: {res.get('sequences_trained')}\nFinal Loss: {res.get('final_loss')}", title="Attack Forecasting Engine"))

@app.command("compliance-scan")
def compliance_scan(target: str = typer.Option("aws", "--target", help="Target environment: aws (Prowler) or k8s (kube-bench)")):
    """Run agentless compliance scan (Prowler/kube-bench) and ingest findings."""
    console.print(f"[bold yellow]Running Agentless Compliance Scan against [cyan]{target}[/cyan]...[/bold yellow]")
    findings = compliance_engine.run_scan(target)
    
    session = SessionLocal()
    try:
        for f in findings:
            item = ComplianceFinding(
                source=f["source"],
                control_id=f["control_id"],
                title=f["title"],
                severity=f["severity"],
                resource=f["resource"],
                description=f["description"],
                remediation=f["remediation"],
                status=f["status"],
                nciipc_guideline=f["nciipc_guideline"],
                plain_english_explanation=f["plain_english_explanation"]
            )
            session.add(item)
        session.commit()
    finally:
        session.expunge_all()
        session.close()

    table = Table(title=f"Agentless Compliance Findings ({target.upper()})")
    table.add_column("Control ID", style="bold yellow")
    table.add_column("Severity", style="bold red")
    table.add_column("Title", style="white")
    table.add_column("NCIIPC Alignment", style="green")

    for f in findings:
        table.add_row(f["control_id"], f["severity"], f["title"], f["nciipc_guideline"])

    console.print(table)

@app.command("behavior-anomalies")
def behavior_anomalies(user: str = typer.Option("USER_101", "--user", help="User ID to inspect")):
    """List insider threat behavioral risk and anomalies for a specific user."""
    session = SessionLocal()
    try:
        logs = session.query(AuthLog).filter(AuthLog.user_id == user).all()
        log_dicts = [
            {
                "user_id": l.user_id,
                "device_id": l.device_id,
                "ip": l.ip,
                "resource": l.resource,
                "login_time": l.login_time,
                "success": l.success,
                "sensitive_access": l.sensitive_access
            }
            for l in logs
        ]
    finally:
        session.expunge_all()
        session.close()

    if not log_dicts:
        console.print(f"[red]No logs found for user {user}[/red]")
        return

    res = insider_engine.compute_behavior_risk(user, log_dicts)
    color = "red" if res["behavior_risk"] > 0.6 else "yellow" if res["behavior_risk"] > 0.3 else "green"
    
    console.print(Panel(
        f"[bold {color}]Behavior Risk Score: {res['behavior_risk']}[/bold {color}]\n"
        f"Anomaly Indicators: {', '.join(res['anomaly_indicators']) or 'None'}\n"
        f"Features: Logins={res['features']['total_logins']}, Failures={res['features']['failed_logins']}, SensitiveAccess={res['features']['sensitive_accesses']}",
        title=f"Insider Threat Profile: {user}"
    ))

@app.command("forecast-session")
def forecast_session(session_id: str = typer.Option("SESS123", "--session", help="Session ID to forecast")):
    """Show attack stage forecast, next stage prediction, and escalation risk."""
    session = SessionLocal()
    try:
        flows = session.query(NetworkFlow).limit(10).all()
        flow_dicts = [
            {
                "src_ip": f.src_ip,
                "duration": f.duration,
                "total_fwd_packets": f.total_fwd_packets,
                "total_bwd_packets": f.total_bwd_packets,
                "total_length_fwd_packets": f.total_length_fwd_packets,
                "total_length_bwd_packets": f.total_length_bwd_packets,
                "flow_bytes_s": f.flow_bytes_s,
                "syn_flag_count": f.syn_flag_count,
                "rst_flag_count": f.rst_flag_count,
                "waf_risk": f.waf_risk,
                "behavior_risk": f.behavior_risk,
                "compliance_score": f.compliance_score,
                "attack_stage": f.attack_stage
            }
            for f in flows
        ]
    finally:
        session.expunge_all()
        session.close()

    res = forecasting_engine.forecast_session(flow_dicts)
    risk_color = "red" if res["escalation_risk"] > 0.7 else "yellow" if res["escalation_risk"] > 0.4 else "green"

    console.print(Panel(
        f"Session ID: [bold]{session_id}[/bold]\n"
        f"Current Attack Stage: [cyan]{res['current_stage']}[/cyan]\n"
        f"Predicted Next Stage: [bold magenta]{res['likely_next_stage']}[/bold magenta] (Confidence: {res['confidence']*100}%)\n"
        f"Escalation Risk: [bold {risk_color}]{res['escalation_risk']}[/bold {risk_color}]\n"
        f"ATT&CK Technique: {res['att_ck_mapping']}",
        title="AI Attack Forecasting Analysis"
    ))

@app.command("trust-status")
def trust_status(session_id: str = typer.Option("SESS123", "--session", help="Session ID")):
    """Show continuous trust score and recommended enforcement policy action."""
    # Compute mock/live trust status
    res = compute_trust_score(identity_trust=0.9, waf_risk=0.15, behavior_risk=0.25, forecast_risk=0.35, compliance_score=0.95)
    action_color = "green" if res["policy_action"] == "FULL_ACCESS" else "yellow" if res["policy_action"] == "RESTRICTED_ACCESS" else "red"

    console.print(Panel(
        f"Session ID: [bold]{session_id}[/bold]\n"
        f"Identity Trust: {res['identity_trust']}\n"
        f"WAF Risk: {res['waf_risk']}\n"
        f"Behavior Risk: {res['behavior_risk']}\n"
        f"Forecast Risk: {res['forecast_risk']}\n"
        f"Compliance Score: {res['compliance_score']}\n"
        f"----------------------------------------\n"
        f"Overall Trust Score: [bold cyan]{res['trust_score']}[/bold cyan]\n"
        f"Policy Enforcement: [bold {action_color}]{res['policy_action']}[/bold {action_color}]\n"
        f"Details: {res['policy_description']}",
        title="Continuous Trust Engine Evaluation"
    ))

@app.command("live-scan")
def live_scan_cli():
    """Execute live host device security scan and real-time attack forecasting."""
    from backend.app.scanner import execute_live_device_scan
    console.print("[bold yellow]Scanning Local Host Device & Running Live Attack Forecasting...[/bold yellow]")
    res = execute_live_device_scan()
    
    action_color = "green" if res["policy_action"] == "FULL_ACCESS" else "yellow" if res["policy_action"] == "RESTRICTED_ACCESS" else "red"

    console.print(Panel(
        f"Host Name: [bold]{res['host_info']['hostname']}[/bold] (IP: {res['host_info']['local_ip']})\n"
        f"OS Architecture: {res['host_info']['os']}\n"
        f"Scan Duration: {res['scan_duration_ms']} ms\n"
        f"----------------------------------------\n"
        f"Current Stage: [cyan]{res['forecast']['current_stage']}[/cyan]\n"
        f"Predicted Next Stage: [bold magenta]{res['forecast']['likely_next_stage']}[/bold magenta] (Confidence: {res['forecast']['confidence']*100}%)\n"
        f"Escalation Risk: [bold red]{res['forecast']['escalation_risk']*100}%[/bold red]\n"
        f"----------------------------------------\n"
        f"Continuous Trust Score: [bold cyan]{res['trust_score']}[/bold cyan]\n"
        f"Recommended Action: [bold {action_color}]{res['policy_action']}[/bold {action_color}]\n"
        f"Details: {res['policy_description']}",
        title="Live Device Security Scan & Attack Forecast"
    ))

if __name__ == "__main__":
    app()
