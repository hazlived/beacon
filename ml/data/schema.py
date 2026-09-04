"""Canonical schema: ATT&CK tactic set, column maps, label->tactic maps.

All label->tactic decisions are centralised here and are deliberately easy to
tune -- they need one review pass with the team (see ml/data/README.md).
"""
from __future__ import annotations

# --- Ordered tactic vocabulary (index = class id) --------------------------- -
# A1 review (2026-09-04): EXECUTION dropped -- 0 rows mapped to it in any source
# (Shellcode/exploit payloads are labelled INITIAL_ACCESS). 9-class vocabulary.
TACTICS = [
    "BENIGN",                 # 0
    "RECONNAISSANCE",         # 1  TA0043
    "INITIAL_ACCESS",         # 2  TA0001  (+ execution-on-access: shellcode, exploits)
    "CREDENTIAL_ACCESS",      # 3  TA0006
    "DISCOVERY",              # 4  TA0007
    "LATERAL_MOVEMENT",       # 5  TA0008
    "COMMAND_AND_CONTROL",    # 6  TA0011
    "EXFILTRATION",           # 7  TA0010
    "IMPACT",                 # 8  TA0040
]
TACTIC_TO_ID = {t: i for i, t in enumerate(TACTICS)}
ID_TO_TACTIC = {i: t for i, t in enumerate(TACTICS)}
UNLABELED = "__UNLABELED__"          # rows we cannot label -> excluded from supervised sets
ESCALATION_TACTICS = {"EXFILTRATION", "IMPACT"}   # define "reached impact"

# --- Canonical CICFlowMeter-v4 header (used when a CSV ships without one) --- -
CICFLOWMETER_V4_COLUMNS = [
    "Flow ID", "Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol", "Timestamp",
    "Flow Duration", "Total Fwd Packet", "Total Bwd packets",
    "Total Length of Fwd Packet", "Total Length of Bwd Packet",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
    "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
    "Packet Length Min", "Packet Length Max", "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count",
    "ACK Flag Count", "URG Flag Count", "CWR Flag Count", "ECE Flag Count",
    "Down/Up Ratio", "Average Packet Size", "Fwd Segment Size Avg", "Bwd Segment Size Avg",
    "Fwd Bytes/Bulk Avg", "Fwd Packet/Bulk Avg", "Fwd Bulk Rate Avg",
    "Bwd Bytes/Bulk Avg", "Bwd Packet/Bulk Avg", "Bwd Bulk Rate Avg",
    "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes",
    "FWD Init Win Bytes", "Bwd Init Win Bytes", "Fwd Act Data Pkts", "Fwd Seg Size Min",
    "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
    "Activity", "Stage",
]

# --- Canonical numeric flow feature names (shared target schema) ------------ -
CANON_FLOW_FEATURES = [
    "duration", "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes",
    "fwd_pkt_len_max", "fwd_pkt_len_min", "fwd_pkt_len_mean", "fwd_pkt_len_std",
    "bwd_pkt_len_max", "bwd_pkt_len_min", "bwd_pkt_len_mean", "bwd_pkt_len_std",
    "flow_bytes_s", "flow_pkts_s",
    "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",
    "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max", "fwd_iat_min",
    "bwd_iat_mean", "bwd_iat_std", "bwd_iat_max", "bwd_iat_min",
    "fin_flags", "syn_flags", "rst_flags", "psh_flags", "ack_flags", "urg_flags", "cwr_flags", "ece_flags",
    "fwd_header_len", "bwd_header_len", "fwd_pkts_s", "bwd_pkts_s",
    "pkt_len_min", "pkt_len_max", "pkt_len_mean", "pkt_len_std", "pkt_len_var",
    "down_up_ratio", "avg_pkt_size", "fwd_seg_size_avg", "bwd_seg_size_avg",
    "subflow_fwd_pkts", "subflow_fwd_bytes", "subflow_bwd_pkts", "subflow_bwd_bytes",
    "fwd_init_win", "bwd_init_win", "fwd_act_data_pkts", "fwd_seg_size_min",
    "active_mean", "active_std", "active_max", "active_min",
    "idle_mean", "idle_std", "idle_max", "idle_min",
    "ttl_src", "ttl_dst",          # UNSW only; NaN for CICFlowMeter sources
]

# CICFlowMeter header -> canonical feature name
CIC_TO_CANON = {
    "Flow Duration": "duration",
    "Total Fwd Packet": "fwd_pkts", "Total Bwd packets": "bwd_pkts",
    "Total Length of Fwd Packet": "fwd_bytes", "Total Length of Bwd Packet": "bwd_bytes",
    "Fwd Packet Length Max": "fwd_pkt_len_max", "Fwd Packet Length Min": "fwd_pkt_len_min",
    "Fwd Packet Length Mean": "fwd_pkt_len_mean", "Fwd Packet Length Std": "fwd_pkt_len_std",
    "Bwd Packet Length Max": "bwd_pkt_len_max", "Bwd Packet Length Min": "bwd_pkt_len_min",
    "Bwd Packet Length Mean": "bwd_pkt_len_mean", "Bwd Packet Length Std": "bwd_pkt_len_std",
    "Flow Bytes/s": "flow_bytes_s", "Flow Packets/s": "flow_pkts_s",
    "Flow IAT Mean": "flow_iat_mean", "Flow IAT Std": "flow_iat_std",
    "Flow IAT Max": "flow_iat_max", "Flow IAT Min": "flow_iat_min",
    "Fwd IAT Mean": "fwd_iat_mean", "Fwd IAT Std": "fwd_iat_std",
    "Fwd IAT Max": "fwd_iat_max", "Fwd IAT Min": "fwd_iat_min",
    "Bwd IAT Mean": "bwd_iat_mean", "Bwd IAT Std": "bwd_iat_std",
    "Bwd IAT Max": "bwd_iat_max", "Bwd IAT Min": "bwd_iat_min",
    "FIN Flag Count": "fin_flags", "SYN Flag Count": "syn_flags", "RST Flag Count": "rst_flags",
    "PSH Flag Count": "psh_flags", "ACK Flag Count": "ack_flags", "URG Flag Count": "urg_flags",
    "CWR Flag Count": "cwr_flags", "ECE Flag Count": "ece_flags",
    "Fwd Header Length": "fwd_header_len", "Bwd Header Length": "bwd_header_len",
    "Fwd Packets/s": "fwd_pkts_s", "Bwd Packets/s": "bwd_pkts_s",
    "Packet Length Min": "pkt_len_min", "Packet Length Max": "pkt_len_max",
    "Packet Length Mean": "pkt_len_mean", "Packet Length Std": "pkt_len_std",
    "Packet Length Variance": "pkt_len_var",
    "Down/Up Ratio": "down_up_ratio", "Average Packet Size": "avg_pkt_size",
    "Fwd Segment Size Avg": "fwd_seg_size_avg", "Bwd Segment Size Avg": "bwd_seg_size_avg",
    "Subflow Fwd Packets": "subflow_fwd_pkts", "Subflow Fwd Bytes": "subflow_fwd_bytes",
    "Subflow Bwd Packets": "subflow_bwd_pkts", "Subflow Bwd Bytes": "subflow_bwd_bytes",
    "FWD Init Win Bytes": "fwd_init_win", "Bwd Init Win Bytes": "bwd_init_win",
    "Fwd Act Data Pkts": "fwd_act_data_pkts", "Fwd Seg Size Min": "fwd_seg_size_min",
    "Active Mean": "active_mean", "Active Std": "active_std",
    "Active Max": "active_max", "Active Min": "active_min",
    "Idle Mean": "idle_mean", "Idle Std": "idle_std", "Idle Max": "idle_max", "Idle Min": "idle_min",
}
CIC_META = {
    "Src IP": "src_ip", "Dst IP": "dst_ip", "Src Port": "src_port",
    "Dst Port": "dst_port", "Protocol": "protocol", "Timestamp": "ts_raw",
}

# UNSW-NB15 (49-col, no header) -> canonical
UNSW_COLUMNS = [
    "srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes", "dbytes",
    "sttl", "dttl", "sloss", "dloss", "service", "sload", "dload", "spkts", "dpkts",
    "swin", "dwin", "stcpb", "dtcpb", "smeansz", "dmeansz", "trans_depth", "res_bdy_len",
    "sjit", "djit", "stime", "ltime", "sintpkt", "dintpkt", "tcprtt", "synack", "ackdat",
    "is_sm_ips_ports", "ct_state_ttl", "ct_flw_http_mthd", "is_ftp_login", "ct_ftp_cmd",
    "ct_srv_src", "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm",
    "ct_dst_sport_ltm", "ct_dst_src_ltm", "attack_cat", "label",
]
UNSW_TO_CANON = {
    "dur": "duration", "spkts": "fwd_pkts", "dpkts": "bwd_pkts",
    "sbytes": "fwd_bytes", "dbytes": "bwd_bytes",
    "smeansz": "fwd_pkt_len_mean", "dmeansz": "bwd_pkt_len_mean",
    "sintpkt": "fwd_iat_mean", "dintpkt": "bwd_iat_mean",
    "sload": "flow_bytes_s", "swin": "fwd_init_win", "dwin": "bwd_init_win",
    "sttl": "ttl_src", "dttl": "ttl_dst",
}
UNSW_CT_FEATURES = [
    "ct_state_ttl", "ct_flw_http_mthd", "ct_ftp_cmd", "ct_srv_src", "ct_srv_dst",
    "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm",
]
PROTO_NAME_TO_NUM = {"tcp": 6, "udp": 17, "icmp": 1, "arp": 0, "unas": 0}

# --- label -> tactic -------------------------------------------------------- -
DAPT_STAGE_TO_TACTIC = {
    "benign": "BENIGN",
    "reconnaissance": "RECONNAISSANCE",
    "establish foothold": "INITIAL_ACCESS",
    "lateral movement": "LATERAL_MOVEMENT",
    "data exfiltration": "EXFILTRATION",
    "internal reconnaissance": "DISCOVERY",
}

def _norm(s: str) -> str:
    return " ".join(str(s).strip().lower().replace("-", " ").replace("_", " ").split())

CIC_LABEL_TO_TACTIC = {
    "benign": "BENIGN",
    "ftp patator": "CREDENTIAL_ACCESS", "ssh patator": "CREDENTIAL_ACCESS",
    "ftp bruteforce": "CREDENTIAL_ACCESS", "ssh bruteforce": "CREDENTIAL_ACCESS",
    "portscan": "RECONNAISSANCE",
    "infiltration portscan": "DISCOVERY",
    "infiltration": "LATERAL_MOVEMENT",
    "web attack brute force": "CREDENTIAL_ACCESS",
    "web attack xss": "INITIAL_ACCESS",
    "web attack sql injection": "INITIAL_ACCESS",
    "sql injection": "INITIAL_ACCESS",
    "brute force web": "CREDENTIAL_ACCESS", "brute force xss": "INITIAL_ACCESS",
    "botnet": "COMMAND_AND_CONTROL", "bot": "COMMAND_AND_CONTROL",
    "heartbleed": "IMPACT",
    "dos hulk": "IMPACT", "dos goldeneye": "IMPACT", "dos slowloris": "IMPACT",
    "dos slowhttptest": "IMPACT", "ddos": "IMPACT",
    "dos attacks hulk": "IMPACT", "dos attacks goldeneye": "IMPACT",
    "dos attacks slowloris": "IMPACT", "dos attacks slowhttptest": "IMPACT",
    "ddos attacks loic http": "IMPACT", "ddos attack loic udp": "IMPACT",
    "ddos attack hoic": "IMPACT", "dos attacks loic udp": "IMPACT",
}
UNSW_CAT_TO_TACTIC = {
    "normal": "BENIGN",
    "reconnaissance": "RECONNAISSANCE", "analysis": "RECONNAISSANCE",
    "fuzzers": "DISCOVERY",
    "exploits": "INITIAL_ACCESS", "shellcode": "INITIAL_ACCESS",
    "backdoor": "COMMAND_AND_CONTROL", "backdoors": "COMMAND_AND_CONTROL",
    "worms": "LATERAL_MOVEMENT",
    "generic": "IMPACT", "dos": "IMPACT",
}


def label_to_tactic(source: str, raw: str, attempted: bool = False) -> str:
    """Map a dataset-native label string to a canonical tactic."""
    if attempted:
        return "BENIGN"                       # DistriNet: "- Attempted" is never its own class
    key = _norm(raw)
    if key in ("", "nan", "none"):
        return UNLABELED
    if key.endswith(" attempted"):
        return "BENIGN"
    if source == "dapt2020":
        return DAPT_STAGE_TO_TACTIC.get(key, UNLABELED)
    if source in ("cicids2017", "cicids2018"):
        return CIC_LABEL_TO_TACTIC.get(key, UNLABELED)
    if source == "unsw_nb15":
        return UNSW_CAT_TO_TACTIC.get(key, UNLABELED)
    return UNLABELED
