import sys
import os
sys.path.insert(0, os.path.abspath("."))

from datetime import datetime
from backend.app.ml.behavior import insider_engine

# Synthetic normal users
normal_users_logs = {
    "USER_N1": [
        {
            "user_id": "USER_N1",
            "device_id": "DEV_WORKSTATION_1",
            "ip": "192.168.1.20",
            "resource": "/api/v1/auth",
            "login_time": datetime.utcnow(),
            "success": 1,
            "sensitive_access": 0,
        }
    ],
    "USER_N2": [
        {
            "user_id": "USER_N2",
            "device_id": "DEV_WORKSTATION_2",
            "ip": "192.168.1.21",
            "resource": "/api/v1/auth",
            "login_time": datetime.utcnow(),
            "success": 1,
            "sensitive_access": 0,
        }
    ],
}

# Synthetic anomalous users
anomalous_users_logs = {
    "USER_A1": [
        {
            "user_id": "USER_A1",
            "device_id": "DEV_WORKSTATION_99",
            "ip": "10.0.4.99",
            "resource": "/admin/db_backup",
            "login_time": datetime.utcnow(),
            "success": 0,
            "sensitive_access": 1,
        },
        {
            "user_id": "USER_A1",
            "device_id": "DEV_WORKSTATION_99",
            "ip": "10.0.4.99",
            "resource": "/admin/db_backup",
            "login_time": datetime.utcnow(),
            "success": 0,
            "sensitive_access": 1,
        },
        {
            "user_id": "USER_A1",
            "device_id": "DEV_WORKSTATION_99",
            "ip": "10.0.4.99",
            "resource": "/admin/db_backup",
            "login_time": datetime.utcnow(),
            "success": 1,
            "sensitive_access": 1,
        },
    ],
    "USER_A2": [
        {
            "user_id": "USER_A2",
            "device_id": "DEV_WORKSTATION_88",
            "ip": "10.0.4.88",
            "resource": "/finance/records",
            "login_time": datetime.utcnow(),
            "success": 0,
            "sensitive_access": 1,
        },
        {
            "user_id": "USER_A2",
            "device_id": "DEV_WORKSTATION_88",
            "ip": "10.0.4.88",
            "resource": "/finance/records",
            "login_time": datetime.utcnow(),
            "success": 0,
            "sensitive_access": 1,
        },
    ],
}

if __name__ == "__main__":
    result = insider_engine.evaluate(normal_users_logs, anomalous_users_logs)
    print("Behavior model evaluation:")
    for k, v in result.items():
        print(f"  {k}: {v}")
