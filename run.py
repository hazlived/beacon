import os
import subprocess
import sys
import time

def main():
    print("=" * 60)
    print("  BEACON AI-Based Network Attack Forecasting SOC")
    print("=" * 60)

    project_root = os.path.abspath(os.path.dirname(__file__))
    os.chdir(project_root)

    print("[1/2] Starting FastAPI Backend on http://localhost:8000 ...")
    backend_proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"],
        cwd=project_root
    )

    time.sleep(2)

    frontend_dir = os.path.join(project_root, "frontend")
    print("[2/2] Starting Frontend React Dev Server on http://localhost:5173 ...")
    frontend_proc = subprocess.Popen(
        ["npx", "vite", "--port", "5173", "--host"],
        shell=True,
        cwd=frontend_dir
    )

    print("\n[SUCCESS] BEACON SOC System is live and accessible at:")
    print("  - GUI Dashboard: http://localhost:5173")
    print("  - API Documentation (Swagger): http://localhost:8000/docs")
    print("\nPress Ctrl+C to terminate services.")

    try:
        backend_proc.wait()
        frontend_proc.wait()
    except KeyboardInterrupt:
        print("\nShutting down BEACON SOC services...")
        backend_proc.terminate()
        frontend_proc.terminate()

if __name__ == "__main__":
    main()
