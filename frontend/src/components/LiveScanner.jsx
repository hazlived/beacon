import React, { useState } from 'react';
import { 
  Radar, 
  X, 
  ShieldAlert, 
  CheckCircle2, 
  AlertTriangle, 
  Cpu, 
  Server, 
  Zap, 
  TrendingUp, 
  Activity,
  Terminal
} from 'lucide-react';

export default function LiveScanner({ onClose }) {
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);

  const startScan = () => {
    setScanning(true);
    setScanResult(null);

    fetch('/api/scan/live', { method: 'POST' })
      .then(res => res.json())
      .then(data => {
        setTimeout(() => {
          setScanResult(data);
          setScanning(false);
        }, 1200);
      })
      .catch(err => {
        console.error('Live scan failed:', err);
        setScanning(false);
      });
  };

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      backgroundColor: 'rgba(9, 9, 8, 0.85)',
      backdropFilter: 'blur(10px)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 9999,
      padding: '2rem'
    }} className="animate-fade-in">
      <div className="glass-panel" style={{ width: '100%', maxWidth: '850px', maxHeight: '90vh', overflowY: 'auto', padding: '2rem', border: '1px solid var(--border-glow)' }}>
        
        {/* Modal Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-color)', paddingBottom: '1rem', marginBottom: '1.5rem' }}>
          <div>
            <h2 style={{ fontSize: '1.3rem', fontWeight: '700', color: 'var(--beige-light)', display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
              <Radar size={22} color="var(--beige-primary)" className={scanning ? 'pulse-dot' : ''} /> Live Device Security Scan & Forecasting
            </h2>
            <p style={{ fontSize: '0.85rem', color: 'var(--beige-muted)', marginTop: '0.2rem' }}>
              Inspect local host environment, active sockets, PyTorch LSTM attack forecast & trust score
            </p>
          </div>
          <button onClick={onClose} style={{ background: 'transparent', border: 'none', color: 'var(--beige-muted)', cursor: 'pointer', padding: '0.25rem' }}>
            <X size={22} />
          </button>
        </div>

        {/* Start Scan Trigger Banner */}
        {!scanResult && !scanning && (
          <div style={{ padding: '2.5rem', textAlign: 'center', background: 'rgba(255, 255, 255, 0.02)', borderRadius: '12px', border: '1px border-dashed var(--border-color)' }}>
            <Activity size={48} color="var(--beige-primary)" style={{ margin: '0 auto 1rem auto' }} />
            <h3 style={{ fontSize: '1.1rem', fontWeight: '600', color: 'var(--beige-light)', marginBottom: '0.5rem' }}>
              Ready to Scan Local Device
            </h3>
            <p style={{ fontSize: '0.85rem', color: 'var(--beige-muted)', maxWidth: '500px', margin: '0 auto 1.5rem auto' }}>
              Click below to initiate a real-time host inspection, socket audit, and PyTorch LSTM sequence attack forecast.
            </p>
            <button className="glow-btn" onClick={startScan} style={{ padding: '0.8rem 2rem', fontSize: '0.95rem' }}>
              <Radar size={18} /> Initiate Live Device Scan
            </button>
          </div>
        )}

        {/* Scanning Animated Loading Indicator */}
        {scanning && (
          <div style={{ padding: '3rem', textAlign: 'center' }}>
            <Radar size={56} color="var(--beige-primary)" style={{ animation: 'spin 2s linear infinite', margin: '0 auto 1.5rem auto' }} />
            <h3 style={{ fontSize: '1.2rem', fontWeight: '700', color: 'var(--beige-light)' }}>Scanning Host Device Telemetry...</h3>
            <p style={{ fontSize: '0.85rem', color: 'var(--beige-muted)', marginTop: '0.4rem' }}>
              Evaluating open sockets, Smart WAF payloads, and PyTorch LSTM sequence predictions
            </p>
          </div>
        )}

        {/* Live Scan Results View */}
        {scanResult && !scanning && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
            {/* Host Details Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1rem' }}>
              <div style={{ padding: '1rem', background: 'rgba(255, 255, 255, 0.02)', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
                <div style={{ fontSize: '0.75rem', color: 'var(--beige-muted)' }}>Host Name</div>
                <div style={{ fontSize: '1.1rem', fontWeight: '700', color: 'var(--beige-light)', marginTop: '0.2rem' }} className="mono-code">
                  {scanResult.host_info.hostname}
                </div>
              </div>

              <div style={{ padding: '1rem', background: 'rgba(255, 255, 255, 0.02)', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
                <div style={{ fontSize: '0.75rem', color: 'var(--beige-muted)' }}>Local IP Address</div>
                <div style={{ fontSize: '1.1rem', fontWeight: '700', color: 'var(--beige-primary)', marginTop: '0.2rem' }} className="mono-code">
                  {scanResult.host_info.local_ip}
                </div>
              </div>

              <div style={{ padding: '1rem', background: 'rgba(255, 255, 255, 0.02)', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
                <div style={{ fontSize: '0.75rem', color: 'var(--beige-muted)' }}>Scan Duration</div>
                <div style={{ fontSize: '1.1rem', fontWeight: '700', color: 'var(--beige-gold)', marginTop: '0.2rem' }}>
                  {scanResult.scan_duration_ms} ms
                </div>
              </div>
            </div>

            {/* PyTorch Attack Forecasting Live Results */}
            <div style={{ padding: '1.25rem', background: 'rgba(217, 83, 79, 0.12)', borderRadius: '10px', border: '1px solid rgba(217, 83, 79, 0.35)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
                <span style={{ fontSize: '0.85rem', fontWeight: '700', color: '#F07875', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  <TrendingUp size={18} /> PyTorch LSTM Live Sequence Forecast
                </span>
                <span className="badge badge-critical">
                  Escalation Risk: {(scanResult.forecast.escalation_risk * 100).toFixed(0)}%
                </span>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginTop: '0.5rem' }}>
                <div>
                  <div style={{ fontSize: '0.8rem', color: 'var(--beige-muted)' }}>Current Stage &rarr; Predicted Next Stage:</div>
                  <div style={{ fontSize: '1.1rem', fontWeight: '700', color: 'var(--beige-light)', marginTop: '0.2rem' }}>
                    <span style={{ color: 'var(--beige-muted)' }}>{scanResult.forecast.current_stage}</span> &rarr; <span style={{ color: '#F07875' }}>{scanResult.forecast.likely_next_stage}</span>
                  </div>
                </div>
                <div>
                  <div style={{ fontSize: '0.8rem', color: 'var(--beige-muted)' }}>Continuous Trust Score:</div>
                  <div style={{ fontSize: '1.1rem', fontWeight: '700', color: 'var(--beige-primary)', marginTop: '0.2rem' }}>
                    {scanResult.trust_score} ({scanResult.policy_action})
                  </div>
                </div>
              </div>

              <div style={{ fontSize: '0.8rem', color: 'var(--beige-light)', marginTop: '0.75rem', fontStyle: 'italic' }}>
                ATT&CK Alignment: {scanResult.forecast.att_ck_mapping}
              </div>
            </div>

            {/* Active Sockets Audit Table */}
            <div>
              <h3 style={{ fontSize: '0.95rem', fontWeight: '600', color: 'var(--beige-light)', marginBottom: '0.75rem' }}>
                Active Host Listening Ports & Sockets:
              </h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                {scanResult.open_sockets.map((sock, i) => (
                  <div key={i} style={{ padding: '0.6rem 0.9rem', background: 'rgba(255, 255, 255, 0.02)', borderRadius: '6px', border: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.85rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                      <span className="mono-code" style={{ fontWeight: '700', color: 'var(--beige-primary)' }}>Port {sock.port}</span>
                      <span style={{ color: 'var(--beige-light)' }}>{sock.service}</span>
                      <span style={{ fontSize: '0.75rem', color: 'var(--beige-muted)' }}>({sock.description})</span>
                    </div>
                    <span className={`badge ${sock.risk === 'CRITICAL' || sock.risk === 'HIGH' ? 'badge-critical' : 'badge-low'}`}>
                      {sock.status} ({sock.risk})
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Actionable Recommendations */}
            <div>
              <h3 style={{ fontSize: '0.95rem', fontWeight: '600', color: 'var(--beige-light)', marginBottom: '0.75rem' }}>
                Remediation Actions:
              </h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
                {scanResult.recommendations.map((rec, i) => (
                  <div key={i} style={{ padding: '0.75rem 1rem', background: 'rgba(10, 9, 8, 0.6)', borderRadius: '6px', borderLeft: rec.severity === 'CRITICAL' ? '4px solid var(--status-critical)' : '4px solid var(--beige-primary)' }}>
                    <div style={{ fontWeight: '600', color: 'var(--beige-light)', fontSize: '0.85rem' }}>{rec.title}</div>
                    <div style={{ fontSize: '0.8rem', color: 'var(--beige-muted)', marginTop: '0.2rem' }}>{rec.description}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Re-Scan Button */}
            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '0.5rem' }}>
              <button className="glow-btn" onClick={startScan}>
                <Radar size={16} /> Re-Scan Host
              </button>
            </div>
          </div>
        )}

      </div>
    </div>
  );
}
