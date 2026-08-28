import React, { useEffect, useState } from 'react';
import { 
  Shield, 
  ShieldAlert, 
  Activity, 
  Lock, 
  AlertTriangle, 
  CheckCircle2, 
  Radio, 
  Server,
  Layers,
  Radar
} from 'lucide-react';
import BeaconLogo from '../components/BeaconLogo';

export default function Overview({ onOpenLiveScan }) {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/api/overview/stats')
      .then(res => res.json())
      .then(data => {
        setStats(data);
        setLoading(false);
      })
      .catch(err => {
        console.error('Error fetching overview stats:', err);
        setLoading(false);
      });
  }, []);

  if (loading) {
    return (
      <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--beige-muted)' }}>
        <Activity size={24} className="pulse-dot" style={{ margin: '0 auto 1rem auto' }} />
        <div>Loading SOC System Telemetry...</div>
      </div>
    );
  }

  const m = stats?.metrics || {
    total_flows: 500,
    attacks_detected: 250,
    open_compliance_findings: 4,
    auth_logs_ingested: 300,
    high_trust_sessions: 6,
    medium_trust_sessions: 2,
    low_trust_sessions: 1
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Header Banner */}
      <div className="glass-panel" style={{ padding: '1.5rem 2rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: '700', color: 'var(--beige-light)', display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <BeaconLogo size={32} /> BEACON SOC Overview
          </h1>
          <p style={{ color: 'var(--beige-muted)', fontSize: '0.9rem', marginTop: '0.25rem' }}>
            Real-Time Network Attack Forecasting & Behavioral Security Engine
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <button 
            className="glow-btn"
            onClick={onOpenLiveScan}
            style={{ padding: '0.6rem 1.25rem', background: 'linear-gradient(135deg, #F8F5EE, #E6D5B8)', color: '#0c0b0a' }}
          >
            <Radar size={18} /> Initiate Live Scan
          </button>
        </div>
      </div>

      {/* Metric Cards Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1rem' }}>
        <div className="glass-panel" style={{ padding: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--beige-muted)' }}>
            <span style={{ fontSize: '0.85rem' }}>Total Flow Records</span>
            <Activity size={20} color="var(--beige-primary)" />
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: '700', marginTop: '0.5rem', color: 'var(--beige-light)' }}>
            {m.total_flows}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--beige-muted)', marginTop: '0.25rem' }}>
            CIC-IDS2017 Format ~80 features
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--beige-muted)' }}>
            <span style={{ fontSize: '0.85rem' }}>Attacks Detected</span>
            <AlertTriangle size={20} color="var(--status-critical)" />
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: '700', marginTop: '0.5rem', color: 'var(--status-critical)' }}>
            {m.attacks_detected}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--beige-muted)', marginTop: '0.25rem' }}>
            RECON, Web, BruteForce, DoS
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--beige-muted)' }}>
            <span style={{ fontSize: '0.85rem' }}>Compliance Findings</span>
            <ShieldAlert size={20} color="var(--status-high)" />
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: '700', marginTop: '0.5rem', color: 'var(--status-high)' }}>
            {m.open_compliance_findings} Open
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--beige-muted)', marginTop: '0.25rem' }}>
            Prowler & kube-bench CIS
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--beige-muted)' }}>
            <span style={{ fontSize: '0.85rem' }}>Auth & Behavior Logs</span>
            <Lock size={20} color="var(--beige-gold)" />
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: '700', marginTop: '0.5rem', color: 'var(--beige-light)' }}>
            {m.auth_logs_ingested}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--beige-gold)', marginTop: '0.25rem' }}>
            LANL Lateral Movement Logs
          </div>
        </div>
      </div>

      {/* Two Column Layout: Continuous Trust Matrix & Live Threat Feed */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
        {/* Continuous Trust Matrix */}
        <div className="glass-panel" style={{ padding: '1.5rem' }}>
          <h2 style={{ fontSize: '1.1rem', fontWeight: '600', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Shield style={{ color: 'var(--beige-primary)' }} /> Continuous Trust Matrix
          </h2>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div style={{ padding: '1rem', background: 'rgba(122, 154, 116, 0.1)', borderRadius: '8px', border: '1px solid rgba(122, 154, 116, 0.3)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <div style={{ fontWeight: '600', color: '#9EC298', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  <CheckCircle2 size={16} /> Full Access Policy (Trust ≥ 0.8)
                </div>
                <div style={{ fontSize: '0.8rem', color: 'var(--beige-muted)' }}>Unrestricted access, continuous monitoring</div>
              </div>
              <div style={{ fontSize: '1.5rem', fontWeight: '700', color: '#9EC298' }}>{m.high_trust_sessions}</div>
            </div>

            <div style={{ padding: '1rem', background: 'rgba(217, 155, 38, 0.1)', borderRadius: '8px', border: '1px solid rgba(217, 155, 38, 0.3)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <div style={{ fontWeight: '600', color: '#E8B452', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  <AlertTriangle size={16} /> Restricted Access Policy (0.5 ≤ Trust &lt; 0.8)
                </div>
                <div style={{ fontSize: '0.8rem', color: 'var(--beige-muted)' }}>Step-up MFA, read-only permissions</div>
              </div>
              <div style={{ fontSize: '1.5rem', fontWeight: '700', color: '#E8B452' }}>{m.medium_trust_sessions}</div>
            </div>

            <div style={{ padding: '1rem', background: 'rgba(217, 83, 79, 0.1)', borderRadius: '8px', border: '1px solid rgba(217, 83, 79, 0.3)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <div style={{ fontWeight: '600', color: '#F07875', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  <ShieldAlert size={16} /> Containment & Isolation (Trust &lt; 0.5)
                </div>
                <div style={{ fontSize: '0.8rem', color: 'var(--beige-muted)' }}>Session kill, IP block, SOC alert</div>
              </div>
              <div style={{ fontSize: '1.5rem', fontWeight: '700', color: '#F07875' }}>{m.low_trust_sessions}</div>
            </div>
          </div>
        </div>

        {/* Live Threat Telemetry Feed */}
        <div className="glass-panel" style={{ padding: '1.5rem' }}>
          <h2 style={{ fontSize: '1.1rem', fontWeight: '600', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Activity style={{ color: 'var(--beige-gold)' }} /> Live Threat Telemetry Feed
          </h2>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', maxHeight: '280px', overflowY: 'auto' }}>
            {(stats?.recent_live_feed || []).map((feed, idx) => (
              <div key={idx} style={{ padding: '0.75rem 1rem', background: 'rgba(255, 255, 255, 0.02)', borderRadius: '8px', borderLeft: feed.stage === 'BENIGN' ? '4px solid var(--status-low)' : '4px solid var(--status-critical)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <div style={{ fontSize: '0.85rem', fontWeight: '600', color: 'var(--beige-light)' }} className="mono-code">
                    {feed.src_ip} &rarr; {feed.dst_ip}
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--beige-muted)' }}>{feed.label}</div>
                </div>
                <span className={`badge ${feed.stage === 'BENIGN' ? 'badge-low' : 'badge-critical'}`}>
                  {feed.stage}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
