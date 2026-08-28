import React, { useEffect, useState } from 'react';
import { Network, Filter, RefreshCw, Cpu, Layers } from 'lucide-react';

export default function NetworkPage() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [filterStage, setFilterStage] = useState('');

  const loadFlows = () => {
    setLoading(true);
    const url = filterStage ? `/api/network/flows?stage=${filterStage}` : '/api/network/flows';
    fetch(url)
      .then(res => res.json())
      .then(d => {
        setData(d);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  };

  useEffect(() => {
    loadFlows();
  }, [filterStage]);

  const stages = ['BENIGN', 'RECON', 'INITIAL_ACCESS', 'CREDENTIAL_ACCESS', 'LATERAL_MOVEMENT', 'IMPACT'];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Header Controls */}
      <div className="glass-panel" style={{ padding: '1.5rem 2rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: '700', color: 'var(--beige-light)', display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <Network style={{ color: 'var(--beige-primary)' }} /> Network Traffic & Flow Analytics
          </h1>
          <p style={{ color: 'var(--beige-muted)', fontSize: '0.9rem', marginTop: '0.25rem' }}>
            CICFlowMeter-style ~80 feature ingestion (CIC-IDS2017 / UNSW-NB15 datasets)
          </p>
        </div>
        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
          <select 
            value={filterStage} 
            onChange={e => setFilterStage(e.target.value)}
            style={{ background: 'rgba(20, 18, 16, 0.95)', color: 'var(--beige-light)', border: '1px solid var(--border-color)', padding: '0.55rem 1rem', borderRadius: '8px', fontFamily: 'var(--font-sans)', outline: 'none' }}
          >
            <option value="">All Attack Stages</option>
            {stages.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <button className="glow-btn" onClick={loadFlows}>
            <RefreshCw size={16} /> Refresh
          </button>
        </div>
      </div>

      {/* Stage Breakdown Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: '0.75rem' }}>
        {stages.map(stage => {
          const count = data?.stage_distribution?.[stage] || 0;
          return (
            <div 
              key={stage} 
              className="glass-panel" 
              style={{ 
                padding: '1rem', 
                textAlign: 'center', 
                cursor: 'pointer', 
                border: filterStage === stage ? '1px solid var(--beige-primary)' : '1px solid var(--border-color)',
                background: filterStage === stage ? 'rgba(230, 213, 184, 0.1)' : 'var(--bg-card)'
              }} 
              onClick={() => setFilterStage(filterStage === stage ? '' : stage)}
            >
              <div style={{ fontSize: '0.75rem', color: 'var(--beige-muted)', fontWeight: '600' }}>{stage}</div>
              <div style={{ fontSize: '1.4rem', fontWeight: '700', color: stage === 'BENIGN' ? '#9EC298' : '#F07875', marginTop: '0.25rem' }}>
                {count}
              </div>
            </div>
          );
        })}
      </div>

      {/* Flows Table Panel */}
      <div className="glass-panel" style={{ padding: '1.5rem' }}>
        <h2 style={{ fontSize: '1.1rem', fontWeight: '600', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Layers style={{ color: 'var(--beige-gold)' }} /> Live Network Flow Records
        </h2>
        
        {loading ? (
          <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--beige-muted)' }}>Fetching flow records...</div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border-color)', color: 'var(--beige-muted)' }}>
                  <th style={{ padding: '0.75rem' }}>Timestamp</th>
                  <th style={{ padding: '0.75rem' }}>Source IP:Port</th>
                  <th style={{ padding: '0.75rem' }}>Destination IP:Port</th>
                  <th style={{ padding: '0.75rem' }}>Protocol</th>
                  <th style={{ padding: '0.75rem' }}>Duration (s)</th>
                  <th style={{ padding: '0.75rem' }}>Bytes/sec</th>
                  <th style={{ padding: '0.75rem' }}>Attack Stage</th>
                  <th style={{ padding: '0.75rem' }}>Label</th>
                </tr>
              </thead>
              <tbody>
                {(data?.flows || []).map((f) => (
                  <tr key={f.id} style={{ borderBottom: '1px solid rgba(212, 197, 169, 0.08)' }}>
                    <td style={{ padding: '0.75rem', color: 'var(--beige-muted)' }} className="mono-code">{f.timestamp}</td>
                    <td style={{ padding: '0.75rem', color: 'var(--beige-light)' }} className="mono-code">{f.src_ip}:{f.src_port}</td>
                    <td style={{ padding: '0.75rem', color: 'var(--beige-light)' }} className="mono-code">{f.dst_ip}:{f.dst_port}</td>
                    <td style={{ padding: '0.75rem', color: 'var(--beige-muted)' }}>{f.protocol === 6 ? 'TCP (6)' : 'UDP (17)'}</td>
                    <td style={{ padding: '0.75rem' }}>{f.duration}</td>
                    <td style={{ padding: '0.75rem' }}>{f.flow_bytes_s}</td>
                    <td style={{ padding: '0.75rem' }}>
                      <span className={`badge ${f.attack_stage === 'BENIGN' ? 'badge-low' : 'badge-critical'}`}>
                        {f.attack_stage}
                      </span>
                    </td>
                    <td style={{ padding: '0.75rem', color: 'var(--beige-muted)' }}>{f.label}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
