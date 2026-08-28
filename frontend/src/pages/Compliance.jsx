import React, { useEffect, useState } from 'react';
import { ShieldCheck, Cloud, Server, AlertOctagon, CheckCircle2, FileText, AlertTriangle } from 'lucide-react';

export default function CompliancePage() {
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filterSource, setFilterSource] = useState('');

  useEffect(() => {
    fetch('/api/compliance/findings')
      .then(r => r.json())
      .then(d => {
        setFindings(d);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  const filtered = filterSource ? findings.filter(f => f.source === filterSource) : findings;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Header */}
      <div className="glass-panel" style={{ padding: '1.5rem 2rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: '700', color: 'var(--beige-light)', display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <ShieldCheck style={{ color: 'var(--beige-primary)' }} /> Auto Compliance & Configuration Checker
          </h1>
          <p style={{ color: 'var(--beige-muted)', fontSize: '0.9rem', marginTop: '0.25rem' }}>
            Agentless Cloud & Kubernetes CIS Audits mapped directly to Indian NCIIPC Guidelines
          </p>
        </div>
        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <button 
            className="glow-btn" 
            onClick={() => setFilterSource(filterSource === 'prowler' ? '' : 'prowler')}
            style={{ background: filterSource === 'prowler' ? 'linear-gradient(135deg, #E6D5B8, #C5B358)' : 'rgba(20, 18, 16, 0.95)', color: filterSource === 'prowler' ? '#0c0b0a' : 'var(--beige-light)' }}
          >
            <Cloud size={16} /> AWS (Prowler)
          </button>
          <button 
            className="glow-btn" 
            onClick={() => setFilterSource(filterSource === 'kube-bench' ? '' : 'kube-bench')}
            style={{ background: filterSource === 'kube-bench' ? 'linear-gradient(135deg, #E6D5B8, #C5B358)' : 'rgba(20, 18, 16, 0.95)', color: filterSource === 'kube-bench' ? '#0c0b0a' : 'var(--beige-light)' }}
          >
            <Server size={16} /> Kubernetes (kube-bench)
          </button>
        </div>
      </div>

      {/* Compliance Findings List */}
      <div className="glass-panel" style={{ padding: '1.5rem' }}>
        <h2 style={{ fontSize: '1.1rem', fontWeight: '600', marginBottom: '1.25rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <FileText style={{ color: 'var(--beige-gold)' }} /> CIS Benchmark & NCIIPC Compliance Audit Findings
        </h2>

        {loading ? (
          <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--beige-muted)' }}>Running agentless scan analysis...</div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            {filtered.map((item) => {
              const isCrit = item.severity === 'CRITICAL';
              const isHigh = item.severity === 'HIGH';
              const badgeClass = isCrit ? 'badge-critical' : isHigh ? 'badge-high' : 'badge-medium';

              return (
                <div key={item.id} style={{ padding: '1.25rem', background: 'rgba(255, 255, 255, 0.02)', borderRadius: '10px', border: '1px solid var(--border-color)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '1rem' }}>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                        <span className="mono-code" style={{ fontSize: '0.85rem', color: 'var(--beige-gold)', fontWeight: '700' }}>
                          [{item.source.toUpperCase()}] {item.control_id}
                        </span>
                        <h3 style={{ fontSize: '1rem', fontWeight: '600', color: 'var(--beige-light)' }}>{item.title}</h3>
                      </div>
                      <div style={{ fontSize: '0.8rem', color: 'var(--beige-primary)', marginTop: '0.35rem', fontWeight: '500' }}>
                        {item.nciipc_guideline}
                      </div>
                    </div>
                    <span className={`badge ${badgeClass}`}>{item.severity}</span>
                  </div>

                  {/* Description & Remediation */}
                  <div style={{ marginTop: '1rem', padding: '0.75rem 1rem', background: 'rgba(10, 9, 8, 0.6)', borderRadius: '6px', fontSize: '0.85rem', color: 'var(--beige-muted)', borderLeft: '3px solid var(--beige-primary)' }}>
                    <div style={{ color: 'var(--beige-light)', fontWeight: '600', marginBottom: '0.25rem' }}>Plain-English Risk & Explanation:</div>
                    {item.plain_english_explanation}
                  </div>

                  <div style={{ marginTop: '0.75rem', fontSize: '0.8rem', color: 'var(--beige-dim)', display: 'flex', justifyContent: 'space-between' }}>
                    <span>Target Resource: <code className="mono-code" style={{ color: 'var(--beige-muted)' }}>{item.resource}</code></span>
                    <span>Status: <strong style={{ color: item.status === 'RESOLVED' ? '#9EC298' : '#E8B452' }}>{item.status}</strong></span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
