import React, { useEffect, useState } from 'react';
import { ShieldCheck, Play, Bug, Globe, Code, AlertTriangle, ShieldAlert, CheckCircle2 } from 'lucide-react';

export default function WafPage() {
  const [method, setMethod] = useState('GET');
  const [path, setPath] = useState('/products');
  const [query, setQuery] = useState('id=1 UNION SELECT 1,username,password FROM users--');
  const [headers, setHeaders] = useState('{"User-Agent": "sqlmap/1.5"}');
  const [body, setBody] = useState('');
  const [evalResult, setEvalResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [logs, setLogs] = useState([]);

  const handleEvaluate = (e) => {
    e?.preventDefault();
    setLoading(true);
    fetch('/api/waf/evaluate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ method, path, query, headers, body })
    })
      .then(res => res.json())
      .then(d => {
        setEvalResult(d);
        setLoading(false);
        fetchLogs();
      })
      .catch(() => setLoading(false));
  };

  const fetchLogs = () => {
    fetch('/api/waf/logs')
      .then(res => res.json())
      .then(d => setLogs(d))
      .catch(() => {});
  };

  useEffect(() => {
    fetchLogs();
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Header */}
      <div className="glass-panel" style={{ padding: '1.5rem 2rem' }}>
        <h1 style={{ fontSize: '1.5rem', fontWeight: '700', color: 'var(--beige-light)', display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <ShieldCheck style={{ color: 'var(--beige-primary)' }} /> Smart WAF (DistilBERT HTTP Classifier)
        </h1>
        <p style={{ color: 'var(--beige-muted)', fontSize: '0.9rem', marginTop: '0.25rem' }}>
          Transformer-based HTTP payload evaluation for SQLi, XSS, Path Traversal & Command Injection
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
        {/* Interactive Evaluation Sandbox */}
        <div className="glass-panel" style={{ padding: '1.5rem' }}>
          <h2 style={{ fontSize: '1.1rem', fontWeight: '600', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Play style={{ color: 'var(--beige-gold)' }} /> Real-Time HTTP Request Sandbox
          </h2>
          <form onSubmit={handleEvaluate} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div style={{ display: 'flex', gap: '0.75rem' }}>
              <select value={method} onChange={e => setMethod(e.target.value)} style={{ background: 'rgba(20, 18, 16, 0.95)', color: 'var(--beige-light)', border: '1px solid var(--border-color)', padding: '0.6rem', borderRadius: '8px', fontFamily: 'var(--font-mono)' }}>
                <option value="GET">GET</option>
                <option value="POST">POST</option>
                <option value="PUT">PUT</option>
                <option value="DELETE">DELETE</option>
              </select>
              <input type="text" value={path} onChange={e => setPath(e.target.value)} placeholder="/api/endpoint" style={{ flex: 1, background: 'rgba(20, 18, 16, 0.95)', color: 'var(--beige-light)', border: '1px solid var(--border-color)', padding: '0.6rem', borderRadius: '8px', fontFamily: 'var(--font-mono)' }} />
            </div>

            <div>
              <label style={{ fontSize: '0.8rem', color: 'var(--beige-muted)', display: 'block', marginBottom: '0.25rem' }}>URL Query String:</label>
              <input type="text" value={query} onChange={e => setQuery(e.target.value)} placeholder="id=1&name=test" style={{ width: '100%', background: 'rgba(20, 18, 16, 0.95)', color: 'var(--beige-light)', border: '1px solid var(--border-color)', padding: '0.6rem', borderRadius: '8px', fontFamily: 'var(--font-mono)' }} />
            </div>

            <div>
              <label style={{ fontSize: '0.8rem', color: 'var(--beige-muted)', display: 'block', marginBottom: '0.25rem' }}>HTTP Headers (JSON):</label>
              <input type="text" value={headers} onChange={e => setHeaders(e.target.value)} placeholder='{"User-Agent": "Mozilla/5.0"}' style={{ width: '100%', background: 'rgba(20, 18, 16, 0.95)', color: 'var(--beige-light)', border: '1px solid var(--border-color)', padding: '0.6rem', borderRadius: '8px', fontFamily: 'var(--font-mono)' }} />
            </div>

            <div>
              <label style={{ fontSize: '0.8rem', color: 'var(--beige-muted)', display: 'block', marginBottom: '0.25rem' }}>Request Body Payload:</label>
              <textarea value={body} onChange={e => setBody(e.target.value)} rows={3} placeholder='Payload body text...' style={{ width: '100%', background: 'rgba(20, 18, 16, 0.95)', color: 'var(--beige-light)', border: '1px solid var(--border-color)', padding: '0.6rem', borderRadius: '8px', fontFamily: 'var(--font-mono)' }} />
            </div>

            <button type="submit" className="glow-btn" disabled={loading}>
              <Play size={16} /> {loading ? 'Evaluating...' : 'Classify HTTP Request'}
            </button>
          </form>

          {/* Model Inference Output */}
          {evalResult && (
            <div style={{ marginTop: '1.5rem', padding: '1rem', background: evalResult.label === 1 ? 'rgba(217, 83, 79, 0.12)' : 'rgba(122, 154, 116, 0.12)', borderRadius: '8px', border: evalResult.label === 1 ? '1px solid rgba(217, 83, 79, 0.4)' : '1px solid rgba(122, 154, 116, 0.4)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontWeight: '700', color: evalResult.label === 1 ? '#F07875' : '#9EC298', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  {evalResult.label === 1 ? <ShieldAlert size={18} /> : <CheckCircle2 size={18} />}
                  {evalResult.label === 1 ? 'MALICIOUS REQUEST DETECTED' : 'BENIGN REQUEST'}
                </span>
                <span className={`badge ${evalResult.label === 1 ? 'badge-critical' : 'badge-low'}`}>
                  Score: {evalResult.malicious_score}
                </span>
              </div>
              <div style={{ fontSize: '0.85rem', marginTop: '0.5rem', color: 'var(--beige-muted)' }}>
                Attack Classification: <strong style={{ color: 'var(--beige-light)' }}>{evalResult.attack_type}</strong>
              </div>
              <div style={{ fontSize: '0.75rem', marginTop: '0.25rem', color: 'var(--beige-dim)' }} className="mono-code">
                Normalized Representation: {evalResult.text}
              </div>
            </div>
          )}
        </div>

        {/* WAF Decision & Evaluation Logs */}
        <div className="glass-panel" style={{ padding: '1.5rem' }}>
          <h2 style={{ fontSize: '1.1rem', fontWeight: '600', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Bug style={{ color: 'var(--status-critical)' }} /> Live WAF Inspection Logs
          </h2>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', maxHeight: '420px', overflowY: 'auto' }}>
            {logs.map((log) => (
              <div key={log.id} style={{ padding: '0.75rem', background: 'rgba(255, 255, 255, 0.02)', borderRadius: '8px', borderLeft: log.label === 1 ? '4px solid var(--status-critical)' : '4px solid var(--status-low)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span className="mono-code" style={{ fontSize: '0.85rem', color: 'var(--beige-light)', fontWeight: '600' }}>
                    {log.method} {log.path}
                  </span>
                  <span className={`badge ${log.label === 1 ? 'badge-critical' : 'badge-low'}`}>
                    Score: {log.malicious_score}
                  </span>
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--beige-muted)', marginTop: '0.25rem' }}>
                  Type: {log.attack_type} | Time: {log.created_at}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
