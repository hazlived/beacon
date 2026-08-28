import React, { useEffect, useState } from 'react';
import { Users, UserX, AlertCircle, Share2, ShieldAlert, Monitor, Database, Globe, User } from 'lucide-react';

export default function BehaviorPage() {
  const [graphData, setGraphData] = useState({ nodes: [], links: [] });
  const [usersRisk, setUsersRisk] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      fetch('/api/behavior/graph').then(r => r.json()),
      fetch('/api/behavior/users').then(r => r.json())
    ])
      .then(([g, u]) => {
        setGraphData(g);
        setUsersRisk(u);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Header */}
      <div className="glass-panel" style={{ padding: '1.5rem 2rem' }}>
        <h1 style={{ fontSize: '1.5rem', fontWeight: '700', color: 'var(--beige-light)', display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <Users style={{ color: 'var(--beige-primary)' }} /> Insider Threat & Graph Behavioral Detection
        </h1>
        <p style={{ color: 'var(--beige-muted)', fontSize: '0.9rem', marginTop: '0.25rem' }}>
          Heterogeneous Entity-Relational Graph (Users &rarr; Devices &rarr; Resources) + Isolation Forest Anomaly Engine
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
        {/* Interactive Behavioral Graph Representation */}
        <div className="glass-panel" style={{ padding: '1.5rem' }}>
          <h2 style={{ fontSize: '1.1rem', fontWeight: '600', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Share2 style={{ color: 'var(--beige-gold)' }} /> Heterogeneous Entity Graph
          </h2>
          <div style={{ padding: '1rem', background: 'rgba(10, 9, 8, 0.6)', borderRadius: '8px', minHeight: '350px', border: '1px solid var(--border-color)', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
            <div style={{ fontSize: '0.8rem', color: 'var(--beige-muted)', display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem', color: 'var(--beige-primary)' }}>
                <User size={14} /> Users ({graphData.nodes?.filter(n => n.type === 'User').length || 0})
              </span>
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem', color: '#9EC298' }}>
                <Monitor size={14} /> Devices ({graphData.nodes?.filter(n => n.type === 'Device').length || 0})
              </span>
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem', color: 'var(--beige-gold)' }}>
                <Database size={14} /> Resources ({graphData.nodes?.filter(n => n.type === 'Resource').length || 0})
              </span>
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem', color: '#E8B452' }}>
                <Globe size={14} /> IPs ({graphData.nodes?.filter(n => n.type === 'IP').length || 0})
              </span>
            </div>

            {/* Visual Node Cloud */}
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.6rem', padding: '1rem 0' }}>
              {graphData.nodes?.slice(0, 35).map((node, i) => {
                const color = node.type === 'User' ? 'var(--beige-primary)' : node.type === 'Device' ? '#9EC298' : node.type === 'Resource' ? 'var(--beige-gold)' : '#E8B452';
                return (
                  <div key={i} style={{ padding: '0.35rem 0.65rem', borderRadius: '20px', background: 'rgba(230, 213, 184, 0.08)', border: `1px solid ${color}60`, color: color, fontSize: '0.75rem', fontWeight: '600' }} className="mono-code">
                    {node.label}
                  </div>
                );
              })}
            </div>

            <div style={{ fontSize: '0.75rem', color: 'var(--beige-dim)', textAlign: 'center' }}>
              Total Graph Edges: {graphData.links?.length || 0} relational connections
            </div>
          </div>
        </div>

        {/* User Risk Ranking Table */}
        <div className="glass-panel" style={{ padding: '1.5rem' }}>
          <h2 style={{ fontSize: '1.1rem', fontWeight: '600', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <ShieldAlert style={{ color: 'var(--status-high)' }} /> User Behavioral Risk Rankings
          </h2>
          
          {loading ? (
            <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--beige-muted)' }}>Calculating user anomaly profiles...</div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', maxHeight: '350px', overflowY: 'auto' }}>
              {usersRisk.map((user, idx) => (
                <div key={idx} style={{ padding: '0.75rem 1rem', background: 'rgba(255, 255, 255, 0.02)', borderRadius: '8px', borderLeft: user.behavior_risk > 0.6 ? '4px solid var(--status-critical)' : '4px solid var(--status-low)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div>
                    <div style={{ fontWeight: '600', color: 'var(--beige-light)', fontSize: '0.9rem' }} className="mono-code">
                      {user.user_id}
                    </div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--beige-muted)', marginTop: '0.2rem' }}>
                      Indicators: {user.anomaly_indicators?.join(', ') || 'Normal pattern'}
                    </div>
                  </div>
                  <span className={`badge ${user.behavior_risk > 0.6 ? 'badge-critical' : 'badge-low'}`}>
                    Risk: {user.behavior_risk}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
