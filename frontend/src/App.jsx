import React, { useState } from 'react';
import { 
  Shield, 
  Activity, 
  Network, 
  ShieldCheck, 
  Users, 
  TrendingUp, 
  CheckSquare, 
  Terminal, 
  Radio, 
  Lock,
  Cpu,
  CheckCircle2,
  Radar
} from 'lucide-react';

import Overview from './pages/Overview';
import NetworkPage from './pages/Network';
import WafPage from './pages/Waf';
import BehaviorPage from './pages/Behavior';
import ForecastPage from './pages/Forecast';
import CompliancePage from './pages/Compliance';
import LiveScanner from './components/LiveScanner';
import BeaconLogo from './components/BeaconLogo';

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [showLiveScanner, setShowLiveScanner] = useState(false);

  const navItems = [
    { id: 'overview', label: 'Overview SOC', icon: Activity },
    { id: 'network', label: 'Network Flows', icon: Network },
    { id: 'waf', label: 'Smart WAF', icon: ShieldCheck },
    { id: 'behavior', label: 'Behavior & Graph', icon: Users },
    { id: 'forecast', label: 'AI Forecasting', icon: TrendingUp },
    { id: 'compliance', label: 'Auto Compliance', icon: CheckSquare },
  ];

  return (
    <div style={{ display: 'flex', minHeight: '100vh', backgroundColor: 'var(--bg-dark)' }}>
      {/* Live Scanner Modal */}
      {showLiveScanner && <LiveScanner onClose={() => setShowLiveScanner(false)} />}

      {/* Sidebar Navigation */}
      <aside style={{ width: '270px', borderRight: '1px solid var(--border-color)', padding: '1.5rem 1rem', display: 'flex', flexDirection: 'column', justifyContent: 'space-between', background: '#0a0908' }}>
        <div>
          {/* Logo & Brand */}
          <div style={{ padding: '0 0.5rem 1.5rem 0.5rem', borderBottom: '1px solid var(--border-color)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
              <BeaconLogo size={42} />
              <div>
                <div style={{ fontWeight: '800', fontSize: '1.25rem', letterSpacing: '0.06em', color: 'var(--beige-light)', fontFamily: 'var(--font-heading)' }}>
                  BEACON <span style={{ color: 'var(--beige-gold)', fontSize: '0.75rem' }}>SOC</span>
                </div>
                <div style={{ fontSize: '0.7rem', color: 'var(--beige-muted)', fontWeight: '600', letterSpacing: '0.04em' }}>
                  AI ATTACK FORECASTING SOC
                </div>
              </div>
            </div>
          </div>

          {/* Navigation Items */}
          <nav style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', marginTop: '1.5rem' }}>
            {navItems.map(item => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.75rem',
                    padding: '0.75rem 1rem',
                    borderRadius: '8px',
                    border: 'none',
                    background: isActive ? 'rgba(230, 213, 184, 0.12)' : 'transparent',
                    color: isActive ? 'var(--beige-primary)' : 'var(--beige-muted)',
                    borderLeft: isActive ? '4px solid var(--beige-primary)' : '4px solid transparent',
                    fontWeight: isActive ? '600' : '400',
                    fontSize: '0.9rem',
                    cursor: 'pointer',
                    transition: 'all 0.2s ease',
                    textAlign: 'left'
                  }}
                >
                  <Icon size={18} color={isActive ? 'var(--beige-primary)' : 'var(--beige-dim)'} />
                  {item.label}
                </button>
              );
            })}
          </nav>
        </div>
      </aside>

      {/* Main Content Area */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
        {/* Top Header Bar */}
        <header style={{ height: '64px', borderBottom: '1px solid var(--border-color)', padding: '0 2rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'rgba(12, 11, 10, 0.85)', backdropFilter: 'blur(8px)' }}>
          <div style={{ fontSize: '0.85rem', color: 'var(--beige-muted)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Terminal size={16} color="var(--beige-primary)" /> Module: <strong style={{ color: 'var(--beige-light)' }}>{navItems.find(i => i.id === activeTab)?.label}</strong>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem', fontSize: '0.85rem' }}>
            <button 
              className="glow-btn"
              onClick={() => setShowLiveScanner(true)}
              style={{ padding: '0.45rem 1rem', fontSize: '0.8rem', background: 'linear-gradient(135deg, #F8F5EE, #E6D5B8)', color: '#0c0b0a' }}
            >
              <Radar size={16} /> Live Device Scan
            </button>

            <button 
              className="glow-btn"
              onClick={() => {
                fetch('/api/system/ingest', { method: 'POST' })
                  .then(r => r.json())
                  .then(d => alert(`Dataset Ingestion Complete!\nFlows: ${d.flows_ingested}\nAuth Logs: ${d.auth_logs_ingested}\nCompliance: ${d.compliance_findings_ingested}`));
              }}
              style={{ padding: '0.4rem 0.85rem', fontSize: '0.78rem' }}
            >
              Ingest Datasets
            </button>

            <button 
              className="glow-btn"
              onClick={() => {
                fetch('/api/system/train', { method: 'POST' })
                  .then(r => r.json())
                  .then(d => alert(`ML Model Retraining Complete!\nWAF Accuracy: ${d.waf.accuracy * 100}%\nBehavior Graph Nodes: ${d.behavior.nodes}\nForecast Loss: ${d.forecast.final_loss}`));
              }}
              style={{ padding: '0.4rem 0.85rem', fontSize: '0.78rem', background: 'linear-gradient(135deg, #D4B982, #C5B358)' }}
            >
              Retrain Models
            </button>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--beige-muted)' }}>
              <Cpu size={16} color="var(--beige-gold)" /> PyTorch + DistilBERT
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--beige-muted)' }}>
              <Lock size={16} color="var(--beige-primary)" /> Trust: <span style={{ color: 'var(--beige-primary)', fontWeight: '600' }}>ACTIVE</span>
            </div>
          </div>
        </header>

        {/* Page View Container */}
        <main style={{ flex: 1, padding: '2rem', overflowY: 'auto' }} className="animate-fade-in">
          {activeTab === 'overview' && <Overview onOpenLiveScan={() => setShowLiveScanner(true)} />}
          {activeTab === 'network' && <NetworkPage />}
          {activeTab === 'waf' && <WafPage />}
          {activeTab === 'behavior' && <BehaviorPage />}
          {activeTab === 'forecast' && <ForecastPage />}
          {activeTab === 'compliance' && <CompliancePage />}
        </main>
      </div>
    </div>
  );
}
