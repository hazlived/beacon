import React, { useEffect, useState } from 'react';
import { TrendingUp, Target, AlertTriangle, ShieldCheck, Zap, Activity } from 'lucide-react';

export default function ForecastPage() {
  const [forecast, setForecast] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/api/forecast/evaluate?session_id=SESS101')
      .then(r => r.json())
      .then(d => {
        setForecast(d);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  const stages = ["RECON", "INITIAL_ACCESS", "CREDENTIAL_ACCESS", "LATERAL_MOVEMENT", "IMPACT"];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Header */}
      <div className="glass-panel" style={{ padding: '1.5rem 2rem' }}>
        <h1 style={{ fontSize: '1.5rem', fontWeight: '700', color: 'var(--beige-light)', display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <TrendingUp style={{ color: 'var(--beige-primary)' }} /> Core AI Network Attack Forecasting Engine
        </h1>
        <p style={{ color: 'var(--beige-muted)', fontSize: '0.9rem', marginTop: '0.25rem' }}>
          PyTorch Dual-Head LSTM Temporal Sequence Model (Next Attack Stage & Escalation Risk Prediction)
        </p>
      </div>

      {/* Main Forecasting Status Banner */}
      {loading ? (
        <div className="glass-panel" style={{ padding: '3rem', textAlign: 'center', color: 'var(--beige-muted)' }}>
          Computing LSTM sequence predictions...
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr', gap: '1.5rem' }}>
          {/* Left Column: Stage Sequence Stepper & Predictions */}
          <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
            <h2 style={{ fontSize: '1.1rem', fontWeight: '600', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Target style={{ color: 'var(--beige-gold)' }} /> ATT&CK Multi-Stage Attack Pipeline Forecast
            </h2>

            {/* Stage Stepper Visual */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '1rem 0' }}>
              {stages.map((stage, i) => {
                const isCurrent = forecast?.current_stage === stage;
                const isNext = forecast?.likely_next_stage === stage;
                const isPassed = stages.indexOf(forecast?.current_stage) > i;

                let bg = 'rgba(255, 255, 255, 0.03)';
                let border = 'var(--border-color)';
                let color = 'var(--beige-muted)';

                if (isCurrent) {
                  bg = 'rgba(230, 213, 184, 0.15)';
                  border = 'var(--beige-primary)';
                  color = 'var(--beige-primary)';
                } else if (isNext) {
                  bg = 'rgba(217, 83, 79, 0.18)';
                  border = 'var(--status-critical)';
                  color = '#F07875';
                } else if (isPassed) {
                  bg = 'rgba(122, 154, 116, 0.15)';
                  border = 'var(--status-low)';
                  color = '#9EC298';
                }

                return (
                  <div key={stage} style={{ textAlign: 'center', flex: 1, position: 'relative' }}>
                    <div style={{ width: '40px', height: '40px', borderRadius: '50%', background: bg, border: `2px solid ${border}`, color: color, display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: '700', margin: '0 auto 0.5rem auto' }}>
                      {i + 1}
                    </div>
                    <div style={{ fontSize: '0.75rem', fontWeight: '600', color: color }}>{stage}</div>
                    {isCurrent && <div style={{ fontSize: '0.65rem', color: 'var(--beige-primary)', marginTop: '0.2rem', fontWeight: '700' }}>CURRENT</div>}
                    {isNext && <div style={{ fontSize: '0.65rem', color: '#F07875', marginTop: '0.2rem', fontWeight: '700' }}>PREDICTED</div>}
                  </div>
                );
              })}
            </div>

            {/* Stage Detail Card */}
            <div style={{ padding: '1.25rem', background: 'rgba(217, 83, 79, 0.12)', borderRadius: '8px', border: '1px solid rgba(217, 83, 79, 0.35)' }}>
              <div style={{ fontSize: '0.85rem', color: 'var(--beige-muted)' }}>Predicted Next Attack Stage:</div>
              <div style={{ fontSize: '1.4rem', fontWeight: '700', color: '#F07875', marginTop: '0.25rem' }}>
                {forecast?.likely_next_stage} ({(forecast?.confidence * 100).toFixed(1)}% Confidence)
              </div>
              <div style={{ fontSize: '0.85rem', color: 'var(--beige-light)', marginTop: '0.5rem' }}>
                ATT&CK Mapping: {forecast?.att_ck_mapping}
              </div>
            </div>
          </div>

          {/* Right Column: Escalation Risk Gauge */}
          <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <h2 style={{ fontSize: '1.1rem', fontWeight: '600', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Zap style={{ color: 'var(--status-high)' }} /> Escalation Risk Gauge
            </h2>

            <div style={{ textAlign: 'center', padding: '1.5rem 0' }}>
              <div style={{ fontSize: '3rem', fontWeight: '800', color: forecast?.escalation_risk > 0.7 ? 'var(--status-critical)' : 'var(--status-high)' }}>
                {(forecast?.escalation_risk * 100).toFixed(0)}%
              </div>
              <div style={{ fontSize: '0.9rem', color: 'var(--beige-muted)', marginTop: '0.25rem' }}>
                Escalation Risk Probability
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              <div style={{ fontSize: '0.85rem', color: 'var(--beige-muted)' }}>Stage Probability Distribution:</div>
              {Object.entries(forecast?.probs || {}).map(([stage, prob]) => (
                <div key={stage} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem' }}>
                  <span style={{ width: '130px', color: 'var(--beige-light)' }}>{stage}</span>
                  <div style={{ flex: 1, height: '8px', background: 'rgba(255, 255, 255, 0.08)', borderRadius: '4px', overflow: 'hidden' }}>
                    <div style={{ width: `${prob * 100}%`, height: '100%', background: 'linear-gradient(90deg, #E6D5B8, #C5B358)' }}></div>
                  </div>
                  <span style={{ width: '40px', textAlign: 'right', color: 'var(--beige-muted)' }}>{(prob * 100).toFixed(0)}%</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
