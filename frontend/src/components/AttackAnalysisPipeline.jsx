import React from 'react';

import {
  Activity,
  ArrowRight,
  BrainCircuit,
  Crosshair,
  Database,
  Gauge,
  Layers3,
  ShieldAlert,
  Target,
} from 'lucide-react';

const pipelineStages = [
  {
    eyebrow: '01 / INGEST',
    title: 'Network data',
    detail: 'Flow and security telemetry enters Beacon for analysis.',
    meta: '10-flow evaluation window',
    icon: Database,
    tone: 'neutral',
  },
  {
    eyebrow: '02 / TRANSFORM',
    title: 'Feature extraction',
    detail: 'Network and security signals are normalized into model inputs.',
    meta: '12 model features',
    icon: Layers3,
    tone: 'neutral',
  },
  {
    eyebrow: '03 / ANALYZE',
    title: 'LSTM temporal analysis',
    detail: 'A five-step sequence reveals behavior over time, not an isolated flow.',
    meta: '5-step sequence window',
    icon: BrainCircuit,
    tone: 'active',
  },
];

function parseMapping(mapping = '') {
  const match = mapping.match(/^(.*?)\s*\((T\d+(?:\.\d+)?)\s*-\s*(.*?)\)$/);
  return match
    ? { label: match[1], technique: match[2], description: match[3] }
    : { label: mapping, technique: 'N/A', description: 'Representative stage mapping' };
}

function riskLevel(risk) {
  if (risk > 0.7) return { label: 'HIGH', tone: 'critical' };
  if (risk > 0.4) return { label: 'MEDIUM', tone: 'high' };
  return { label: 'LOW', tone: 'low' };
}

function PipelineNode({ stage, children, last = false }) {
  const Icon = stage.icon;
  return (
    <div className="attack-pipeline-step">
      <div className={`attack-pipeline-node attack-pipeline-node-${stage.tone}`}>
        <div className="attack-pipeline-node-topline">
          <span>{stage.eyebrow}</span>
          <Icon size={17} aria-hidden="true" />
        </div>
        <div className="attack-pipeline-node-title">{stage.title}</div>
        <div className="attack-pipeline-node-detail">{stage.detail}</div>
        {stage.meta && <div className="attack-pipeline-node-meta">{stage.meta}</div>}
        {children}
      </div>
      {!last && <ArrowRight className="attack-pipeline-connector" size={18} aria-hidden="true" />}
    </div>
  );
}

export default function AttackAnalysisPipeline({ forecast }) {
  if (!forecast) return null;

  const mapping = parseMapping(forecast.att_ck_mapping);
  const risk = riskLevel(forecast.escalation_risk);
  const confidence = Number(forecast.confidence || 0);
  const escalationRisk = Number(forecast.escalation_risk || 0);

  return (
    <section className="attack-pipeline glass-panel" aria-labelledby="attack-pipeline-title">
      <div className="attack-pipeline-header">
        <div>
          <div className="section-kicker"><Activity size={14} /> ANALYSIS PATH / LIVE MODEL OUTPUT</div>
          <h2 id="attack-pipeline-title">End-to-End Attack Analysis Pipeline</h2>
          <p>How Beacon turns network telemetry into an explainable attack forecast.</p>
        </div>
        <div className="attack-pipeline-status"><span className="pulse-dot" /> SEQUENCE ONLINE</div>
      </div>

      <div className="attack-pipeline-flow">
        {pipelineStages.map(stage => <PipelineNode key={stage.title} stage={stage} />)}

        <PipelineNode
          stage={{
            eyebrow: '04 / IDENTIFY',
            title: 'Current attack stage',
            detail: 'Latest stage identified from the observed sequence.',
            icon: Crosshair,
            tone: 'current',
          }}
        >
          <div className="pipeline-value pipeline-value-current">{forecast.current_stage || 'UNKNOWN'}</div>
        </PipelineNode>

        <PipelineNode
          stage={{
            eyebrow: '05 / FORECAST',
            title: 'Predicted next stage',
            detail: 'The dual-head LSTM forecasts the next likely progression.',
            icon: Target,
            tone: 'predicted',
          }}
        >
          <div className="pipeline-value pipeline-value-predicted">{forecast.likely_next_stage || 'UNKNOWN'}</div>
          <div className="pipeline-confidence"><span>MODEL CONFIDENCE</span><strong>{(confidence * 100).toFixed(1)}%</strong></div>
        </PipelineNode>

        <PipelineNode
          stage={{
            eyebrow: '06 / MAP',
            title: 'MITRE ATT&CK mapping',
            detail: 'Predicted stage mapped to a representative ATT&CK technique.',
            icon: ShieldAlert,
            tone: 'mapping',
          }}
        >
          <div className="pipeline-mapping"><strong>{mapping.technique}</strong><span>{mapping.description}</span></div>
          <div className="pipeline-mapping-label">PREDICTED MAPPING / {mapping.label || 'UNAVAILABLE'}</div>
        </PipelineNode>

        <PipelineNode
          last
          stage={{
            eyebrow: '07 / ASSESS',
            title: 'Escalation risk',
            detail: 'Risk output from Beacon’s forecasting engine.',
            icon: Gauge,
            tone: risk.tone,
          }}
        >
          <div className="pipeline-risk"><strong>{(escalationRisk * 100).toFixed(0)}%</strong><span className={`risk-label risk-label-${risk.tone}`}>{risk.label}</span></div>
          <div className="pipeline-risk-track"><span style={{ width: `${Math.min(100, Math.max(0, escalationRisk * 100))}%` }} /></div>
        </PipelineNode>
      </div>
    </section>
  );
}
