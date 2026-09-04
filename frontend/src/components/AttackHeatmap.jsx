import React from 'react';
import { Crosshair, ShieldAlert } from 'lucide-react';

const attackStages = [
  { name: 'RECON', technique: 'T1046', description: 'Network Service Discovery' },
  { name: 'INITIAL_ACCESS', technique: 'T1190', description: 'Exploit Public-Facing Application' },
  { name: 'CREDENTIAL_ACCESS', technique: 'T1110', description: 'Brute Force' },
  { name: 'LATERAL_MOVEMENT', technique: 'T1021', description: 'Remote Services' },
  { name: 'IMPACT', technique: 'T1499', description: 'Endpoint Denial of Service' },
];

export default function AttackHeatmap({ forecast }) {
  const probabilities = forecast?.probs || {};
  const predictedStage = forecast?.likely_next_stage;

  return (
    <div className="attack-heatmap" aria-labelledby="attack-heatmap-title">
      <div className="attack-heatmap-header">
        <div>
          <div className="attack-heatmap-kicker"><ShieldAlert size={14} /> PREDICTION CONFIDENCE MATRIX</div>
          <h3 id="attack-heatmap-title">MITRE ATT&CK Prediction</h3>
          <p>Confidence by predicted attack stage and representative technique.</p>
        </div>
        <Crosshair size={18} className="attack-heatmap-crosshair" aria-hidden="true" />
      </div>

      <div className="attack-heatmap-rows">
        {attackStages.map(stage => {
          const probability = Math.min(1, Math.max(0, Number(probabilities[stage.name] || 0)));
          const isPredicted = predictedStage === stage.name;

          return (
            <div key={stage.name} className={`attack-heatmap-row${isPredicted ? ' attack-heatmap-row-predicted' : ''}`} title={`${stage.technique} - ${stage.description}\nBeacon stage: ${stage.name}\nPrediction confidence: ${(probability * 100).toFixed(1)}%`}>
              <div className="attack-heatmap-stage">
                <strong>{stage.name}</strong>
                {isPredicted && <span><span className="heatmap-predicted-dot" /> PREDICTED</span>}
              </div>
              <div className="attack-heatmap-technique">
                <strong>{stage.technique}</strong>
                <span>{stage.description}</span>
              </div>
              <div className="attack-heatmap-bar-track" aria-label={`${stage.name} confidence ${(probability * 100).toFixed(1)} percent`}>
                <div className="attack-heatmap-bar" style={{ width: `${probability * 100}%` }} />
              </div>
              <strong className="attack-heatmap-percent">{(probability * 100).toFixed(0)}%</strong>
            </div>
          );
        })}
      </div>

      <div className="attack-heatmap-legend">
        <div className="attack-heatmap-legend-title">PREDICTION CONFIDENCE</div>
        <div className="attack-heatmap-legend-line"><span>LOW</span><div className="attack-heatmap-gradient" /><span>HIGH</span></div>
        <div className="attack-heatmap-legend-scale"><span>0%</span><span>25%</span><span>50%</span><span>75%</span><span>100%</span></div>
      </div>
    </div>
  );
}
