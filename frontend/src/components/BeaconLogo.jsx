import React from 'react';

export default function BeaconLogo({ size = 32, className = '' }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 100 100"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      style={{ display: 'block', filter: 'drop-shadow(0 0 8px rgba(230, 213, 184, 0.35))' }}
    >
      <defs>
        <linearGradient id="beaconGoldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#F8F5EE" />
          <stop offset="50%" stopColor="#E6D5B8" />
          <stop offset="100%" stopColor="#D4B982" />
        </linearGradient>

        <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="0%" y2="100%">
          <stop offset="0%" stopColor="#24211D" stopOpacity="0.9" />
          <stop offset="100%" stopColor="#0A0908" stopOpacity="0.9" />
        </linearGradient>

        <radialGradient id="beamGlow" cx="50%" cy="30%" r="50%">
          <stop offset="0%" stopColor="#F8F5EE" stopOpacity="0.9" />
          <stop offset="60%" stopColor="#E6D5B8" stopOpacity="0.4" />
          <stop offset="100%" stopColor="#E6D5B8" stopOpacity="0" />
        </radialGradient>
      </defs>

      {/* Outer Cyber Shield Frame */}
      <path
        d="M50 8 L85 24 V50 C85 71.5 70 87 50 94 C30 87 15 71.5 15 50 V24 L50 8 Z"
        fill="url(#shieldGrad)"
        stroke="url(#beaconGoldGrad)"
        strokeWidth="3.5"
        strokeLinejoin="round"
      />

      {/* Radar Signal Wave Arcs */}
      <path
        d="M32 38 A 22 22 0 0 1 68 38"
        stroke="url(#beaconGoldGrad)"
        strokeWidth="2.5"
        strokeLinecap="round"
        opacity="0.6"
      />
      <path
        d="M26 30 A 30 30 0 0 1 74 30"
        stroke="url(#beaconGoldGrad)"
        strokeWidth="2"
        strokeLinecap="round"
        opacity="0.35"
      />

      {/* Beacon Light Emitter Rays */}
      <polygon points="50,26 22,14 78,14" fill="url(#beamGlow)" opacity="0.6" />

      {/* Lighthouse Beacon Tower Geometry */}
      <polygon points="43,72 57,72 54,42 46,42" fill="url(#beaconGoldGrad)" />
      
      {/* Beacon Base Stand */}
      <path d="M38 78 H62 V72 H38 V78 Z" fill="url(#beaconGoldGrad)" />
      
      {/* Light Lens Dome */}
      <circle cx="50" cy="38" r="6" fill="#F8F5EE" />
      <circle cx="50" cy="38" r="9" stroke="url(#beaconGoldGrad)" strokeWidth="2" fill="none" />
      
      {/* Top Signal Spire */}
      <line x1="50" y1="29" x2="50" y2="20" stroke="url(#beaconGoldGrad)" strokeWidth="3" strokeLinecap="round" />
      <circle cx="50" cy="18" r="2.5" fill="#F8F5EE" />
    </svg>
  );
}
