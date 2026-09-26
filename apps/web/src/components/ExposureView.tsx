'use client';

import React from 'react';

export function ExposureView() {
  const assets = [
    {
      host: 'owa.enterprise-corp.internal',
      service: 'HTTPS / Outlook Web Access',
      product: 'Microsoft Exchange Server',
      version: '15.1.2507.17',
      ip: '198.51.100.25',
      cves: ['CVE-2024-21413', 'CVE-2023-35636'],
      state: 'ACTIVE_EXPLOITATION',
      exposure_score: 91.5,
    },
    {
      host: 'mail.enterprise-corp.internal',
      service: 'SMTP / ESMTP',
      product: 'Postfix Mail Gateway',
      version: '3.7.4',
      ip: '198.51.100.26',
      cves: [],
      state: 'HARDENED',
      exposure_score: 24.0,
    },
    {
      host: 'zimbra-edge.enterprise-corp.internal',
      service: 'HTTPS / Zimbra Web Client',
      product: 'Zimbra Collaboration Suite',
      version: '8.8.15',
      ip: '198.51.100.27',
      cves: ['CVE-2022-27925'],
      state: 'VULNERABLE',
      exposure_score: 78.0,
    },
  ];

  return (
    <div className="bg-card border border-border rounded-2xl p-6 shadow-tactical-card space-y-5 font-poppins">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-neon-cyan shadow-[0_0_8px_#00e5ff] animate-pulse" />
            <h3 className="text-sm font-bold tracking-wider text-foreground font-mono uppercase">
              INTERNET-FACING EMAIL ATTACK SURFACE
            </h3>
          </div>
          <p className="text-xs text-muted mt-0.5 font-light">
            Continuous perimeter asset discovery, software version fingerprinting & live CVE correlation
          </p>
        </div>
        <span className="inline-flex items-center gap-1.5 px-3 py-1 bg-card-secondary text-foreground border border-border rounded-xl text-xs font-mono font-semibold self-start">
          <span className="w-1.5 h-1.5 rounded-full bg-neon-emerald animate-pulse" />
          3 DISCOVERED HOSTS
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs text-foreground">
          <thead className="bg-card-secondary text-muted uppercase font-mono text-[10px] border-b border-border">
            <tr>
              <th className="p-3.5">Host / FQDN</th>
              <th className="p-3.5">Identified Software</th>
              <th className="p-3.5">Version</th>
              <th className="p-3.5">Correlated CVEs</th>
              <th className="p-3.5">Asset State</th>
              <th className="p-3.5 text-right">Exposure Score</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border font-sans">
            {assets.map((asset, idx) => (
              <tr key={idx} className="hover:bg-hover-bg transition-colors">
                <td className="p-3.5 font-mono font-medium text-foreground">
                  <div className="flex items-center gap-2">
                    <svg className="w-3.5 h-3.5 text-muted shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
                    </svg>
                    {asset.host}
                  </div>
                  <span className="text-[10px] text-muted font-mono block pl-5">{asset.ip}</span>
                </td>
                <td className="p-3.5 text-foreground font-semibold">{asset.product}</td>
                <td className="p-3.5 font-mono text-muted text-[11px]">{asset.version}</td>
                <td className="p-3.5">
                  {asset.cves.length > 0 ? (
                    <div className="flex gap-1.5 flex-wrap">
                      {asset.cves.map((c, i) => (
                        <span
                          key={i}
                          className="px-2 py-0.5 bg-rose-500/10 text-rose-400 border border-rose-500/30 rounded text-[10px] font-mono font-bold"
                        >
                          {c}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <span className="text-muted text-[11px] font-mono">None detected</span>
                  )}
                </td>
                <td className="p-3.5">
                  <span
                    className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-[10px] font-mono font-bold ${
                      asset.state === 'ACTIVE_EXPLOITATION'
                        ? 'bg-rose-500/10 text-rose-400 border border-rose-500/30 shadow-[0_0_8px_rgba(255,0,85,0.2)]'
                        : asset.state === 'VULNERABLE'
                        ? 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                        : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                    }`}
                  >
                    <span
                      className={`w-1.5 h-1.5 rounded-full ${
                        asset.state === 'ACTIVE_EXPLOITATION'
                          ? 'bg-neon-rose animate-ping'
                          : asset.state === 'VULNERABLE'
                          ? 'bg-neon-amber'
                          : 'bg-neon-emerald'
                      }`}
                    />
                    {asset.state}
                  </span>
                </td>
                <td className="p-3.5 font-mono font-black text-right text-foreground">
                  {asset.exposure_score.toFixed(1)} / 100
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
