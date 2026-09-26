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
    <div className="bg-card border border-border rounded-2xl p-6 shadow-sm space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-accent-blue" />
            <h3 className="text-sm font-semibold tracking-tight text-foreground font-mono">
              INTERNET-FACING EMAIL ATTACK SURFACE
            </h3>
          </div>
          <p className="text-xs text-muted mt-0.5">
            Continuous external surface discovery, mail server fingerprinting, and live CVE correlation
          </p>
        </div>
        <span className="inline-flex items-center gap-1.5 px-3 py-1 bg-slate-50 dark:bg-slate-950/50 text-foreground border border-border rounded-full text-xs font-mono font-medium self-start">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
          3 Discovered Hosts
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs text-foreground">
          <thead className="bg-slate-50/50 dark:bg-slate-950/40 text-muted uppercase font-mono text-[10px] border-b border-border">
            <tr>
              <th className="p-3.5">Host / FQDN</th>
              <th className="p-3.5">Identified Product</th>
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
                <td className="p-3.5 text-foreground font-medium">{asset.product}</td>
                <td className="p-3.5 font-mono text-muted text-[11px]">{asset.version}</td>
                <td className="p-3.5">
                  {asset.cves.length > 0 ? (
                    <div className="flex gap-1.5 flex-wrap">
                      {asset.cves.map((c, i) => (
                        <span
                          key={i}
                          className="px-2 py-0.5 bg-rose-50 dark:bg-rose-950/60 text-rose-700 dark:text-rose-400 border border-rose-200 dark:border-rose-800/60 rounded text-[10px] font-mono font-semibold"
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
                    className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-semibold ${
                      asset.state === 'ACTIVE_EXPLOITATION'
                        ? 'bg-rose-50 dark:bg-rose-950/60 text-rose-700 dark:text-rose-400 border border-rose-200 dark:border-rose-800'
                        : asset.state === 'VULNERABLE'
                        ? 'bg-amber-50 dark:bg-amber-950/60 text-amber-700 dark:text-amber-400 border border-amber-200 dark:border-amber-800'
                        : 'bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800'
                    }`}
                  >
                    <span
                      className={`w-1.5 h-1.5 rounded-full ${
                        asset.state === 'ACTIVE_EXPLOITATION'
                          ? 'bg-rose-500 animate-ping'
                          : asset.state === 'VULNERABLE'
                          ? 'bg-amber-500'
                          : 'bg-emerald-500'
                      }`}
                    />
                    {asset.state}
                  </span>
                </td>
                <td className="p-3.5 font-mono font-bold text-right text-foreground">
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
