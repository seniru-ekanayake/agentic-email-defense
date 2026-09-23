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
      cves: ['CVE-2023-35636', 'CVE-2023-23397'],
      state: 'ATTACK_OBSERVED',
      exposure_score: 85.0
    },
    {
      host: 'mail.enterprise-corp.internal',
      service: 'SMTP / ESMTP',
      product: 'Postfix / Exchange Connector',
      version: '3.5.x',
      ip: '198.51.100.26',
      cves: [],
      state: 'ASSET_EXPOSED',
      exposure_score: 45.0
    },
    {
      host: 'zimbra-legacy.enterprise-corp.internal',
      service: 'HTTPS / Zimbra Web Client',
      product: 'Zimbra Collaboration Suite',
      version: '8.8.15',
      ip: '198.51.100.27',
      cves: ['CVE-2022-27925'],
      state: 'VULNERABLE',
      exposure_score: 75.0
    }
  ];

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-2xl space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-bold text-white">Internet-Facing Email Attack Surface</h3>
          <p className="text-xs text-slate-400">Continuous asset discovery, service fingerprinting, and CVE exposure correlation</p>
        </div>
        <span className="px-3 py-1 bg-cyan-950/80 text-cyan-400 border border-cyan-800 rounded-full text-xs font-mono">
          3 Discovered Assets
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs text-slate-300">
          <thead className="bg-slate-950 text-slate-400 uppercase font-mono text-[10px] border-b border-slate-800">
            <tr>
              <th className="p-3">Host / Domain</th>
              <th className="p-3">Identified Product</th>
              <th className="p-3">Version</th>
              <th className="p-3">Associated CVEs</th>
              <th className="p-3">Asset State</th>
              <th className="p-3">Exposure Score</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 font-sans">
            {assets.map((asset, idx) => (
              <tr key={idx} className="hover:bg-slate-800/40 transition-colors">
                <td className="p-3 font-mono text-white font-medium">{asset.host}</td>
                <td className="p-3 text-cyan-300">{asset.product}</td>
                <td className="p-3 font-mono text-slate-400">{asset.version}</td>
                <td className="p-3">
                  {asset.cves.length > 0 ? (
                    <div className="flex gap-1 flex-wrap">
                      {asset.cves.map((c, i) => (
                        <span key={i} className="px-1.5 py-0.5 bg-red-950/80 text-red-400 border border-red-800 rounded text-[10px] font-mono">
                          {c}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <span className="text-slate-500">None detected</span>
                  )}
                </td>
                <td className="p-3">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    asset.state === 'ATTACK_OBSERVED' ? 'bg-red-950/80 text-red-400 border border-red-800 animate-pulse' :
                    asset.state === 'VULNERABLE' ? 'bg-amber-950/80 text-amber-400 border border-amber-800' :
                    'bg-slate-800 text-slate-300'
                  }`}>
                    {asset.state}
                  </span>
                </td>
                <td className="p-3 font-bold font-mono text-white">{asset.exposure_score.toFixed(1)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
