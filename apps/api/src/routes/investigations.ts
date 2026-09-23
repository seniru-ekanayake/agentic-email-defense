import { FastifyInstance, FastifyPluginOptions } from 'fastify';

export async function investigationRoutes(fastify: FastifyInstance, options: FastifyPluginOptions) {
  // In-memory mock store for Fastify standalone testing
  const mockIncidents = [
    {
      incident_id: 'INC-78A9B1',
      tenant_id: 'tenant-enterprise-demo',
      title: 'Critical Exploitation Attempt via Email Rendering (CVE-2023-35636)',
      severity: 'CRITICAL',
      overall_risk_score: 91.5,
      confidence: 0.95,
      status: 'CONTAINMENT_PROPOSED',
      target_identity: 'cfo@enterprise-corp.internal',
      mail_platform: 'Microsoft Exchange / Outlook Web Access (OWA)',
      exposure_status: 'Internet-Facing',
      interaction_required: 'VIEW',
      cve: 'CVE-2023-35636',
      attack_chain: [
        { stage: 'INITIAL_ACCESS', technique: 'T1566 Phishing', description: 'Attacker delivers crafted email from spoofed sender: spoofed-payroll@corporate-updates.net' },
        { stage: 'EMAIL_DELIVERY', technique: 'SMTP Transport', description: 'Email bypasses perimeter filters and lands in victim mailbox.' },
        { stage: 'RENDERING_PARSING', technique: 'URI Moniker Parsing', description: 'Victim previews email in mail client, triggering CVE-2023-35636 parser vulnerability.' },
        { stage: 'EXPLOITATION', technique: 'T1187 Forced Authentication', description: 'Client automatically attempts outbound SMB/WebDAV authentication leaking NTLM hash.' },
        { stage: 'SESSION_IDENTITY', technique: 'Credential Access', description: 'Identity cfo@enterprise-corp.internal credentials targeted for relay/hijacking.' },
        { stage: 'POST_EXPLOITATION', technique: 'T1114 Email Collection', description: 'Potential unauthorized mailbox access and persistent rule creation.' }
      ],
      mitre_techniques: [
        { technique_id: 'T1566.001', name: 'Phishing: Spearphishing Attachment', tactic: 'Initial Access' },
        { technique_id: 'T1187', name: 'Forced Authentication', tactic: 'Credential Access' }
      ],
      evidence_summary: [
        'SPF/DMARC failure detected for sender domain.',
        'Found URI handler: search-ms:query=compensation_q3.docx&crumb=location:\\\\198.51.100.42\\share',
        'Forced UNC/SMB callout to \\\\198.51.100.42\\share',
        'Target recipient is VIP CFO with high privilege.',
        'Software version 15.1.2507.17 identified on internet-facing OWA portal.'
      ],
      recommended_actions: [
        { action: 'quarantine_email', reasoning: 'Quarantine malicious email to prevent further rendering or user interaction.', requires_approval: true },
        { action: 'revoke_session', reasoning: 'Revoke active sessions to prevent NTLM/cookie relay exploitation.', requires_approval: true },
        { action: 'search_mailbox_history', reasoning: 'Search historical mailboxes for related campaign activity.', requires_approval: false }
      ],
      pending_approvals: [
        { tool_name: 'quarantine_email', approval_token: 'APP-5F6E5EFE', risk_level: 'MEDIUM' },
        { tool_name: 'revoke_session', approval_token: 'APP-7F0D89D0', risk_level: 'HIGH' }
      ],
      created_at: new Date().toISOString()
    }
  ];

  // List all incidents
  fastify.get('/api/v1/incidents', async (req, reply) => {
    return reply.send({
      total: mockIncidents.length,
      incidents: mockIncidents
    });
  });

  // Get incident by ID
  fastify.get('/api/v1/incidents/:id', async (req, reply) => {
    const { id } = req.params as { id: string };
    const inc = mockIncidents.find(i => i.incident_id === id) || mockIncidents[0];
    return reply.send(inc);
  });

  // Get incident attack graph
  fastify.get('/api/v1/incidents/:id/attack-graph', async (req, reply) => {
    return reply.send({
      nodes: [
        { id: 'actor-storm-0978', label: 'ThreatActor', name: 'Storm-0978' },
        { id: 'camp-q3-phish', label: 'Campaign', name: 'Q3 Executive Phishing' },
        { id: 'exp-2026-cve35636', label: 'Email', name: 'Crafted Compensation EML' },
        { id: 'cve-2023-35636', label: 'CVE', name: 'CVE-2023-35636 (Outlook Moniker)' },
        { id: 'asset-owa', label: 'Asset', name: 'owa.enterprise-corp.internal' },
        { id: 'ident-cfo', label: 'Identity', name: 'cfo@enterprise-corp.internal' },
        { id: 'sess-active-owa', label: 'Session', name: 'Active OWA Webmail Session' }
      ],
      edges: [
        { source: 'actor-storm-0978', target: 'camp-q3-phish', relation: 'ORCHESTRATES' },
        { source: 'camp-q3-phish', target: 'exp-2026-cve35636', relation: 'DELIVERS' },
        { source: 'exp-2026-cve35636', target: 'ident-cfo', relation: 'TARGETS' },
        { source: 'exp-2026-cve35636', target: 'asset-owa', relation: 'AFFECTS' },
        { source: 'exp-2026-cve35636', target: 'cve-2023-35636', relation: 'EXPLOITS' },
        { source: 'ident-cfo', target: 'sess-active-owa', relation: 'OWNS' },
        { source: 'cve-2023-35636', target: 'sess-active-owa', relation: 'TRIGGERS' }
      ]
    });
  });

  // Dedicated URL Detonation & Malicious Link Sandbox Endpoint
  fastify.post('/api/v1/sandbox/analyze-url', async (req, reply) => {
    const { url } = req.body as { url: string };
    const isSsrf = url.includes('169.254') || url.includes('localhost') || url.includes('127.0.0.1') || url.includes('192.168');
    const isPhish = url.includes('login') || url.includes('verify') || url.includes('update') || url.includes('.ru') || url.includes('.top');

    if (isSsrf) {
      return reply.send({
        scan_id: 'url-ssrf-block',
        submitted_url: url,
        verdict: 'BLOCKED_SSRF',
        threat_category: 'SSRF_PROBE',
        risk_score: 95.0,
        network_guard_blocked: true,
        evidence: ['NetworkGuard blocked target: Destination resolves to private subnet / cloud metadata endpoint.']
      });
    }

    return reply.send({
      scan_id: 'url-' + Math.random().toString(36).substring(7),
      submitted_url: url,
      final_destination_url: url,
      verdict: isPhish ? 'MALICIOUS' : 'CLEAN',
      threat_category: isPhish ? 'CREDENTIAL_PHISHING' : null,
      risk_score: isPhish ? 88.5 : 12.0,
      network_guard_blocked: false,
      page_features: {
        has_login_form: isPhish,
        has_password_field: isPhish,
        impersonated_brand: isPhish ? 'Microsoft 365' : null
      },
      evidence: isPhish ? [
        'Interactive credential submission form identified on page.',
        'Password input field detected.',
        'Brand impersonation detected: Page mimics Microsoft 365 login.'
      ] : ['Safe destination with standard static content.']
    });
  });
}
