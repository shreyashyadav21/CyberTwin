import React, { useState } from 'react';
import { Card, StatCard } from '../components/Card';
import Badge from '../components/Badge';
import { SlidersHorizontal, ShieldCheck, CheckCircle2, ArrowRight, RefreshCw, Zap, TrendingUp, AlertTriangle } from 'lucide-react';
import { applySecurityControl } from '../services/api';

const CONTROLS = [
  {
    type: 'restrict_db_access',
    title: 'Restrict Database Access to Application Server',
    desc: 'Removes the dangerous 0.0.0.0/0 wildcard allow rule and restricts port 5432 to app_server_01 only.',
    category: 'Firewall & Microsegmentation',
    expectedImpact: 'Risk Score decreases significantly; lateral movement directly from student workstation to DB is blocked.'
  },
  {
    type: 'strengthen_auth',
    title: 'Enforce Strong MFA & Account Lockout',
    desc: 'Upgrades authentication strength on workstation and server nodes to "strong" and enables lockout after 3 failures.',
    category: 'Identity & Access Control',
    expectedImpact: 'Eliminates brute-force credential stuffing vulnerabilities.'
  },
  {
    type: 'disable_service',
    title: 'Disable Insecure Cleartext Services (Telnet/FTP)',
    desc: 'Shuts down legacy unencrypted services listening on ports 23 and 21 across campus assets.',
    category: 'Attack Surface Reduction',
    expectedImpact: 'Prevents cleartext credential interception and command injection.'
  },
  {
    type: 'rate_limiting',
    title: 'Deploy Perimeter SYN Rate Limiting & Cookies',
    desc: 'Configures edge firewall with TCP SYN cookies and per-source connection rate thresholds (100 req/s).',
    category: 'Availability & DoS Mitigation',
    expectedImpact: 'Mitigates volume surge saturation attacks against the web portal.'
  },
  {
    type: 'parameterized_queries',
    title: 'Deploy WAF & Parameterized Query Enforcement',
    desc: 'Enforces input validation filters and SQL parameter binding to neutralize SQL injection attempts.',
    category: 'Application Layer Defense',
    expectedImpact: 'Blocks SQL injection payloads and prevents unauthorized database leakage.'
  },
  {
    type: 'enforce_rbac',
    title: 'Enforce Strict Role-Based Access Control (RBAC)',
    desc: 'Blocks student subnets from reaching internal administrative APIs and server management backplanes.',
    category: 'Zero Trust Segmentation',
    expectedImpact: 'Thwarts unauthorized privilege escalation attempts.'
  }
];

export default function ControlsPage({ network, onRefresh }) {
  const [applyingType, setApplyingType] = useState(null);
  const [comparisonResult, setComparisonResult] = useState(null);

  const handleApply = async (controlType) => {
    setApplyingType(controlType);
    setComparisonResult(null);
    try {
      const res = await applySecurityControl({
        network_id: network?.id || 'university-sample-01',
        control_type: controlType
      });
      setComparisonResult(res.data);
      if (onRefresh) await onRefresh();
    } catch (err) {
      console.error('Failed to apply control:', err);
    } finally {
      setApplyingType(null);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-[#253443]">Defensive Security Controls</h1>
          <p className="text-sm text-[#718096] mt-1">
            Apply automated security mitigations and observe quantitative before-and-after risk reduction.
          </p>
        </div>
        <Badge variant="primary">Defensive Hardening Ready</Badge>
      </div>

      {comparisonResult && (
        <Card
          title="Before vs After Quantitative Verification"
          subtitle={`Simulated mitigation outcome for control: ${comparisonResult.applied_controls?.[0] || 'Defensive Hardening'}`}
          className="border-[#5B9678]/40 bg-[#5B9678]/5"
        >
          <div className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
              <div className="p-3 bg-white rounded-xl border border-[#E2E8F0]">
                <span className="text-[10px] text-[#718096] uppercase font-bold block">Pre-Mitigation Score</span>
                <span className="text-xl font-bold text-[#CE7373]">{comparisonResult.before_security_score} / 100</span>
              </div>
              <div className="p-3 bg-white rounded-xl border border-[#E2E8F0]">
                <span className="text-[10px] text-[#718096] uppercase font-bold block">Post-Mitigation Score</span>
                <span className="text-xl font-bold text-[#5B9678]">{comparisonResult.after_security_score} / 100</span>
              </div>
              <div className="p-3 bg-white rounded-xl border border-[#E2E8F0]">
                <span className="text-[10px] text-[#718096] uppercase font-bold block">Score Improvement</span>
                <span className="text-xl font-bold text-[#397C78]">+{comparisonResult.score_delta} pts</span>
              </div>
              <div className="p-3 bg-white rounded-xl border border-[#E2E8F0]">
                <span className="text-[10px] text-[#718096] uppercase font-bold block">Attack Blocked?</span>
                <span className={`text-xl font-bold ${comparisonResult.attack_blocked_after ? 'text-[#5B9678]' : 'text-[#CE7373]'}`}>
                  {comparisonResult.attack_blocked_after ? 'SUCCESSFULLY BLOCKED' : 'PARTIAL REDUCTION'}
                </span>
              </div>
            </div>

            <p className="text-xs text-[#253443] leading-relaxed bg-white p-3 rounded-lg border border-[#E2E8F0]">
              <strong className="text-[#397C78]">Verification Summary: </strong>
              {comparisonResult.summary}
            </p>
          </div>
        </Card>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {CONTROLS.map((ctrl) => {
          const isApplying = applyingType === ctrl.type;

          return (
            <div key={ctrl.type} className="bg-white border border-[#E2E8F0] rounded-xl p-5 hover:border-[#80AAA1] shadow-sm transition-all flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-[#397C78] bg-[#397C78]/10 px-2 py-0.5 rounded-full">
                    {ctrl.category}
                  </span>
                  <Badge variant="neutral">Automated</Badge>
                </div>
                <h3 className="text-sm font-bold text-[#253443] mb-1">{ctrl.title}</h3>
                <p className="text-xs text-[#718096] leading-relaxed mb-3">{ctrl.desc}</p>
                <div className="p-2.5 rounded-lg bg-[#F5F7F6] text-xs text-[#253443] border border-[#E2E8F0] mb-4">
                  <span className="font-semibold text-[#5B9678]">Expected Result: </span>
                  {ctrl.expectedImpact}
                </div>
              </div>

              <button
                onClick={() => handleApply(ctrl.type)}
                disabled={isApplying}
                className="w-full flex items-center justify-center space-x-2 px-4 py-2 rounded-lg bg-[#397C78] hover:bg-[#2F6763] text-white text-xs font-semibold transition-colors"
              >
                <Zap className={`h-3.5 w-3.5 ${isApplying ? 'animate-spin' : ''}`} />
                <span>{isApplying ? 'Applying Control...' : 'Deploy Security Control'}</span>
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
}
