import React from 'react';
import { Card, StatCard } from '../components/Card';
import Badge from '../components/Badge';
import { ShieldAlert, CheckCircle2, AlertTriangle, RefreshCw, Lock, Activity, Server, FileText, Calculator, HelpCircle } from 'lucide-react';

export default function AssessmentPage({ network, assessment, onRunAssessment, isAssessing }) {
  const findings = assessment?.findings || [];
  const riskScore = assessment?.risk_score ?? assessment?.overall_risk_score ?? 65;
  const securityScore = assessment?.security_score ?? Math.max(0, 100 - riskScore);
  const cia = assessment?.cia_triad || {};

  const confStatus = cia.confidentiality_status || cia.confidentiality || 'At Risk';
  const integStatus = cia.integrity_status || cia.integrity || 'Degraded';
  const availStatus = cia.availability_status || cia.availability || 'Operational';

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-[#253443]">Security Assessment & Vulnerability Analysis</h1>
          <p className="text-sm text-[#718096] mt-1">
            Deterministic rule-based inspection across authentication, firewall ACLs, services, and segmentation.
          </p>
        </div>
        <button
          onClick={onRunAssessment}
          disabled={isAssessing}
          className="flex items-center space-x-2 px-4 py-2 rounded-lg bg-[#397C78] hover:bg-[#2F6763] text-white text-xs font-semibold shadow-sm transition-all"
        >
          <RefreshCw className={`h-4 w-4 ${isAssessing ? 'animate-spin' : ''}`} />
          <span>{isAssessing ? 'Evaluating Network...' : 'Re-Run Assessment'}</span>
        </button>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          label="Security Health Score"
          value={`${securityScore}/100`}
          subtext={`Risk: ${riskScore} pts (100 - Risk)`}
          icon={ShieldAlert}
          color={securityScore >= 70 ? 'success' : securityScore >= 40 ? 'warning' : 'danger'}
        />
        <StatCard
          label="Confidentiality Impact"
          value={confStatus}
          subtext={cia.confidentiality_desc ? 'Data isolation evaluation' : 'Database exposure check'}
          icon={Lock}
          color={confStatus === 'Strong' || confStatus === 'Protected' ? 'success' : 'danger'}
        />
        <StatCard
          label="Integrity Posture"
          value={integStatus}
          subtext={cia.integrity_desc ? 'State modification pathway' : 'Authentication strength'}
          icon={Activity}
          color={integStatus === 'Maintained' || integStatus === 'Secured' ? 'success' : 'warning'}
        />
        <StatCard
          label="Availability Score"
          value={availStatus}
          subtext="DoS & open service exposure"
          icon={Server}
          color="primary"
        />
      </div>

      {/* Transparent Calculation Formula Card */}
      <Card
        title="Transparent Scoring Formula & Methodology"
        subtitle="Mathematical derivation of the Digital Twin Security Score"
      >
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          <div className="p-3 bg-[#F5F7F6] rounded-xl border border-[#E2E8F0]">
            <div className="flex items-center space-x-1.5 font-bold text-[#253443] mb-1">
              <Calculator className="h-4 w-4 text-[#397C78]" />
              <span>Mathematical Formula</span>
            </div>
            <p className="text-[#718096] font-mono text-[11px] leading-relaxed">
              Risk = min(100, &Sigma; [Weight(Severity) &times; Multiplier(Criticality)])<br />
              Security Score = 100 - Risk
            </p>
          </div>

          <div className="p-3 bg-[#F5F7F6] rounded-xl border border-[#E2E8F0]">
            <div className="font-bold text-[#253443] mb-1">Severity Base Weights</div>
            <ul className="text-[#718096] text-[11px] space-y-0.5">
              <li><strong className="text-[#CE7373]">Critical:</strong> 25.0 points</li>
              <li><strong className="text-[#D5A45C]">High:</strong> 15.0 points</li>
              <li><strong className="text-[#397C78]">Medium:</strong> 8.0 points</li>
              <li><strong className="text-slate-500">Low / Info:</strong> 3.0 / 1.0 points</li>
            </ul>
          </div>

          <div className="p-3 bg-[#F5F7F6] rounded-xl border border-[#E2E8F0]">
            <div className="font-bold text-[#253443] mb-1">Asset Criticality Multipliers</div>
            <ul className="text-[#718096] text-[11px] space-y-0.5">
              <li><strong className="text-[#253443]">Critical Tier (Database):</strong> 2.0&times;</li>
              <li><strong className="text-[#253443]">High Tier (App Server / Firewall):</strong> 1.5&times;</li>
              <li><strong className="text-[#253443]">Medium Tier (Faculty):</strong> 1.0&times;</li>
              <li><strong className="text-[#253443]">Low Tier (Student Lab):</strong> 0.5&times;</li>
            </ul>
          </div>
        </div>
      </Card>

      {/* Findings Table */}
      <Card
        title="Detected Vulnerability Findings"
        subtitle={`Total ${findings.length} findings identified across network twin nodes`}
      >
        <div className="space-y-4">
          {findings.map((f, i) => (
            <div key={i} className="p-4 rounded-xl border border-[#E2E8F0] bg-white hover:border-[#80AAA1] transition-all space-y-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center space-x-2">
                  <Badge variant={f.severity?.toLowerCase() === 'critical' ? 'danger' : f.severity?.toLowerCase() === 'high' ? 'warning' : 'neutral'}>
                    {f.severity.toUpperCase()}
                  </Badge>
                  <span className="font-mono font-bold text-sm text-[#253443]">{f.rule_code}</span>
                  <span className="text-xs text-[#718096]">
                    Target: <span className="font-semibold text-[#253443]">{f.device_name || f.device}</span>
                  </span>
                </div>
                <span className="text-[11px] font-mono bg-slate-100 text-slate-700 px-2 py-0.5 rounded font-semibold">
                  Risk Impact: +{f.risk_score} pts
                </span>
              </div>
              <div className="text-xs text-[#253443] leading-relaxed">
                <span className="font-semibold">Evidence:</span> {f.evidence}
              </div>
              <div className="text-xs text-[#253443] leading-relaxed">
                <span className="font-semibold">Security Impact:</span> {f.impact}
              </div>
              <div className="p-2.5 rounded-lg bg-[#5B9678]/10 text-xs text-[#253443] border border-[#5B9678]/20 flex items-start space-x-2">
                <CheckCircle2 className="h-4 w-4 text-[#5B9678] shrink-0 mt-0.5" />
                <div>
                  <span className="font-semibold text-[#5B9678]">Recommended Mitigation: </span>
                  {f.mitigation}
                </div>
              </div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
