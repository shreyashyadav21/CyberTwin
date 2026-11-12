import React, { useState } from 'react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  AlertTriangle, 
  AlertOctagon, 
  Server, 
  Database, 
  Lock, 
  Unlock, 
  Play, 
  Activity, 
  ArrowRight, 
  CheckCircle2, 
  XCircle, 
  TrendingUp, 
  FileText, 
  Flame,
  Radio,
  SlidersHorizontal,
  RefreshCw
} from 'lucide-react';
import { Card, StatCard } from '../components/Card';
import Badge from '../components/Badge';

export default function OverviewPage({
  network,
  assessment,
  alerts = [],
  incidents = [],
  simulations = [],
  onNavigate,
  onRunAssessment,
  isAssessing
}) {
  const devices = network?.devices || network?.topology?.devices || [];
  const rules = network?.rules || network?.topology?.security_rules || [];
  const connections = network?.connections || network?.topology?.connections || [];

  // Group devices by type
  const deviceCounts = devices.reduce((acc, d) => {
    acc[d.type] = (acc[d.type] || 0) + 1;
    return acc;
  }, {});

  // Severity counts from assessment findings
  const findings = assessment?.findings || [];
  const critCount = findings.filter(f => f.severity?.toLowerCase() === 'critical').length;
  const highCount = findings.filter(f => f.severity?.toLowerCase() === 'high').length;
  const medCount = findings.filter(f => f.severity?.toLowerCase() === 'medium').length;
  const lowCount = findings.filter(f => f.severity?.toLowerCase() === 'low').length;

  const riskScore = assessment?.overall_risk_score ?? 65;
  const securityScore = Math.max(0, 100 - riskScore);

  const getScoreColor = (score) => {
    if (score >= 75) return 'text-[#5B9678]';
    if (score >= 45) return 'text-[#D5A45C]';
    return 'text-[#CE7373]';
  };

  const getScoreLabel = (score) => {
    if (score >= 75) return 'Robust / Well Hardened';
    if (score >= 45) return 'Moderate Risk / Action Needed';
    return 'Critical Risk / Immediate Action Required';
  };

  const cia = assessment?.cia_triad || {
    confidentiality: 'At Risk',
    integrity: 'Compromised',
    availability: 'Partially Protected'
  };

  return (
    <div className="space-y-6">
      {/* Page Header with Action Banner */}
      <div className="bg-gradient-to-r from-[#202E39] to-[#2B3E4C] rounded-2xl p-6 text-white shadow-sm flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2 text-xs font-semibold text-[#80AAA1] uppercase tracking-wider mb-1">
            <span>Enterprise Digital Twin Telemetry</span>
            <span>•</span>
            <span className="text-emerald-400">Model Active</span>
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-white">
            {network?.name || 'Virtual Organizational Network'}
          </h1>
          <p className="text-sm text-slate-300 mt-1 max-w-2xl">
            {network?.description || 'Active simulated virtual network model. Run automated risk scans, execute controlled attack scenarios, and observe defensive mitigations in real-time.'}
          </p>
        </div>

        <div className="flex items-center space-x-3 shrink-0">
          <button
            onClick={onRunAssessment}
            disabled={isAssessing}
            className="flex items-center space-x-2 px-4 py-2.5 rounded-xl bg-[#397C78] hover:bg-[#2F6763] text-white text-sm font-semibold shadow-sm transition-all"
          >
            <RefreshCw className={`h-4 w-4 ${isAssessing ? 'animate-spin' : ''}`} />
            <span>{isAssessing ? 'Analyzing...' : 'Run Security Scan'}</span>
          </button>
          <button
            onClick={() => onNavigate('simulator')}
            className="flex items-center space-x-2 px-4 py-2.5 rounded-xl bg-white/10 hover:bg-white/15 text-white text-sm font-semibold border border-white/20 transition-all"
          >
            <Play className="h-4 w-4 text-[#80AAA1]" />
            <span>Launch Attack</span>
          </button>
        </div>
      </div>

      {/* Top Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          label="Security Health Score"
          value={`${securityScore}/100`}
          subtext={getScoreLabel(securityScore)}
          icon={ShieldCheck}
          color={securityScore >= 75 ? 'success' : securityScore >= 45 ? 'warning' : 'danger'}
        />

        <StatCard
          label="Total Virtual Assets"
          value={devices.length}
          subtext={`${deviceCounts.server || 0} Servers • ${deviceCounts.database || 0} DBs • ${deviceCounts.workstation || 0} PCs`}
          icon={Server}
          color="primary"
        />

        <StatCard
          label="Identified Vulnerabilities"
          value={findings.length}
          subtext={`${critCount} Critical • ${highCount} High`}
          icon={ShieldAlert}
          color={critCount > 0 ? 'danger' : 'warning'}
        />

        <StatCard
          label="Active Threat Alerts"
          value={alerts.length}
          subtext={`${incidents.length} Under Incident Investigation`}
          icon={Radio}
          color={alerts.length > 0 ? 'danger' : 'success'}
        />
      </div>

      {/* Main Grid: Security Posture & CIA Status */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Security Score Gauge & CIA Triad */}
        <Card
          title="Security Posture & CIA Impact"
          subtitle="Rule-based risk calculation derived from reachability and access controls"
          className="lg:col-span-1"
        >
          <div className="flex flex-col items-center text-center py-4">
            <div className="relative flex items-center justify-center">
              <div className="w-36 h-36 rounded-full border-8 border-slate-100 flex flex-col items-center justify-center">
                <span className={`text-4xl font-extrabold ${getScoreColor(securityScore)}`}>
                  {securityScore}
                </span>
                <span className="text-[11px] font-semibold text-[#718096] uppercase tracking-wider">
                  out of 100
                </span>
              </div>
            </div>
            <p className={`mt-3 text-xs font-bold uppercase tracking-wider ${getScoreColor(securityScore)}`}>
              {getScoreLabel(securityScore)}
            </p>
            <p className="text-xs text-[#718096] mt-1 max-w-xs">
              Risk Weight: Critical DB exposure, auth strength, and gateway rules.
            </p>
          </div>

          {/* CIA Triad Breakdown */}
          <div className="mt-4 pt-4 border-t border-[#E2E8F0] space-y-3">
            <h4 className="text-xs font-semibold text-[#253443] uppercase tracking-wider">
              CIA Triad Status (Simulated)
            </h4>

            <div className="flex items-center justify-between p-2.5 rounded-lg bg-[#F5F7F6]">
              <div className="flex items-center space-x-2.5">
                <div className="p-1.5 rounded bg-white text-[#397C78] shadow-2xs">
                  <Lock className="h-3.5 w-3.5" />
                </div>
                <div>
                  <span className="text-xs font-semibold text-[#253443] block">Confidentiality</span>
                  <span className="text-[11px] text-[#718096]">Sensitive database and student records</span>
                </div>
              </div>
              <Badge 
                variant={cia.confidentiality === 'Protected' ? 'success' : 'danger'}
                dot
              >
                {cia.confidentiality}
              </Badge>
            </div>

            <div className="flex items-center justify-between p-2.5 rounded-lg bg-[#F5F7F6]">
              <div className="flex items-center space-x-2.5">
                <div className="p-1.5 rounded bg-white text-[#397C78] shadow-2xs">
                  <Activity className="h-3.5 w-3.5" />
                </div>
                <div>
                  <span className="text-xs font-semibold text-[#253443] block">Integrity</span>
                  <span className="text-[11px] text-[#718096]">Access credentials and config parity</span>
                </div>
              </div>
              <Badge 
                variant={cia.integrity === 'Secured' ? 'success' : 'warning'}
                dot
              >
                {cia.integrity}
              </Badge>
            </div>

            <div className="flex items-center justify-between p-2.5 rounded-lg bg-[#F5F7F6]">
              <div className="flex items-center space-x-2.5">
                <div className="p-1.5 rounded bg-white text-[#397C78] shadow-2xs">
                  <Server className="h-3.5 w-3.5" />
                </div>
                <div>
                  <span className="text-xs font-semibold text-[#253443] block">Availability</span>
                  <span className="text-[11px] text-[#718096]">Web services & gateway routing</span>
                </div>
              </div>
              <Badge 
                variant={cia.availability === 'High' || cia.availability === 'Resilient' ? 'success' : 'warning'}
                dot
              >
                {cia.availability}
              </Badge>
            </div>
          </div>
        </Card>

        {/* Right Column: Top Critical Vulnerabilities & Mitigations */}
        <Card
          title="Identified Vulnerabilities & Attack Surface"
          subtitle={`${findings.length} rule-based findings detected on the virtual network`}
          className="lg:col-span-2"
          action={
            <button
              onClick={() => onNavigate('assessment')}
              className="text-xs font-semibold text-[#397C78] hover:underline flex items-center space-x-1"
            >
              <span>View Full Assessment</span>
              <ArrowRight className="h-3.5 w-3.5" />
            </button>
          }
        >
          {findings.length === 0 ? (
            <div className="py-12 text-center text-[#718096]">
              <CheckCircle2 className="h-10 w-10 text-[#5B9678] mx-auto mb-2" />
              <p className="text-sm font-semibold text-[#253443]">Zero Critical Weaknesses Detected</p>
              <p className="text-xs mt-1">The active digital twin adheres to baseline microsegmentation and strong auth policies.</p>
            </div>
          ) : (
            <div className="space-y-3">
              {findings.slice(0, 4).map((f, i) => (
                <div
                  key={i}
                  className="p-3.5 rounded-xl border border-[#E2E8F0] hover:border-[#80AAA1] bg-white transition-all flex flex-col md:flex-row md:items-center justify-between gap-3"
                >
                  <div className="space-y-1">
                    <div className="flex items-center space-x-2">
                      <Badge variant={f.severity?.toLowerCase() === 'critical' ? 'danger' : 'warning'}>
                        {f.severity}
                      </Badge>
                      <span className="text-xs font-mono font-bold text-[#253443]">
                        {f.rule_code}
                      </span>
                      <span className="text-xs text-[#718096]">
                        • Device: <span className="font-semibold text-[#253443]">{f.device_name || f.device}</span>
                      </span>
                    </div>
                    <p className="text-xs text-[#253443] font-medium leading-relaxed">
                      {f.impact}
                    </p>
                    <p className="text-[11px] text-[#718096]">
                      <span className="font-semibold text-[#397C78]">Mitigation:</span> {f.mitigation}
                    </p>
                  </div>

                  <button
                    onClick={() => onNavigate('controls')}
                    className="shrink-0 text-xs px-3 py-1.5 rounded-lg border border-[#397C78] text-[#397C78] hover:bg-[#397C78] hover:text-white font-medium transition-colors"
                  >
                    Apply Control
                  </button>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>

      {/* Quick Launchpad to All 6 Cybersecurity Learning Areas */}
      <Card
        title="Cybersecurity Operations Workflow"
        subtitle="End-to-end twin workflow: Model, simulate, detect, contain, and remediate"
      >
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
          <button
            onClick={() => onNavigate('network-twin')}
            className="p-4 rounded-xl border border-[#E2E8F0] hover:border-[#397C78] hover:bg-[#F5F7F6] text-left transition-all group"
          >
            <div className="p-2 rounded-lg bg-[#397C78]/10 text-[#397C78] w-fit mb-3 group-hover:bg-[#397C78] group-hover:text-white transition-colors">
              <Server className="h-5 w-5" />
            </div>
            <div className="text-xs font-bold text-[#253443]">1. Network Twin</div>
            <div className="text-[11px] text-[#718096] mt-0.5">Interactive topology & rule ACLs</div>
          </button>

          <button
            onClick={() => onNavigate('assessment')}
            className="p-4 rounded-xl border border-[#E2E8F0] hover:border-[#397C78] hover:bg-[#F5F7F6] text-left transition-all group"
          >
            <div className="p-2 rounded-lg bg-[#397C78]/10 text-[#397C78] w-fit mb-3 group-hover:bg-[#397C78] group-hover:text-white transition-colors">
              <ShieldAlert className="h-5 w-5" />
            </div>
            <div className="text-xs font-bold text-[#253443]">2. Assessment</div>
            <div className="text-[11px] text-[#718096] mt-0.5">CIA evaluation & vulnerability scan</div>
          </button>

          <button
            onClick={() => onNavigate('simulator')}
            className="p-4 rounded-xl border border-[#E2E8F0] hover:border-[#397C78] hover:bg-[#F5F7F6] text-left transition-all group"
          >
            <div className="p-2 rounded-lg bg-[#397C78]/10 text-[#397C78] w-fit mb-3 group-hover:bg-[#397C78] group-hover:text-white transition-colors">
              <Flame className="h-5 w-5" />
            </div>
            <div className="text-xs font-bold text-[#253443]">3. Attack Simulator</div>
            <div className="text-[11px] text-[#718096] mt-0.5">Step-by-step canvas execution</div>
          </button>

          <button
            onClick={() => onNavigate('monitoring')}
            className="p-4 rounded-xl border border-[#E2E8F0] hover:border-[#397C78] hover:bg-[#F5F7F6] text-left transition-all group"
          >
            <div className="p-2 rounded-lg bg-[#397C78]/10 text-[#397C78] w-fit mb-3 group-hover:bg-[#397C78] group-hover:text-white transition-colors">
              <Radio className="h-5 w-5" />
            </div>
            <div className="text-xs font-bold text-[#253443]">4. Threat Monitor</div>
            <div className="text-[11px] text-[#718096] mt-0.5">Real-time alerts & packet logs</div>
          </button>

          <button
            onClick={() => onNavigate('incidents')}
            className="p-4 rounded-xl border border-[#E2E8F0] hover:border-[#397C78] hover:bg-[#F5F7F6] text-left transition-all group"
          >
            <div className="p-2 rounded-lg bg-[#397C78]/10 text-[#397C78] w-fit mb-3 group-hover:bg-[#397C78] group-hover:text-white transition-colors">
              <AlertOctagon className="h-5 w-5" />
            </div>
            <div className="text-xs font-bold text-[#253443]">5. Incident Response</div>
            <div className="text-[11px] text-[#718096] mt-0.5">Investigate & isolate assets</div>
          </button>

          <button
            onClick={() => onNavigate('controls')}
            className="p-4 rounded-xl border border-[#E2E8F0] hover:border-[#397C78] hover:bg-[#F5F7F6] text-left transition-all group"
          >
            <div className="p-2 rounded-lg bg-[#397C78]/10 text-[#397C78] w-fit mb-3 group-hover:bg-[#397C78] group-hover:text-white transition-colors">
              <SlidersHorizontal className="h-5 w-5" />
            </div>
            <div className="text-xs font-bold text-[#253443]">6. Defend & Compare</div>
            <div className="text-[11px] text-[#718096] mt-0.5">Apply ACLs & observe changes</div>
          </button>
        </div>
      </Card>
    </div>
  );
}

