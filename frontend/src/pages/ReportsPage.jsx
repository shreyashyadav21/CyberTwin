import React, { useState } from 'react';
import { Card } from '../components/Card';
import Badge from '../components/Badge';
import { FileText, Download, CheckCircle2, Shield, AlertTriangle, Printer, ExternalLink, RefreshCw } from 'lucide-react';
import { downloadReportPdfBlob, downloadReportPdfUrl } from '../services/api';

export default function ReportsPage({ network, assessment }) {
  const [isDownloading, setIsDownloading] = useState(false);
  const [downloadSuccess, setDownloadSuccess] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');

  const networkId = network?.id || 'university-sample-01';
  const directUrl = downloadReportPdfUrl(networkId);
  const backendDirectUrl = `http://127.0.0.1:8000/api/reports/${networkId}`;

  const handleDownload = async () => {
    setIsDownloading(true);
    setErrorMsg('');
    setDownloadSuccess(false);
    try {
      await downloadReportPdfBlob(networkId);
      setDownloadSuccess(true);
      setTimeout(() => setDownloadSuccess(false), 4000);
    } catch (err) {
      console.error('PDF download error:', err);
      // Fallback: direct window redirect
      window.open(backendDirectUrl, '_blank');
      setErrorMsg('Direct download triggered in new tab.');
    } finally {
      setIsDownloading(false);
    }
  };

  const findings = assessment?.findings || [];
  const riskScore = assessment?.overall_risk_score ?? assessment?.risk_score ?? 65;
  const securityScore = Math.max(0, 100 - riskScore);

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-[#253443]">Security Assessment Reports</h1>
          <p className="text-sm text-[#718096] mt-1">
            Automated PDF and compliance report generator compiled deterministically via ReportLab.
          </p>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={() => window.print()}
            className="flex items-center space-x-1.5 px-3 py-2 rounded-lg border border-[#E2E8F0] bg-white hover:bg-[#F5F7F6] text-[#253443] text-xs font-semibold shadow-sm transition-all"
          >
            <Printer className="h-4 w-4 text-[#718096]" />
            <span>Print View</span>
          </button>

          <button
            onClick={handleDownload}
            disabled={isDownloading}
            className="flex items-center space-x-2 px-4 py-2 rounded-lg bg-[#397C78] hover:bg-[#2F6763] text-white text-xs font-semibold shadow-sm transition-all disabled:opacity-50"
          >
            <Download className={`h-4 w-4 ${isDownloading ? 'animate-spin' : ''}`} />
            <span>{isDownloading ? 'Generating PDF...' : 'Download PDF Report'}</span>
          </button>
        </div>
      </div>

      {downloadSuccess && (
        <div className="p-3.5 rounded-xl bg-[#5B9678]/15 border border-[#5B9678]/30 text-xs font-semibold text-[#253443] flex items-center space-x-2">
          <CheckCircle2 className="h-4 w-4 text-[#5B9678] shrink-0" />
          <span>Security Assessment PDF report downloaded successfully to your device!</span>
        </div>
      )}

      {errorMsg && (
        <div className="p-3.5 rounded-xl bg-amber-500/15 border border-amber-500/30 text-xs text-[#253443] flex items-center space-x-2">
          <ExternalLink className="h-4 w-4 text-amber-600 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card title="Official CyberTwin Assessment Document" subtitle="Generated from live digital twin state" className="lg:col-span-2">
          <div className="p-6 rounded-xl border border-[#E2E8F0] bg-[#F5F7F6] space-y-5">
            <div className="flex items-center justify-between border-b border-[#E2E8F0] pb-4">
              <div className="flex items-center space-x-3">
                <div className="p-3 rounded-xl bg-[#397C78] text-white shadow-sm">
                  <Shield className="h-7 w-7" />
                </div>
                <div>
                  <h3 className="font-bold text-base text-[#253443]">CyberTwin Executive Security Audit</h3>
                  <p className="text-xs text-[#718096]">Scope: {network?.name || 'Campus Network Digital Twin'}</p>
                </div>
              </div>
              <Badge variant="success">Audit Complete</Badge>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs">
              <div className="p-3 rounded-lg bg-white border border-[#E2E8F0]">
                <span className="text-[#718096] block text-[10px] uppercase font-bold">Organization</span>
                <span className="font-semibold text-[#253443] text-sm">State University</span>
              </div>
              <div className="p-3 rounded-lg bg-white border border-[#E2E8F0]">
                <span className="text-[#718096] block text-[10px] uppercase font-bold">Security Score</span>
                <span className="font-bold text-[#5B9678] text-sm">{securityScore} / 100</span>
              </div>
              <div className="p-3 rounded-lg bg-white border border-[#E2E8F0]">
                <span className="text-[#718096] block text-[10px] uppercase font-bold">Risk Level</span>
                <span className={`font-bold text-sm ${riskScore > 60 ? 'text-[#CE7373]' : 'text-[#D5A45C]'}`}>
                  {riskScore > 60 ? 'CRITICAL' : 'MODERATE'} ({riskScore}/100)
                </span>
              </div>
              <div className="p-3 rounded-lg bg-white border border-[#E2E8F0]">
                <span className="text-[#718096] block text-[10px] uppercase font-bold">Document Engine</span>
                <span className="font-semibold text-[#253443] text-sm">ReportLab Vector</span>
              </div>
            </div>

            <div className="p-3.5 rounded-lg bg-white border border-[#E2E8F0] space-y-2 text-xs">
              <span className="font-bold text-[#253443] block">Executive Summary & Audit Scope:</span>
              <p className="text-[#718096] leading-relaxed">
                This document provides a formal security assessment of the active virtual network model. Analysis encompasses CIA Triad exposure, deterministic path reachability through stateful gateway firewalls, authentication strength against automated brute-force attempts, and recommended remediation controls.
              </p>
            </div>

            {/* Top Findings Quick Table */}
            <div className="space-y-2">
              <span className="text-xs font-bold text-[#253443] uppercase tracking-wider block">
                Vulnerability Registry Included in Report:
              </span>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs bg-white rounded-lg border border-[#E2E8F0] overflow-hidden">
                  <thead className="bg-[#202E39] text-white text-[11px]">
                    <tr>
                      <th className="p-2.5">Rule Code</th>
                      <th className="p-2.5">Severity</th>
                      <th className="p-2.5">Affected Asset</th>
                      <th className="p-2.5">Impact</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#E2E8F0]">
                    {findings.slice(0, 5).map((f, i) => (
                      <tr key={i} className="hover:bg-slate-50">
                        <td className="p-2.5 font-mono font-bold text-[#253443]">{f.rule_code}</td>
                        <td className="p-2.5">
                          <Badge variant={f.severity?.toLowerCase() === 'critical' ? 'danger' : 'warning'}>
                            {f.severity}
                          </Badge>
                        </td>
                        <td className="p-2.5 font-semibold text-[#253443]">{f.device_name || f.device}</td>
                        <td className="p-2.5 text-[#718096] text-[11px] truncate max-w-xs">{f.impact}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="pt-2 flex flex-wrap items-center gap-3">
              <button
                onClick={handleDownload}
                disabled={isDownloading}
                className="inline-flex items-center space-x-2 px-5 py-2.5 rounded-xl bg-[#253443] hover:bg-[#1B2731] text-white text-xs font-bold transition-all shadow-md"
              >
                <Download className="h-4 w-4 text-[#80AAA1]" />
                <span>Download Report (PDF Format)</span>
              </button>

              <a
                href={backendDirectUrl}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center space-x-1.5 px-3 py-2 rounded-lg text-xs text-[#397C78] hover:underline"
              >
                <span>Direct Backend Link</span>
                <ExternalLink className="h-3.5 w-3.5" />
              </a>
            </div>
          </div>
        </Card>

        {/* Right: Security Standards Card */}
        <Card title="Report Standards & Verification" subtitle="Safe academic simulation guarantees">
          <div className="space-y-3 text-xs text-[#718096] leading-relaxed">
            <div className="p-3.5 rounded-xl bg-white border border-[#E2E8F0]">
              <strong className="text-[#253443] block mb-1">100% Simulated Scope</strong>
              All findings are calculated purely against the virtual graph topology. Zero external network scanning or real system packet transmission is conducted.
            </div>
            <div className="p-3.5 rounded-xl bg-white border border-[#E2E8F0]">
              <strong className="text-[#253443] block mb-1">Custom Metric Transparency</strong>
              The 0-100 risk score is an explainable heuristic based on shortest path reachability to critical assets and credential entropy.
            </div>
            <div className="p-3.5 rounded-xl bg-white border border-[#E2E8F0]">
              <strong className="text-[#253443] block mb-1">Export Capabilities</strong>
              ReportLab compiles vector tables, typography, and page geometry into an industry-standard PDF document ready for presentation to hackathon judges.
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
}
