import React, { useState } from 'react';
import { Card, StatCard } from '../components/Card';
import Badge from '../components/Badge';
import { Radio, AlertOctagon, ShieldAlert, Activity, CheckCircle2, RefreshCw, Send, Check } from 'lucide-react';
import { createIncident } from '../services/api';

export default function MonitoringPage({ alerts = [], network, onEvaluateThreats, isEvaluating, onIncidentCreated }) {
  const [escalatingId, setEscalatingId] = useState(null);
  const [escalatedMap, setEscalatedMap] = useState({});

  const handleEscalate = async (alert) => {
    setEscalatingId(alert.id);
    try {
      await createIncident({
        network_id: network?.id || alert.network_id || 'university-sample-01',
        title: `INCIDENT: ${alert.threat_name || alert.title || 'Security Anomaly'}`,
        severity: alert.severity || 'high',
        affected_asset_id: alert.affected_asset_id || alert.target_device || 'db_server_01',
        alert_ids: [alert.id],
        initial_notes: `Escalated directly from Threat Monitoring. Triggered by rule: ${alert.triggered_rule || alert.rule_name}. Evidence: ${alert.evidence || alert.description}`
      });
      setEscalatedMap(prev => ({ ...prev, [alert.id]: true }));
      if (onIncidentCreated) {
        onIncidentCreated();
      }
    } catch (err) {
      console.error('Failed to escalate alert to incident:', err);
    } finally {
      setEscalatingId(null);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-[#253443]">Threat Detection & Security Monitoring</h1>
          <p className="text-sm text-[#718096] mt-1">
            Rule-based Intrusion Detection Engine (IDS) inspecting simulated network events and unauthorized access patterns.
          </p>
        </div>
        <button
          onClick={onEvaluateThreats}
          disabled={isEvaluating}
          className="flex items-center space-x-2 px-4 py-2 rounded-lg bg-[#397C78] hover:bg-[#2F6763] text-white text-xs font-semibold shadow-sm transition-all"
        >
          <RefreshCw className={`h-4 w-4 ${isEvaluating ? 'animate-spin' : ''}`} />
          <span>{isEvaluating ? 'Evaluating IDS Rules...' : 'Re-Evaluate Detection Engine'}</span>
        </button>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <StatCard
          label="Total Active Alerts"
          value={alerts.length}
          subtext="Rule-based IDS findings"
          icon={Radio}
          color={alerts.length > 0 ? 'danger' : 'success'}
        />
        <StatCard
          label="Critical Threats"
          value={alerts.filter(a => a.severity === 'critical').length}
          subtext="Direct exposure to core assets"
          icon={AlertOctagon}
          color="danger"
        />
        <StatCard
          label="Monitored Twin Status"
          value="100% Virtual"
          subtext="Telemetry ingested from simulated twin"
          icon={Activity}
          color="primary"
        />
      </div>

      <Card
        title="Active Threat Alerts"
        subtitle={`${alerts.length} alerts generated from simulated telemetry`}
      >
        {alerts.length === 0 ? (
          <div className="py-12 text-center text-[#718096]">
            <CheckCircle2 className="h-10 w-10 text-[#5B9678] mx-auto mb-2" />
            <p className="text-sm font-semibold text-[#253443]">No Threat Alerts Active</p>
            <p className="text-xs mt-1">Simulated telemetry has not triggered any intrusion detection rules.</p>
          </div>
        ) : (
          <div className="space-y-3">
            {alerts.map((a, i) => {
              const isEscalated = escalatedMap[a.id];
              const isEscalating = escalatingId === a.id;

              return (
                <div key={a.id || i} className="p-4 rounded-xl border border-[#E2E8F0] hover:border-[#80AAA1] bg-white transition-all space-y-2">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center space-x-2">
                      <Badge variant={a.severity === 'critical' ? 'danger' : 'warning'}>
                        {a.severity.toUpperCase()}
                      </Badge>
                      <span className="font-semibold text-xs text-[#253443]">{a.threat_name || a.title}</span>
                    </div>
                    
                    <div className="flex items-center space-x-2">
                      <span className="text-[11px] font-mono text-[#718096]">
                        {a.triggered_rule || a.rule_name || a.alert_code}
                      </span>
                      
                      <button
                        onClick={() => handleEscalate(a)}
                        disabled={isEscalated || isEscalating}
                        className={`px-3 py-1 text-xs font-semibold rounded-lg flex items-center space-x-1.5 transition-all ${
                          isEscalated
                            ? 'bg-[#5B9678]/10 text-[#5B9678] border border-[#5B9678]/30 cursor-default'
                            : 'bg-[#CE7373] hover:bg-[#B95D5D] text-white shadow-sm'
                        }`}
                      >
                        {isEscalated ? (
                          <>
                            <Check className="h-3 w-3" />
                            <span>Escalated</span>
                          </>
                        ) : (
                          <>
                            <Send className="h-3 w-3" />
                            <span>{isEscalating ? 'Escalating...' : 'Escalate to Incident'}</span>
                          </>
                        )}
                      </button>
                    </div>
                  </div>

                  <p className="text-xs text-[#253443] leading-relaxed">
                    <span className="font-semibold">Evidence:</span> {a.evidence || a.description}
                  </p>

                  <div className="flex flex-wrap items-center gap-4 text-[11px] text-[#718096] pt-1">
                    <span>Target Asset: <strong className="text-[#253443]">{a.affected_asset_name || a.affected_asset_id || a.target_device || 'Unknown'}</strong></span>
                    {a.recommended_action && (
                      <span className="text-[#397C78]">
                        <strong>Recommended Action:</strong> {a.recommended_action}
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </Card>
    </div>
  );
}
