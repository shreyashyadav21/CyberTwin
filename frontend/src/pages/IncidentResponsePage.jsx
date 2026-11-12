import React, { useState } from 'react';
import { Card, StatCard } from '../components/Card';
import Badge from '../components/Badge';
import { AlertOctagon, ShieldAlert, ShieldCheck, CheckCircle2, Lock, Unlock, Play } from 'lucide-react';
import { isolateAsset, updateIncidentStatus } from '../services/api';

export default function IncidentResponsePage({ network, incidents = [], onRefresh }) {
  const [loadingId, setLoadingId] = useState(null);

  const handleIsolate = async (deviceId, isolate) => {
    setLoadingId(deviceId);
    try {
      await isolateAsset(network?.id || 'university-sample-01', deviceId, isolate);
      if (onRefresh) await onRefresh();
    } catch (err) {
      console.error('Failed to isolate device:', err);
    } finally {
      setLoadingId(null);
    }
  };

  const handleStatusChange = async (incidentId, newStatus) => {
    try {
      await updateIncidentStatus(incidentId, newStatus);
      if (onRefresh) await onRefresh();
    } catch (err) {
      console.error('Failed to update incident status:', err);
    }
  };

  const devices = network?.devices || network?.topology?.devices || [];

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-[#253443]">Incident Response & Containment</h1>
          <p className="text-sm text-[#718096] mt-1">
            Complete incident lifecycle: Triage, investigation, asset containment/isolation, and post-incident recovery.
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <Badge variant="primary">Incident SLA: Active</Badge>
          <Badge variant="neutral">Open Cases: {incidents.filter(i => i.status !== 'closed').length}</Badge>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Incident Cases */}
        <Card
          title="Active Incident Cases"
          subtitle={`${incidents.length} security events escalated to formal incidents`}
          className="lg:col-span-2"
        >
          {incidents.length === 0 ? (
            <div className="py-12 text-center text-[#718096]">
              <CheckCircle2 className="h-10 w-10 text-[#5B9678] mx-auto mb-2" />
              <p className="text-sm font-semibold text-[#253443]">No Open Incidents</p>
              <p className="text-xs mt-1">All simulated events are resolved or no incidents have been declared.</p>
            </div>
          ) : (
            <div className="space-y-4">
              {incidents.map((inc) => (
                <div key={inc.id} className="p-4 rounded-xl border border-[#E2E8F0] bg-white hover:border-[#80AAA1] transition-all space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center space-x-2">
                      <Badge variant={inc.severity === 'critical' ? 'danger' : 'warning'}>
                        {inc.severity.toUpperCase()}
                      </Badge>
                      <span className="font-semibold text-xs text-[#253443]">{inc.title}</span>
                    </div>
                    <select
                      value={inc.status}
                      onChange={(e) => handleStatusChange(inc.id, e.target.value)}
                      className="text-xs bg-[#F5F7F6] border border-[#E2E8F0] rounded px-2 py-1 font-semibold text-[#253443]"
                    >
                      <option value="open">OPEN (Triage)</option>
                      <option value="investigating">INVESTIGATING</option>
                      <option value="contained">CONTAINED</option>
                      <option value="resolved">RESOLVED</option>
                      <option value="closed">CLOSED</option>
                    </select>
                  </div>
                  <p className="text-xs text-[#253443]">{inc.description}</p>
                  <div className="flex items-center justify-between text-[11px] text-[#718096] pt-1 border-t border-[#EDF2F7]">
                    <span>Affected Device: <strong className="text-[#253443]">{inc.affected_device}</strong></span>
                    <span>Created: {new Date(inc.created_at).toLocaleTimeString()}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>

        {/* Rapid Containment Actions: Isolate Assets */}
        <Card
          title="Virtual Asset Containment"
          subtitle="Sever network connections to prevent lateral movement"
          className="lg:col-span-1"
        >
          <div className="space-y-3">
            {devices.map((d) => {
              const isIsolated = d.security_status === 'isolated';
              const isLoading = loadingId === d.id;

              return (
                <div
                  key={d.id}
                  className={`p-3 rounded-lg border flex items-center justify-between text-xs transition-colors ${
                    isIsolated ? 'bg-[#D5A45C]/10 border-[#D5A45C]/30' : 'bg-[#F5F7F6] border-[#E2E8F0]'
                  }`}
                >
                  <div>
                    <span className="font-semibold text-[#253443] block">{d.name}</span>
                    <span className="text-[10px] text-[#718096] font-mono">{d.ip} • {d.zone}</span>
                  </div>

                  <button
                    onClick={() => handleIsolate(d.id, !isIsolated)}
                    disabled={isLoading}
                    className={`px-2.5 py-1.5 rounded-lg text-xs font-semibold flex items-center space-x-1.5 transition-colors ${
                      isIsolated
                        ? 'bg-[#5B9678] text-white hover:bg-[#4E8268]'
                        : 'bg-[#CE7373] text-white hover:bg-[#B95D5D]'
                    }`}
                  >
                    {isIsolated ? (
                      <>
                        <Unlock className="h-3 w-3" />
                        <span>Restore</span>
                      </>
                    ) : (
                      <>
                        <Lock className="h-3 w-3" />
                        <span>Isolate</span>
                      </>
                    )}
                  </button>
                </div>
              );
            })}
          </div>
        </Card>
      </div>
    </div>
  );
}

