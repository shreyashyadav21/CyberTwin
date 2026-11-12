import React from 'react';
import { Card } from '../components/Card';
import { Network, Plus, Shield, Layers, Server } from 'lucide-react';
import Badge from '../components/Badge';

export default function NetworkTwinPage({ network, onSelectNetwork }) {
  const devices = network?.devices || network?.topology?.devices || [];
  const rules = network?.rules || network?.topology?.security_rules || [];
  const connections = network?.connections || network?.topology?.connections || [];

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-[#253443]">Network Digital Twin</h1>
          <p className="text-sm text-[#718096] mt-1">
            Virtual topology model, device configurations, network segments, and security rules.
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <Badge variant="primary">Model: {network?.name || 'Default'}</Badge>
          <Badge variant="neutral">Devices: {devices.length}</Badge>
          <Badge variant="neutral">Rules: {rules.length}</Badge>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Device List Preview */}
        <Card title="Virtual Assets & Nodes" subtitle={`${devices.length} configured nodes in network model`} className="lg:col-span-2">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#F5F7F6] text-[#718096] font-semibold border-b border-[#E2E8F0]">
                <tr>
                  <th className="p-3">Device Name</th>
                  <th className="p-3">Type</th>
                  <th className="p-3">IP Address</th>
                  <th className="p-3">Zone</th>
                  <th className="p-3">Criticality</th>
                  <th className="p-3">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#E2E8F0]">
                {devices.map((d) => (
                  <tr key={d.id} className="hover:bg-[#F5F7F6]/50">
                    <td className="p-3 font-semibold text-[#253443] flex items-center space-x-2">
                      <Server className="h-3.5 w-3.5 text-[#397C78]" />
                      <span>{d.name}</span>
                    </td>
                    <td className="p-3 uppercase text-[10px] font-bold text-[#718096]">{d.type}</td>
                    <td className="p-3 font-mono text-[#718096]">{d.ip}</td>
                    <td className="p-3">
                      <span className="px-2 py-0.5 rounded-full bg-slate-100 text-slate-700 text-[10px] font-semibold">
                        {d.zone}
                      </span>
                    </td>
                    <td className="p-3">
                      <Badge variant={d.criticality === 'critical' ? 'danger' : d.criticality === 'high' ? 'warning' : 'neutral'}>
                        {d.criticality}
                      </Badge>
                    </td>
                    <td className="p-3">
                      <span className={`inline-flex items-center space-x-1 text-[11px] font-medium ${
                        d.security_status === 'compromised' ? 'text-[#CE7373]' :
                        d.security_status === 'isolated' ? 'text-[#D5A45C]' : 'text-[#5B9678]'
                      }`}>
                        <span className={`h-1.5 w-1.5 rounded-full ${
                          d.security_status === 'compromised' ? 'bg-[#CE7373]' :
                          d.security_status === 'isolated' ? 'bg-[#D5A45C]' : 'bg-[#5B9678]'
                        }`} />
                        <span className="capitalize">{d.security_status}</span>
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>

        {/* Security Rules Preview */}
        <Card title="Firewall & Security Rules" subtitle={`${rules.length} active policy entries`}>
          <div className="space-y-3">
            {rules.map((r) => (
              <div key={r.id} className="p-3 rounded-lg border border-[#E2E8F0] bg-[#F5F7F6] text-xs space-y-1">
                <div className="flex items-center justify-between">
                  <span className="font-mono font-bold text-[#253443]">{r.id}</span>
                  <Badge variant={r.action === 'allow' ? 'success' : 'danger'}>
                    {r.action.toUpperCase()}
                  </Badge>
                </div>
                <div className="text-[11px] text-[#718096]">
                  <span className="font-semibold text-[#253443]">{r.source}</span> → <span className="font-semibold text-[#253443]">{r.destination}</span>
                </div>
                <div className="text-[10px] text-[#718096] font-mono">
                  Port: {r.service}
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
}

