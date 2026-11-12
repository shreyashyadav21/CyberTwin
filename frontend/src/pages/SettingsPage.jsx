import React from 'react';
import { Card } from '../components/Card';
import Badge from '../components/Badge';
import { Settings, Shield, Server, Database, Key } from 'lucide-react';

export default function SettingsPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-[#253443]">System & Simulation Settings</h1>
        <p className="text-sm text-[#718096] mt-1">
          Digital twin simulation parameters, rule-based detection thresholds, and AI explanation providers.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <Card title="Simulation Engine Parameters" subtitle="Deterministic rule-based configuration">
          <div className="space-y-4 text-xs">
            <div>
              <label className="block font-semibold text-[#253443] mb-1">Randomness Seed</label>
              <input
                type="text"
                readOnly
                value="42 (Deterministic / Reproducible)"
                className="w-full p-2.5 rounded-lg border border-[#E2E8F0] bg-[#F5F7F6] text-[#253443] font-mono"
              />
            </div>
            <div>
              <label className="block font-semibold text-[#253443] mb-1">Default Firewall Behavior</label>
              <input
                type="text"
                readOnly
                value="Default-Deny at Boundaries (Deny overrides Allow)"
                className="w-full p-2.5 rounded-lg border border-[#E2E8F0] bg-[#F5F7F6] text-[#253443]"
              />
            </div>
            <div>
              <label className="block font-semibold text-[#253443] mb-1">Graph Path Algorithm</label>
              <input
                type="text"
                readOnly
                value="NetworkX BFS / DFS reachability with ACL filters"
                className="w-full p-2.5 rounded-lg border border-[#E2E8F0] bg-[#F5F7F6] text-[#253443]"
              />
            </div>
          </div>
        </Card>

        <Card title="AI Analyst & Explanations" subtitle="LLM integration for structured findings">
          <div className="space-y-4 text-xs">
            <div>
              <label className="block font-semibold text-[#253443] mb-1">AI Provider</label>
              <input
                type="text"
                readOnly
                value="Groq / OpenAI Compatible API (with Template Fallback)"
                className="w-full p-2.5 rounded-lg border border-[#E2E8F0] bg-[#F5F7F6] text-[#253443]"
              />
            </div>
            <div>
              <label className="block font-semibold text-[#253443] mb-1">Safety Constraints</label>
              <p className="text-slate-500 leading-relaxed">
                The LLM strictly explains structured simulation facts. It never invents non-existent devices, paths, or outcomes.
              </p>
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
}

