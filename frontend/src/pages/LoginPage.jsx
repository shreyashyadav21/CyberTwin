import React, { useState } from 'react';
import { Shield, Lock, Mail, ArrowRight, CheckCircle2, UserCheck, AlertCircle, KeyRound, Sparkles } from 'lucide-react';
import { loginUser } from '../services/api';

export default function LoginPage({ onLoginSuccess }) {
  const [email, setEmail] = useState('analyst@cybertwin.org');
  const [password, setPassword] = useState('CyberTwin#2026!');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  const handleLogin = async (e) => {
    if (e) e.preventDefault();
    setIsLoading(true);
    setError('');

    try {
      const data = await loginUser(email, password);
      onLoginSuccess(data.user);
    } catch (err) {
      setError(err?.response?.data?.detail || 'Authentication failed. Please verify credentials.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleQuickDemoLogin = async (demoEmail, demoName, role) => {
    setEmail(demoEmail);
    setPassword('DemoSecPass2026!');
    setIsLoading(true);
    setError('');
    try {
      const data = await loginUser(demoEmail, 'DemoSecPass2026!');
      const personaUser = {
        name: demoName,
        email: demoEmail,
        role: role,
        organization: 'State University SOC'
      };
      localStorage.setItem('cybertwin_user', JSON.stringify(personaUser));
      onLoginSuccess(personaUser);
    } catch (err) {
      setError('Demo login failed');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#1A242D] flex flex-col justify-center py-12 sm:px-6 lg:px-8 relative overflow-hidden">
      {/* Background Graphic Grid */}
      <div className="absolute inset-0 opacity-10 bg-[radial-gradient(#397C78_1px,transparent_1px)] [background-size:24px_24px] pointer-events-none" />

      {/* Decorative Glow */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-[#397C78]/20 rounded-full blur-3xl pointer-events-none" />

      <div className="sm:mx-auto sm:w-full sm:max-w-md relative z-10">
        {/* Brand Shield Logo */}
        <div className="flex justify-center">
          <div className="h-16 w-16 rounded-2xl bg-[#397C78] flex items-center justify-center text-white shadow-xl ring-8 ring-[#397C78]/20">
            <Shield className="h-9 w-9 stroke-[2.2]" />
          </div>
        </div>

        <h1 className="mt-5 text-center text-3xl font-extrabold tracking-tight text-white font-sans">
          CyberTwin
        </h1>
        <p className="mt-1 text-center text-xs font-semibold uppercase tracking-widest text-[#80AAA1]">
          Simulate • Detect • Defend • Improve
        </p>
        <p className="mt-2 text-center text-xs text-slate-400 max-w-sm mx-auto">
          Intelligent Cybersecurity Digital Twin & Controlled Attack Simulation Platform
        </p>
      </div>

      <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md relative z-10 px-4 sm:px-0">
        <div className="bg-[#202E39] py-8 px-6 sm:px-10 shadow-2xl rounded-2xl border border-[#2A3B49]">
          <form className="space-y-4" onSubmit={handleLogin}>
            {error && (
              <div className="p-3 rounded-lg bg-[#CE7373]/20 border border-[#CE7373]/30 text-xs text-[#CE7373] flex items-center space-x-2">
                <AlertCircle className="h-4 w-4 shrink-0" />
                <span>{error}</span>
              </div>
            )}

            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">
                Security Analyst Email
              </label>
              <div className="relative rounded-lg shadow-sm">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-400">
                  <Mail className="h-4 w-4 text-[#80AAA1]" />
                </div>
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="block w-full pl-10 pr-3 py-2.5 bg-[#1B2731] border border-[#2E3F4E] rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-[#397C78] focus:border-transparent transition-colors"
                  placeholder="analyst@cybertwin.org"
                />
              </div>
            </div>

            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="block text-xs font-semibold text-slate-300">
                  Password
                </label>
                <span className="text-[11px] text-[#80AAA1] hover:underline cursor-pointer">
                  Demo Pass: CyberTwin#2026!
                </span>
              </div>
              <div className="relative rounded-lg shadow-sm">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-400">
                  <KeyRound className="h-4 w-4 text-[#80AAA1]" />
                </div>
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="block w-full pl-10 pr-3 py-2.5 bg-[#1B2731] border border-[#2E3F4E] rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-[#397C78] focus:border-transparent transition-colors"
                  placeholder="••••••••••••"
                />
              </div>
            </div>

            <div className="pt-2">
              <button
                type="submit"
                disabled={isLoading}
                className="w-full flex items-center justify-center space-x-2 py-3 px-4 rounded-xl bg-[#397C78] hover:bg-[#2F6763] text-white text-xs font-bold uppercase tracking-wider shadow-lg transition-all"
              >
                {isLoading ? (
                  <>
                    <span className="h-4 w-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                    <span>Authenticating Session...</span>
                  </>
                ) : (
                  <>
                    <span>Enter CyberTwin Workspace</span>
                    <ArrowRight className="h-4 w-4" />
                  </>
                )}
              </button>
            </div>
          </form>

          {/* Quick Demo Personas (Hackathon / Reviewer friendly) */}
          <div className="mt-6 pt-6 border-t border-[#2A3B49]">
            <div className="flex items-center justify-between mb-2">
              <span className="text-[11px] font-bold uppercase tracking-wider text-[#80AAA1] flex items-center space-x-1">
                <Sparkles className="h-3 w-3" />
                <span>Instant Hackathon Review Logins</span>
              </span>
            </div>
            <p className="text-[11px] text-slate-400 mb-3">
              Click any role to log in with pre-configured access rights:
            </p>

            <div className="space-y-2">
              <button
                onClick={() => handleQuickDemoLogin('analyst@cybertwin.org', 'Alex Rivera, CISSP', 'Lead Security Analyst')}
                disabled={isLoading}
                className="w-full flex items-center justify-between p-2.5 rounded-lg bg-[#1B2731] hover:bg-[#253644] border border-[#2E3F4E] text-left transition-colors text-xs text-slate-200 group"
              >
                <div className="flex items-center space-x-2.5">
                  <div className="h-7 w-7 rounded bg-[#397C78]/20 flex items-center justify-center text-[#80AAA1] group-hover:bg-[#397C78] group-hover:text-white transition-colors">
                    <UserCheck className="h-3.5 w-3.5" />
                  </div>
                  <div>
                    <span className="font-semibold block text-white text-xs">Lead Security Analyst</span>
                    <span className="text-[10px] text-slate-400">Full Access • Attack Sim & Mitigation</span>
                  </div>
                </div>
                <ArrowRight className="h-3 w-3 text-slate-400 group-hover:text-white" />
              </button>

              <button
                onClick={() => handleQuickDemoLogin('responder@cybertwin.org', 'Jordan Vance', 'SOC Incident Responder')}
                disabled={isLoading}
                className="w-full flex items-center justify-between p-2.5 rounded-lg bg-[#1B2731] hover:bg-[#253644] border border-[#2E3F4E] text-left transition-colors text-xs text-slate-200 group"
              >
                <div className="flex items-center space-x-2.5">
                  <div className="h-7 w-7 rounded bg-[#D5A45C]/20 flex items-center justify-center text-[#D5A45C] group-hover:bg-[#D5A45C] group-hover:text-[#1A242D] transition-colors">
                    <Shield className="h-3.5 w-3.5" />
                  </div>
                  <div>
                    <span className="font-semibold block text-white text-xs">SOC Incident Responder</span>
                    <span className="text-[10px] text-slate-400">Triage • Asset Isolation • Alert Ingest</span>
                  </div>
                </div>
                <ArrowRight className="h-3 w-3 text-slate-400 group-hover:text-white" />
              </button>

              <button
                onClick={() => handleQuickDemoLogin('student@university.edu', 'Morgan Lee', 'Academic / Student Auditor')}
                disabled={isLoading}
                className="w-full flex items-center justify-between p-2.5 rounded-lg bg-[#1B2731] hover:bg-[#253644] border border-[#2E3F4E] text-left transition-colors text-xs text-slate-200 group"
              >
                <div className="flex items-center space-x-2.5">
                  <div className="h-7 w-7 rounded bg-[#5B9678]/20 flex items-center justify-center text-[#5B9678] group-hover:bg-[#5B9678] group-hover:text-white transition-colors">
                    <CheckCircle2 className="h-3.5 w-3.5" />
                  </div>
                  <div>
                    <span className="font-semibold block text-white text-xs">Academic / Student Auditor</span>
                    <span className="text-[10px] text-slate-400">Read-Only • Learning Scenarios & Reports</span>
                  </div>
                </div>
                <ArrowRight className="h-3 w-3 text-slate-400 group-hover:text-white" />
              </button>
            </div>
          </div>
        </div>

        {/* Security Disclaimers Badge */}
        <div className="mt-6 text-center text-[11px] text-slate-400 space-y-1">
          <p className="font-medium text-[#80AAA1]">
            🔒 100% Software Digital Twin • Safe Isolated Virtual Simulation
          </p>
          <p>Zero real external scanning • Deterministic rule-based outcomes</p>
        </div>
      </div>
    </div>
  );
}

