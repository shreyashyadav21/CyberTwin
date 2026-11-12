import React, { useState, useEffect, useCallback } from 'react';
import Sidebar from './components/Sidebar';
import TopNavbar from './components/TopNavbar';
import LoginPage from './pages/LoginPage';
import OverviewPage from './pages/OverviewPage';
import NetworkTwinPage from './pages/NetworkTwinPage';
import AssessmentPage from './pages/AssessmentPage';
import SimulatorPage from './pages/SimulatorPage';
import MonitoringPage from './pages/MonitoringPage';
import IncidentResponsePage from './pages/IncidentResponsePage';
import ControlsPage from './pages/ControlsPage';
import ReportsPage from './pages/ReportsPage';
import SettingsPage from './pages/SettingsPage';
import { 
  getNetworks, 
  getNetwork, 
  getAssessment, 
  runAssessment, 
  getThreatAlerts, 
  evaluateThreats, 
  getIncidents, 
  getSimulations,
  applySecurityControl,
  getCurrentUser,
  logoutUser
} from './services/api';

export default function App() {
  const [currentUser, setCurrentUser] = useState(() => getCurrentUser());
  const [activeTab, setActiveTab] = useState('overview');
  const [networks, setNetworks] = useState([]);
  const [currentNetworkId, setCurrentNetworkId] = useState('university-sample-01');
  const [currentNetwork, setCurrentNetwork] = useState(null);
  const [assessment, setAssessment] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [simulations, setSimulations] = useState([]);

  const [isLoading, setIsLoading] = useState(true);
  const [isAssessing, setIsAssessing] = useState(false);
  const [isEvaluating, setIsEvaluating] = useState(false);
  const [demoStep, setDemoStep] = useState(null);

  // Load all telemetry for the selected network
  const loadNetworkData = useCallback(async (networkId) => {
    setIsLoading(true);
    try {
      const netRes = await getNetwork(networkId);
      setCurrentNetwork(netRes.data);

      // Concurrently fetch assessment, threats, incidents, simulations
      const [assessRes, alertsRes, incsRes, simsRes] = await Promise.allSettled([
        getAssessment(networkId),
        getThreatAlerts(networkId),
        getIncidents(networkId),
        getSimulations(networkId)
      ]);

      if (assessRes.status === 'fulfilled') setAssessment(assessRes.value.data);
      if (alertsRes.status === 'fulfilled') setAlerts(alertsRes.value.data);
      if (incsRes.status === 'fulfilled') setIncidents(incsRes.value.data);
      if (simsRes.status === 'fulfilled') setSimulations(simsRes.value.data);
    } catch (err) {
      console.error('Failed to load network telemetry:', err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  // Initial bootstrap: load network list
  useEffect(() => {
    if (!currentUser) return;

    const init = async () => {
      try {
        const res = await getNetworks();
        setNetworks(res.data);
        if (res.data.length > 0) {
          const defaultNet = res.data[0].id;
          setCurrentNetworkId(defaultNet);
          await loadNetworkData(defaultNet);
        }
      } catch (err) {
        console.error('Initialization error:', err);
        setIsLoading(false);
      }
    };
    init();
  }, [currentUser, loadNetworkData]);

  // Handle network change
  const handleSelectNetwork = (id) => {
    setCurrentNetworkId(id);
    loadNetworkData(id);
  };

  // Run security assessment
  const handleRunAssessment = async () => {
    setIsAssessing(true);
    try {
      const res = await runAssessment(currentNetworkId);
      setAssessment(res.data);
    } catch (err) {
      console.error('Assessment failed:', err);
    } finally {
      setIsAssessing(false);
    }
  };

  // Evaluate threats
  const handleEvaluateThreats = async () => {
    setIsEvaluating(true);
    try {
      const res = await evaluateThreats(currentNetworkId);
      setAlerts(res.data);
    } catch (err) {
      console.error('Threat evaluation failed:', err);
    } finally {
      setIsEvaluating(false);
    }
  };

  // Logout handler
  const handleLogout = () => {
    logoutUser();
    setCurrentUser(null);
  };

  // 9-Step Hackathon Demo Mode automated tour
  const handleStartDemoMode = async () => {
    setDemoStep('Step 1: Inspecting baseline vulnerable twin...');
    setActiveTab('overview');
    await loadNetworkData('university-sample-01');

    setTimeout(() => {
      setDemoStep('Step 2: Viewing Network Digital Twin canvas & assets...');
      setActiveTab('network-twin');
    }, 2000);

    setTimeout(() => {
      setDemoStep('Step 3: Running Rule-Based Vulnerability Assessment...');
      setActiveTab('assessment');
    }, 4500);

    setTimeout(() => {
      setDemoStep('Step 4: Executing Lateral Movement attack simulation...');
      setActiveTab('simulator');
    }, 7000);

    setTimeout(() => {
      setDemoStep('Step 5: Inspecting IDS real-time alerts...');
      setActiveTab('monitoring');
    }, 9500);

    setTimeout(() => {
      setDemoStep('Step 6: Triaging incident and isolating compromised node...');
      setActiveTab('incidents');
    }, 12000);

    setTimeout(() => {
      setDemoStep('Step 7: Applying defensive firewall microsegmentation...');
      setActiveTab('controls');
    }, 14500);

    setTimeout(() => {
      setDemoStep('Step 8: Verifying risk reduction in Reports & PDF export...');
      setActiveTab('reports');
    }, 17000);

    setTimeout(() => {
      setDemoStep(null);
    }, 20000);
  };

  // If user is not logged in, show sleek Login Page
  if (!currentUser) {
    return (
      <LoginPage 
        onLoginSuccess={(user) => {
          setCurrentUser(user);
        }} 
      />
    );
  }

  return (
    <div className="flex h-screen bg-[#F5F7F6] overflow-hidden">
      {/* Fixed Left Navigation Sidebar */}
      <Sidebar
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        alertsCount={alerts.length}
        incidentsCount={incidents.filter(i => i.status !== 'closed').length}
      />

      {/* Main View Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top Navbar */}
        <TopNavbar
          networks={networks}
          currentNetwork={currentNetwork}
          onSelectNetwork={handleSelectNetwork}
          alertsCount={alerts.length}
          onStartDemoMode={handleStartDemoMode}
          onRefresh={() => loadNetworkData(currentNetworkId)}
          isRefreshing={isLoading}
          currentUser={currentUser}
          onLogout={handleLogout}
        />

        {/* Demo Mode Notification Toast */}
        {demoStep && (
          <div className="bg-[#397C78] text-white text-xs font-semibold px-6 py-2 flex items-center justify-between shadow-md transition-all animate-pulse">
            <div className="flex items-center space-x-2">
              <span className="h-2 w-2 rounded-full bg-emerald-300 inline-block" />
              <span>HACKATHON DEMO TOUR: {demoStep}</span>
            </div>
            <button
              onClick={() => setDemoStep(null)}
              className="text-white hover:text-slate-200 text-xs font-bold"
            >
              Exit Tour
            </button>
          </div>
        )}

        {/* Main Content Scrollable Area */}
        <main className="flex-1 overflow-y-auto p-6">
          <div className="max-w-7xl mx-auto">
            {activeTab === 'overview' && (
              <OverviewPage
                network={currentNetwork}
                assessment={assessment}
                alerts={alerts}
                incidents={incidents}
                simulations={simulations}
                onNavigate={setActiveTab}
                onRunAssessment={handleRunAssessment}
                isAssessing={isAssessing}
              />
            )}

            {activeTab === 'network-twin' && (
              <NetworkTwinPage
                network={currentNetwork}
                onSelectNetwork={handleSelectNetwork}
              />
            )}

            {activeTab === 'assessment' && (
              <AssessmentPage
                network={currentNetwork}
                assessment={assessment}
                onRunAssessment={handleRunAssessment}
                isAssessing={isAssessing}
              />
            )}

            {activeTab === 'simulator' && (
              <SimulatorPage
                network={currentNetwork}
                onSimulationFinished={() => loadNetworkData(currentNetworkId)}
              />
            )}

            {activeTab === 'monitoring' && (
              <MonitoringPage
                alerts={alerts}
                network={currentNetwork}
                onEvaluateThreats={handleEvaluateThreats}
                isEvaluating={isEvaluating}
                onIncidentCreated={() => loadNetworkData(currentNetworkId)}
              />
            )}

            {activeTab === 'incidents' && (
              <IncidentResponsePage
                network={currentNetwork}
                incidents={incidents}
                onRefresh={() => loadNetworkData(currentNetworkId)}
              />
            )}

            {activeTab === 'controls' && (
              <ControlsPage
                network={currentNetwork}
                onRefresh={() => loadNetworkData(currentNetworkId)}
              />
            )}

            {activeTab === 'reports' && (
              <ReportsPage
                network={currentNetwork}
                assessment={assessment}
              />
            )}

            {activeTab === 'settings' && (
              <SettingsPage />
            )}
          </div>
        </main>
      </div>
    </div>
  );
}
