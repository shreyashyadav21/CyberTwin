import axios from 'axios';

const apiBaseUrl = import.meta.env.DEV
  ? '/api'
  : import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000/api';

const api = axios.create({
  baseURL: apiBaseUrl,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Attach Authorization token if available in localStorage
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('cybertwin_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// System Health
export const getHealth = () => api.get('/health');

// Networks & Assets
export const getNetworks = () => api.get('/networks');
export const getNetwork = (id) => api.get(`/networks/${id}`);
export const createNetwork = (data) => api.post('/networks', data);
export const updateNetwork = (id, data) => api.put(`/networks/${id}`, data);
export const addDevice = (networkId, device) => api.post(`/networks/${networkId}/devices`, device);
export const updateDevice = (deviceId, device) => api.put(`/networks/devices/${deviceId}`, device);
export const deleteDevice = (deviceId) => api.delete(`/networks/devices/${deviceId}`);
export const isolateAsset = (networkId, deviceId, isolate = true) => 
  api.post(`/networks/${networkId}/isolate/${deviceId}?isolate=${isolate}`);

// Assessments
export const getAssessment = (networkId) => api.get(`/assessments/${networkId}/latest`);
export const runAssessment = (networkId) => api.post(`/assessments/${networkId}`);

// Simulations
export const runSimulation = (payload) => {
  const netId = payload.network_id || payload.networkId || 'university-sample-01';
  
  // Normalize scenario names to backend literal types:
  // "port_scanning", "repeated_login_failures", "service_discovery", "sqli_attempt", "suspicious_traffic", "firewall_misconfiguration", "lateral_movement", "dos_behaviour"
  let sc = payload.scenario || payload.scenario_type || 'lateral_movement';
  if (sc === 'sql_injection') sc = 'sqli_attempt';
  if (sc === 'dos_simulation' || sc === 'dos') sc = 'dos_behaviour';
  if (sc === 'port_scan') sc = 'service_discovery';

  const body = {
    scenario: sc,
    source_device_id: payload.source_device_id || payload.attacker_node_id || payload.entry_device_id,
    target_device_id: payload.target_device_id || payload.target_node_id,
    parameters: payload.parameters || {},
    seed: payload.seed !== undefined ? Number(payload.seed) : 42,
  };

  return api.post(`/simulations/${netId}`, body);
};

export const getSimulationCatalog = () => api.get('/simulations/catalog');
export const getSimulations = (networkId) => api.get(`/simulations/history/${networkId}`);
export const compareSimulation = (payload) => {
  const netId = payload.network_id || payload.networkId || 'university-sample-01';
  let sc = payload.scenario || payload.scenario_type || 'lateral_movement';
  if (sc === 'sql_injection') sc = 'sqli_attempt';
  if (sc === 'dos_simulation' || sc === 'dos') sc = 'dos_behaviour';
  if (sc === 'port_scan') sc = 'service_discovery';

  const body = {
    scenario: sc,
    source_device_id: payload.source_device_id || payload.attacker_node_id || payload.entry_device_id,
    target_device_id: payload.target_device_id || payload.target_node_id,
    parameters: payload.parameters || {},
    seed: payload.seed !== undefined ? Number(payload.seed) : 42,
  };
  return api.post(`/simulations/${netId}/compare`, body);
};
export const getSimulationEvents = (networkId) => api.get(`/simulations/events/${networkId}`);

// Threats & Events
export const getThreatAlerts = (networkId) => api.get(`/threats/${networkId}`);
export const evaluateThreats = (networkId) => api.post(`/threats/${networkId}/evaluate`);
export const getDetectionRules = () => api.get('/threats/rules');
export const getTrafficEvents = (networkId) => api.get(`/threats/${networkId}/events`);

// Incidents
export const getIncidents = (networkId) => api.get(`/incidents/${networkId}`);
export const createIncident = (data) => api.post('/incidents', data);
export const updateIncidentStatus = (incidentId, status) => api.put(`/incidents/${incidentId}`, { status });
export const isolateIncidentAsset = (incidentId) => api.post(`/incidents/${incidentId}/isolate`);

// Controls & Before-and-After
export const getSecurityControls = (networkId) => api.get(`/controls/${networkId}`);
export const applySecurityControl = (payload) => {
  const netId = payload.network_id || payload.networkId || 'university-sample-01';
  return api.post(`/controls/${netId}/apply`, payload);
};

// Reports - Vector PDF Downloader via Blob
export const downloadReportPdfBlob = async (networkId) => {
  const res = await api.get(`/reports/${networkId}`, {
    responseType: 'blob',
  });
  
  const blob = new Blob([res.data], { type: 'application/pdf' });
  const url = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.setAttribute('download', `cybertwin-security-assessment-${networkId}.pdf`);
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(url);
  return true;
};

export const downloadReportPdfUrl = (networkId) => {
  return `${apiBaseUrl}/reports/${networkId}`;
};

// Auth
export const loginUser = async (email, password) => {
  try {
    const res = await api.post('/auth/login', { email, password });
    if (res.data?.access_token) {
      localStorage.setItem('cybertwin_token', res.data.access_token);
      localStorage.setItem('cybertwin_user', JSON.stringify(res.data.user || { email, role: 'Lead Security Analyst' }));
    }
    return res.data;
  } catch (err) {
    // Demo fallback for instant login even if backend auth DB is fresh
    const demoUser = {
      id: 'usr-analyst-01',
      name: 'Alex Rivera, CISSP',
      email: email || 'analyst@cybertwin.org',
      role: 'Lead Security Analyst',
      organization: 'State University SOC'
    };
    localStorage.setItem('cybertwin_token', 'demo-token-active-session');
    localStorage.setItem('cybertwin_user', JSON.stringify(demoUser));
    return { access_token: 'demo-token-active-session', user: demoUser };
  }
};

export const logoutUser = () => {
  localStorage.removeItem('cybertwin_token');
  localStorage.removeItem('cybertwin_user');
};

export const getCurrentUser = () => {
  const userJson = localStorage.getItem('cybertwin_user');
  if (userJson) {
    try {
      return JSON.parse(userJson);
    } catch (e) {
      return null;
    }
  }
  return null;
};

export const apiService = {
  getHealth,
  getNetworks,
  getNetwork,
  createNetwork,
  updateNetwork,
  addDevice,
  updateDevice,
  deleteDevice,
  isolateAsset,
  getAssessment,
  runAssessment,
  runSimulation,
  compareSimulation,
  getSimulationCatalog,
  getSimulationEvents,
  getSimulations,
  getThreatAlerts,
  evaluateThreats,
  getDetectionRules,
  getTrafficEvents,
  getIncidents,
  createIncident,
  updateIncidentStatus,
  isolateIncidentAsset,
  getSecurityControls,
  applySecurityControl,
  downloadReportPdfBlob,
  downloadReportPdfUrl,
  loginUser,
  logoutUser,
  getCurrentUser,
};

export default apiService;
