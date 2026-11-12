import React, { useState, useEffect, useRef, useMemo } from 'react';
import { 
  Play, 
  Pause, 
  RotateCcw, 
  SkipBack, 
  SkipForward, 
  Square,
  ShieldAlert, 
  ShieldCheck, 
  Flame, 
  AlertTriangle, 
  Server, 
  Database, 
  Laptop, 
  Lock, 
  Unlock, 
  SlidersHorizontal, 
  Sparkles, 
  CheckCircle2, 
  XCircle, 
  Terminal,
  Zap,
  Info,
  ChevronDown,
  ChevronUp,
  Search,
  Filter,
  Activity,
  Radio,
  Layers,
  ArrowRight,
  ExternalLink,
  Cpu,
  History,
  FileCode,
  Gauge,
  BookOpen,
  Maximize2,
  Minimize2,
  HelpCircle,
  Eye,
  RefreshCw,
  Network,
  Ban,
  Key,
  Globe,
  Sliders,
  Shield,
  Crosshair,
  TrendingUp,
  Send,
  AlertCircle,
  ChevronRight,
  ChevronLeft
} from 'lucide-react';
import { 
  runSimulation, 
  compareSimulation, 
  applySecurityControl, 
  isolateAsset,
  createIncident,
  getSimulationEvents
} from '../services/api';

// 7 Core Scenarios + Lateral Movement
const SCENARIOS = [
  { 
    id: 'port_scanning', 
    name: '1. Port Scanning & Reconnaissance', 
    category: 'Reconnaissance',
    desc: 'Synthetic TCP SYN sweep probing target host ports, classifying open, closed, and filtered services.',
    mitre: 'T1046 - Network Service Discovery',
    source: 'student_pc_01',
    target: 'app_server_01',
    severity: 'medium',
    targetPort: 'Sweep (21-8080)',
    vulnerabilities: [
      { code: 'UNNECESSARY_SERVICE', text: 'Cleartext Telnet (port 23) and FTP (port 21) listening daemons left exposed', severity: 'medium' },
      { code: 'INFO_DISCLOSURE', text: 'Service banners reveal unpatched server daemon versions and OS fingerprint', severity: 'low' }
    ],
    stages: [
      { stage: 'Reconnaissance', desc: 'Attacker probes target host ports with TCP SYN packets to map reachable services.' },
      { stage: 'Port Identification', desc: 'Host daemon responses and firewall dispositions determine Open, Filtered, and Closed ports.' },
      { stage: 'Detection', desc: 'Network IDS identifies high-frequency connection attempts and flags port sweep anomaly.' },
      { stage: 'Security Assessment', desc: 'Exposure metric calculated based on count of unencrypted and high-risk exposed daemons.' },
      { stage: 'Remediation', desc: 'Disable legacy services and enforce strict perimeter firewall ingress ACLs.' }
    ]
  },
  { 
    id: 'repeated_login_failures', 
    name: '2. Credential Brute-Force & Lockout Audit', 
    category: 'Credential Access',
    desc: 'Sequence of synthetic authentication attempts testing account lockout thresholds and password entropy.',
    mitre: 'T1110 - Brute Force',
    source: 'student_pc_01',
    target: 'app_server_01',
    severity: 'high',
    targetPort: 'SSH (22) / HTTP (80)',
    vulnerabilities: [
      { code: 'WEAK_AUTH', text: 'Target account lockout disabled; allows unlimited dictionary authentication attempts', severity: 'critical' },
      { code: 'MISSING_MFA', text: 'Multi-factor authentication (MFA) not enforced on privileged user accounts', severity: 'medium' }
    ],
    stages: [
      { stage: 'Target Selection', desc: 'Adversary targets administrative service endpoint on internal application server.' },
      { stage: 'Credential Stuffing', desc: 'Sequential dictionary attack tests high-frequency password guesses against the account.' },
      { stage: 'Threshold Evaluation', desc: 'Authentication policy evaluates failed attempt count against lockout threshold (3 attempts).' },
      { stage: 'Account Disposition', desc: 'If lockout disabled: password matched and host breached. If enabled: account locked out.' },
      { stage: 'Remediation', desc: 'Enforce automatic account lockout, rate limiting, and hardware token MFA.' }
    ]
  },
  { 
    id: 'sqli_attempt', 
    name: '3. SQL Injection & Database Exfiltration', 
    category: 'Web App Security',
    desc: 'Evaluates web tier input validation against SQL tautologies to exfiltrate backend academic records.',
    mitre: 'T1190 - Exploit Public-Facing Application',
    source: 'student_pc_01',
    target: 'db_server_01',
    severity: 'critical',
    targetPort: 'HTTP (80) → DB (5432)',
    vulnerabilities: [
      { code: 'BROAD_DB_ACCESS', text: 'Perimeter firewall allows direct workstation traffic to database port 5432', severity: 'critical' },
      { code: 'WEAK_INPUT_VALIDATION', text: 'Web application search parameter concatenated directly into raw SQL string', severity: 'high' }
    ],
    stages: [
      { stage: 'Form Reconnaissance', desc: 'Attacker locates user-controlled query input parameter on Student Web Portal.' },
      { stage: 'Payload Injection', desc: 'Injects SQL tautology (" OR 1=1 --) to alter query execution logic.' },
      { stage: 'Query Forwarding', desc: 'Vulnerable web application sends tainted SQL query string directly to PostgreSQL backend.' },
      { stage: 'Data Exfiltration', desc: 'Backend returns unauthorized student table records (IDs, GPAs, names).' },
      { stage: 'Remediation', desc: 'Enforce parameterized prepared statements, deploy WAF rules, and isolate DB tier.' }
    ]
  },
  { 
    id: 'suspicious_traffic', 
    name: '4. Suspicious Network Traffic & Anomaly', 
    category: 'Traffic Analysis',
    desc: 'Generates anomalous connection bursts across non-standard port 4444 to test traffic threshold alerts.',
    mitre: 'T1071 - Application Layer Protocol',
    source: 'student_pc_01',
    target: 'app_server_01',
    severity: 'high',
    targetPort: 'TCP 4444 (Non-Standard)',
    vulnerabilities: [
      { code: 'POOR_SEGMENTATION', text: 'Perimeter firewall allows outbound high-port egress traffic without deep inspection', severity: 'high' }
    ],
    stages: [
      { stage: 'Baseline Measurement', desc: 'Traffic analyzer establishes normal workstation communication profile (15 pkts/sec).' },
      { stage: 'Anomaly Generation', desc: 'High-frequency burst of synthetic traffic generated across non-standard port 4444.' },
      { stage: 'Threshold Detection', desc: 'NetFlow monitoring engine triggers alarm when connection volume exceeds threshold by 16x.' },
      { stage: 'Traffic Classification', desc: 'Traffic classified as potential C2 beacon or unauthorized high-volume data exfiltration.' },
      { stage: 'Remediation', desc: 'Enforce strict egress filtering: allow only approved ports 80/443 and drop non-standard ports.' }
    ]
  },
  { 
    id: 'unauthorized_access', 
    name: '5. Unauthorized Privilege & RBAC Violation', 
    category: 'Privilege Escalation',
    desc: 'Simulates student guest persona attempting privileged administrative operations on internal servers.',
    mitre: 'T1078 - Valid Accounts',
    source: 'student_pc_01',
    target: 'app_server_01',
    severity: 'high',
    targetPort: 'HTTPS (8443)',
    vulnerabilities: [
      { code: 'WEAK_AUTH', text: 'Missing role-based permission checks on administrative endpoints', severity: 'critical' }
    ],
    stages: [
      { stage: 'Session Establishment', desc: 'Student Guest user authenticates and establishes TLS session with application server.' },
      { stage: 'Privilege Escalation Attempt', desc: 'User requests high-privilege administrative action (EXPORT_STUDENT_TRANSCRIPTS).' },
      { stage: 'RBAC Evaluation', desc: 'Authorization layer checks requested operation against user role permissions.' },
      { stage: 'Access Disposition', desc: 'If RBAC missing: access granted (Violation). If RBAC active: 403 Forbidden enforced.' },
      { stage: 'Remediation', desc: 'Implement principle of least privilege, strict RBAC authorization, and zero-trust tokens.' }
    ]
  },
  { 
    id: 'malware_behaviour', 
    name: '6. Malware Behavior & Endpoint Containment', 
    category: 'Endpoint Security',
    desc: 'Simulates endpoint attack chain (process creation, credential dump, C2 beaconing) and tests containment.',
    mitre: 'T1059 - Command and Scripting Interpreter',
    source: 'student_pc_01',
    target: 'db_server_01',
    severity: 'critical',
    targetPort: 'Host Process + C2 4444',
    vulnerabilities: [
      { code: 'WEAK_AUTH', text: 'Host process execution unmonitored; memory scraping and sub-process spawning permitted', severity: 'critical' }
    ],
    stages: [
      { stage: 'Initial Execution', desc: 'Malicious macro spawns hidden powershell.exe process on student workstation.' },
      { stage: 'Credential Scraping', desc: 'Malicious process attempts memory dump of lsass.exe to extract cached user tokens.' },
      { stage: 'Persistence Installation', desc: 'Installs scheduled startup task in HKCU Run registry hive.' },
      { stage: 'Outbound C2 Beaconing', desc: 'Attempts lateral connection across subnet to pivot into core database.' },
      { stage: 'Containment', desc: 'SOC executes immediate virtual endpoint network isolation to quarantine the host.' }
    ]
  },
  { 
    id: 'dos_behaviour', 
    name: '7. Denial-of-Service (DoS) Capacity Surge', 
    category: 'Availability',
    desc: 'Mathematical capacity consumption model testing server latency and saturation under SYN request floods.',
    mitre: 'T1498 - Network Denial of Service',
    source: 'student_pc_01',
    target: 'app_server_01',
    severity: 'medium',
    targetPort: 'HTTP (80)',
    vulnerabilities: [
      { code: 'NO_RATE_LIMITING', text: 'Gateway firewall lacks connection rate limiting per source IP address', severity: 'medium' }
    ],
    stages: [
      { stage: 'Baseline Load', desc: 'Target server processes normal traffic (50 req/sec) with low CPU utilization (12%).' },
      { stage: 'Volume Escalation', desc: 'Synthetic SYN flood escalates request rate through 500 → 2,500 → 6,500 req/sec.' },
      { stage: 'Resource Saturation', desc: 'Server connection pool fills, CPU surges to 100%, and latency spikes past 3,000ms.' },
      { stage: 'Service Outage', desc: 'Server drops legitimate user requests and returns 503 Service Unavailable.' },
      { stage: 'Remediation', desc: 'Deploy SYN cookies, upstream connection throttling, and per-IP rate limiting (100 req/s).' }
    ]
  },
  { 
    id: 'lateral_movement', 
    name: '8. Lateral Movement: Pivot to Core Database', 
    category: 'Lateral Movement',
    desc: 'Multi-hop graph traversal from unsegmented student workstation across firewalls to student records database.',
    mitre: 'T1021 - Remote Services',
    source: 'student_pc_01',
    target: 'db_server_01',
    severity: 'critical',
    targetPort: 'Multi-Hop (5432)',
    vulnerabilities: [
      { code: 'BROAD_DB_ACCESS', text: 'Wildcard firewall rule allows 0.0.0.0/0 to PostgreSQL port 5432', severity: 'critical' },
      { code: 'POOR_SEGMENTATION', text: 'Student zone shares flat routing into internal server subnets', severity: 'high' }
    ],
    stages: [
      { stage: 'Initial Foothold', desc: 'Workstation compromised in unsegmented student computer lab.' },
      { stage: 'Internal Reconnaissance', desc: 'Scanner discovers internal database IP at 10.0.3.10.' },
      { stage: 'Firewall Ingress Check', desc: 'Perimeter firewall evaluates broad rule rule_misconfig_broad_db.' },
      { stage: 'Pivot Execution', desc: 'Workstation establishes direct PostgreSQL socket connection across subnets.' },
      { stage: 'Remediation', desc: 'Revoke wildcard DB rule and enforce zero-trust microsegmentation.' }
    ]
  }
];

// Spatial node coordinates & zone layout for the cyber range canvas
const SPATIAL_TOPOLOGY = {
  zones: [
    {
      id: 'zone_1',
      name: 'ZONE 1 • LAB SUBNET',
      subtext: 'Untrusted Workstations',
      polygon: '40,130 250,130 295,280 250,430 40,430 5,280',
      labelPos: { x: 140, y: 155 }
    },
    {
      id: 'zone_2',
      name: 'ZONE 2 • PERIMETER DMZ',
      subtext: 'Gateway Firewall & Ingress',
      polygon: '335,110 515,110 560,280 515,450 335,450 290,280',
      labelPos: { x: 425, y: 135 }
    },
    {
      id: 'zone_3',
      name: 'ZONE 3 • SERVER FARM',
      subtext: 'Application Tier & Services',
      polygon: '600,110 780,110 825,280 780,450 600,450 555,280',
      labelPos: { x: 690, y: 135 }
    },
    {
      id: 'zone_4',
      name: 'ZONE 4 • SECURE DATA',
      subtext: 'PostgreSQL Core Tier',
      polygon: '855,130 990,130 1015,280 990,430 855,430 830,280',
      labelPos: { x: 925, y: 155 }
    }
  ],
  nodes: {
    student_pc_01: { x: 105, y: 280, icon: 'laptop', label: 'Student PC', ip: '10.0.1.50', zone: 'Zone 1' },
    faculty_pc_01: { x: 205, y: 280, icon: 'laptop', label: 'Faculty PC', ip: '10.0.1.60', zone: 'Zone 1' },
    gw_firewall_01: { x: 425, y: 210, icon: 'shield', label: 'Gateway Firewall', ip: '10.0.0.1', zone: 'Zone 2' },
    web_portal_01: { x: 425, y: 355, icon: 'globe', label: 'Student Web Portal', ip: '10.0.2.20', zone: 'Zone 2' },
    app_server_01: { x: 690, y: 280, icon: 'server', label: 'University App Server', ip: '10.0.2.10', zone: 'Zone 3' },
    db_server_01: { x: 925, y: 280, icon: 'database', label: 'Records Database', ip: '10.0.3.10', zone: 'Zone 4' }
  },
  edges: [
    { from: 'student_pc_01', to: 'gw_firewall_01', d: 'M 105 280 C 240 280, 300 210, 425 210', hop: 1 },
    { from: 'faculty_pc_01', to: 'gw_firewall_01', d: 'M 205 280 C 290 280, 340 210, 425 210', hop: 1 },
    { from: 'gw_firewall_01', to: 'web_portal_01', d: 'M 425 210 L 425 355', hop: 2 },
    { from: 'gw_firewall_01', to: 'app_server_01', d: 'M 425 210 C 530 210, 580 280, 690 280', hop: 2 },
    { from: 'web_portal_01', to: 'app_server_01', d: 'M 425 355 C 530 355, 580 280, 690 280', hop: 2 },
    { from: 'app_server_01', to: 'db_server_01', d: 'M 690 280 L 925 280', hop: 3 },
    { from: 'gw_firewall_01', to: 'db_server_01', d: 'M 425 210 C 580 120, 780 120, 925 280', hop: 2, isBroadRule: true }
  ]
};

export default function SimulatorPage({ network, onSimulationFinished }) {
  // Use actual database network devices, with realistic fallback
  const devices = useMemo(() => {
    return network?.devices || network?.topology?.devices || [
      { id: 'student_pc_01', name: 'Student Lab Workstation', type: 'workstation', ip: '10.0.1.50', zone: 'Zone 1: Lab Subnet', security_status: 'normal', criticality: 'low', auth_strength: 'weak', lockout_enabled: false, services: [] },
      { id: 'faculty_pc_01', name: 'Faculty Office PC', type: 'workstation', ip: '10.0.1.60', zone: 'Zone 1: Lab Subnet', security_status: 'normal', criticality: 'medium', auth_strength: 'medium', lockout_enabled: true, services: [] },
      { id: 'gw_firewall_01', name: 'Campus Gateway Firewall', type: 'firewall', ip: '10.0.0.1', zone: 'Zone 2: Perimeter DMZ', security_status: 'normal', criticality: 'high', auth_strength: 'strong', lockout_enabled: true, services: [{ name: 'Firewall-ACL', port: 8443, enabled: true }] },
      { id: 'web_portal_01', name: 'Student Web Portal', type: 'server', ip: '10.0.2.20', zone: 'Zone 2: Perimeter DMZ', security_status: 'normal', criticality: 'medium', auth_strength: 'weak', lockout_enabled: false, services: [{ name: 'HTTP', port: 80, enabled: true }, { name: 'HTTPS', port: 443, enabled: true }] },
      { id: 'app_server_01', name: 'University App Server', type: 'server', ip: '10.0.2.10', zone: 'Zone 3: Server Farm', security_status: 'normal', criticality: 'high', auth_strength: 'weak', lockout_enabled: false, services: [{ name: 'Telnet', port: 23, enabled: true }, { name: 'SSH', port: 22, enabled: true }, { name: 'HTTP', port: 80, enabled: true }] },
      { id: 'db_server_01', name: 'Student Records Database', type: 'database', ip: '10.0.3.10', zone: 'Zone 4: Secure Data Tier', security_status: 'normal', criticality: 'critical', auth_strength: 'strong', lockout_enabled: true, services: [{ name: 'PostgreSQL', port: 5432, enabled: true }] }
    ];
  }, [network]);

  // Main UI State
  const [selectedScenarioId, setSelectedScenarioId] = useState('port_scanning');
  const [sourceNode, setSourceNode] = useState('student_pc_01');
  const [targetNode, setTargetNode] = useState('app_server_01');
  const [seed, setSeed] = useState(42);
  const [speed, setSpeed] = useState(1); // 0.5x, 1x, 2x
  const [isManualStepMode, setIsManualStepMode] = useState(false);
  const [isFullScreen, setIsFullScreen] = useState(false);
  const [isRightPanelOpen, setIsRightPanelOpen] = useState(true);
  const [activeViewTab, setActiveViewTab] = useState('studio'); // 'studio' | 'learning' | 'history'

  // Interactive Scenario Parameters
  const [selectedDemoAccount, setSelectedDemoAccount] = useState('admin');
  const [sqliInputPayload, setSqliInputPayload] = useState("' OR '1'='1 --");
  const [inspectedPort, setInspectedPort] = useState(null);
  const [inspectedAsset, setInspectedAsset] = useState(null);
  const [whyDidThisHappenModal, setWhyDidThisHappenModal] = useState(false);
  const [activeBeforeAfterView, setActiveBeforeAfterView] = useState('current'); // 'current' | 'before' | 'after'

  // Explanation Mode: Beginner vs Technical
  const [explanationMode, setExplanationMode] = useState('beginner'); // 'beginner' | 'technical'

  // Simulation Lifecycle & Playback
  const [executionState, setExecutionState] = useState('IDLE'); // 'IDLE' | 'RUNNING' | 'PAUSED' | 'COMPLETED' | 'STOPPED'
  const [simResult, setSimResult] = useState(null);
  const [activeStepIndex, setActiveStepIndex] = useState(-1);
  const [terminalLogs, setTerminalLogs] = useState([]);
  const [simulationHistory, setSimulationHistory] = useState([]);

  // Live Security Event Monitor
  const [isBottomPanelExpanded, setIsBottomPanelExpanded] = useState(true);
  const [activeEventFilter, setActiveEventFilter] = useState('ALL');
  const [highlightedHop, setHighlightedHop] = useState(null);

  // Before vs After Comparison Modal
  const [compareModalOpen, setCompareModalOpen] = useState(false);
  const [compareData, setCompareData] = useState(null);
  const [isComparing, setIsComparing] = useState(false);
  const [remediationMsg, setRemediationMsg] = useState('');
  const [isRemediating, setIsRemediating] = useState(false);

  const timerRef = useRef(null);
  const currentScenario = useMemo(() => {
    return SCENARIOS.find(s => s.id === selectedScenarioId) || SCENARIOS[0];
  }, [selectedScenarioId]);

  // Handle Scenario Selection
  const handleSelectScenario = (scId) => {
    setSelectedScenarioId(scId);
    const sc = SCENARIOS.find(s => s.id === scId);
    if (sc) {
      if (devices.some(d => d.id === sc.source)) setSourceNode(sc.source);
      if (devices.some(d => d.id === sc.target)) setTargetNode(sc.target);
    }
    handleReset();
  };

  // Run Simulation Execution
  const handleStartSimulation = async (customScenario = selectedScenarioId) => {
    setExecutionState('RUNNING');
    setActiveStepIndex(-1);
    setTerminalLogs([]);
    setRemediationMsg('');
    setHighlightedHop(null);

    try {
      const payload = {
        network_id: network?.id || 'university-sample-01',
        scenario: customScenario,
        source_device_id: sourceNode,
        target_device_id: targetNode,
        parameters: {
          attempts: 5,
          target_account: selectedDemoAccount,
          sql_payload: sqliInputPayload,
          control_type: 'none'
        },
        seed: Number(seed)
      };

      const res = await runSimulation(payload);
      setSimResult(res.data);
      setActiveStepIndex(0);

      setSimulationHistory(prev => [
        {
          id: res.data.id || `sim-${Date.now()}`,
          scenario: currentScenario.name,
          scenario_id: customScenario,
          source: sourceNode,
          target: targetNode,
          timestamp: new Date().toLocaleTimeString(),
          target_compromised: res.data.target_compromised,
          risk_level: res.data.risk_level,
          steps_count: res.data.steps?.length || 0,
          summary: res.data.summary
        },
        ...prev.slice(0, 9)
      ]);

      if (onSimulationFinished) {
        onSimulationFinished();
      }
    } catch (err) {
      console.error('Simulation execution failed:', err);
      setExecutionState('IDLE');
      setTerminalLogs(prev => [
        `[${new Date().toLocaleTimeString()}] ›[ERROR] Execution failed: ${err.response?.data?.detail || err.message}`
      ]);
    }
  };

  // Automated Playback Timer
  useEffect(() => {
    if (executionState !== 'RUNNING' || isManualStepMode) {
      if (timerRef.current) clearInterval(timerRef.current);
      return;
    }

    if (!simResult || !simResult.steps || simResult.steps.length === 0) return;

    const baseInterval = 1400;
    const intervalTime = Math.max(300, baseInterval / speed);

    timerRef.current = setInterval(() => {
      setActiveStepIndex(prev => {
        const next = prev + 1;
        if (next >= simResult.steps.length) {
          clearInterval(timerRef.current);
          setExecutionState('COMPLETED');
          return prev;
        }
        return next;
      });
    }, intervalTime);

    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [simResult, executionState, speed, isManualStepMode]);

  // Log active step into terminal when active index changes
  useEffect(() => {
    if (!simResult || !simResult.steps || activeStepIndex < 0 || activeStepIndex >= simResult.steps.length) return;

    const st = simResult.steps[activeStepIndex];
    const outcomeStr = st.allowed ? '✓ PERMITTED' : '✗ INTERCEPTED & BLOCKED';
    const logLine = `[${new Date().toLocaleTimeString()}] [Step ${st.step}] ${st.stage || 'Transit'}: ${st.from} → ${st.to} | Svc: ${st.service || 'ANY'} (${st.port || '*'}) | Verdict: ${outcomeStr} | Rule: ${st.rule_or_reason}`;

    setTerminalLogs(prev => {
      if (prev.includes(logLine)) return prev;
      return [...prev, logLine];
    });
  }, [activeStepIndex, simResult]);

  // Playback handlers
  const handlePause = () => {
    if (timerRef.current) clearInterval(timerRef.current);
    setExecutionState('PAUSED');
  };

  const handleResume = () => {
    setExecutionState('RUNNING');
  };

  const handleStop = () => {
    if (timerRef.current) clearInterval(timerRef.current);
    setExecutionState('STOPPED');
  };

  const handleReset = () => {
    if (timerRef.current) clearInterval(timerRef.current);
    setExecutionState('IDLE');
    setActiveStepIndex(-1);
    setSimResult(null);
    setHighlightedHop(null);
    setTerminalLogs([
      `[${new Date().toLocaleTimeString()}] [CYBER_RANGE] Environment restored to baseline virtual model.`
    ]);
  };

  const handleReplay = () => {
    if (!simResult) {
      handleStartSimulation();
      return;
    }
    setActiveStepIndex(0);
    setExecutionState('RUNNING');
  };

  const handleStepForward = () => {
    if (!simResult || !simResult.steps) return;
    setActiveStepIndex(prev => Math.min(simResult.steps.length - 1, prev + 1));
  };

  const handleStepBack = () => {
    if (!simResult || !simResult.steps) return;
    setActiveStepIndex(prev => Math.max(0, prev - 1));
  };

  // Run Before vs After Experiment
  const handleRunComparison = async () => {
    setIsComparing(true);
    setCompareData(null);
    try {
      const res = await compareSimulation({
        network_id: network?.id || 'university-sample-01',
        scenario: selectedScenarioId,
        source_device_id: sourceNode,
        target_device_id: targetNode,
        parameters: { control_type: 'restrict_db_access' },
        seed: Number(seed)
      });
      setCompareData(res.data);
      setCompareModalOpen(true);
    } catch (err) {
      console.error('Comparison experiment failed:', err);
    } finally {
      setIsComparing(false);
    }
  };

  // Apply Defense
  const handleApplyDefense = async (controlType) => {
    setIsRemediating(true);
    setRemediationMsg('');
    try {
      await applySecurityControl({
        network_id: network?.id || 'university-sample-01',
        control_type: controlType,
        target_asset_id: targetNode
      });
      setRemediationMsg(`Security control deployed: "${controlType}". Re-running simulation to verify mitigation...`);
      await handleStartSimulation(selectedScenarioId);
    } catch (err) {
      console.error('Remediation error:', err);
    } finally {
      setIsRemediating(false);
    }
  };

  // Quick Asset Isolation
  const handleToggleIsolation = async (deviceId, currentStatus) => {
    try {
      const shouldIsolate = currentStatus !== 'isolated';
      await isolateAsset(network?.id || 'university-sample-01', deviceId, shouldIsolate);
      setRemediationMsg(`Virtual asset ${deviceId} ${shouldIsolate ? 'ISOLATED from network communication' : 'RESTORED to normal state'}.`);
      if (onSimulationFinished) onSimulationFinished();
      handleStartSimulation();
    } catch (err) {
      console.error('Asset isolation error:', err);
    }
  };

  // Active step details
  const currentStep = useMemo(() => {
    if (!simResult || !simResult.steps || activeStepIndex < 0 || activeStepIndex >= simResult.steps.length) return null;
    return simResult.steps[activeStepIndex];
  }, [simResult, activeStepIndex]);

  const isTargetCompromised = simResult?.target_compromised && activeStepIndex === (simResult?.steps?.length || 1) - 1;
  const isTargetProtected = simResult && !simResult.target_compromised && activeStepIndex === (simResult?.steps?.length || 1) - 1;

  // Active edge calculation based on current step
  const activeEdge = useMemo(() => {
    if (!currentStep) return null;
    return SPATIAL_TOPOLOGY.edges.find(e => 
      (e.from === currentStep.from && e.to === currentStep.to) ||
      (e.from === currentStep.to && e.to === currentStep.from) ||
      (currentStep.from === 'student_pc_01' && currentStep.to === 'app_server_01' && e.from === 'student_pc_01' && e.to === 'gw_firewall_01')
    ) || SPATIAL_TOPOLOGY.edges[0];
  }, [currentStep]);

  // Node status resolver
  const getNodeVisualState = (nodeId) => {
    if (!simResult || activeStepIndex < 0) {
      return { border: '#1E3553', glow: 'none', fill: '#101B2B', text: '#91A2B8', status: 'INACTIVE' };
    }

    if (nodeId === sourceNode) {
      return { border: '#FF5265', glow: '0 0 16px rgba(255,82,101,0.5)', fill: '#1F1524', text: '#FF5265', status: 'ATTACKER' };
    }

    if (nodeId === targetNode) {
      if (isTargetCompromised) {
        return { border: '#FF5265', glow: '0 0 24px rgba(255,82,101,0.8)', fill: '#2A1420', text: '#FF5265', status: 'BREACHED' };
      }
      if (isTargetProtected) {
        return { border: '#39D69B', glow: '0 0 24px rgba(57,214,155,0.8)', fill: '#102B23', text: '#39D69B', status: 'DEFENDED' };
      }
      return { border: '#F5AE48', glow: '0 0 12px rgba(245,174,72,0.4)', fill: '#22201D', text: '#F5AE48', status: 'TARGET' };
    }

    if (nodeId === 'gw_firewall_01' && activeStepIndex >= 1) {
      if (!simResult.target_compromised) {
        return { border: '#39D69B', glow: '0 0 20px rgba(57,214,155,0.7)', fill: '#102B23', text: '#39D69B', status: 'INTERCEPTED' };
      }
      return { border: '#F5AE48', glow: '0 0 14px rgba(245,174,72,0.5)', fill: '#22201D', text: '#F5AE48', status: 'TRAVERSED' };
    }

    if (currentStep && (currentStep.from === nodeId || currentStep.to === nodeId)) {
      return { border: '#00E5FF', glow: '0 0 14px rgba(0,229,255,0.6)', fill: '#102B3B', text: '#00E5FF', status: 'ACTIVE' };
    }

    return { border: '#1E3553', glow: 'none', fill: '#101B2B', text: '#91A2B8', status: 'STANDBY' };
  };

  // Node Icon Resolver
  const renderNodeIcon = (iconType, color) => {
    switch (iconType) {
      case 'laptop': return <Laptop className="h-5 w-5" style={{ color }} />;
      case 'shield': return <Shield className="h-5 w-5" style={{ color }} />;
      case 'globe': return <Globe className="h-5 w-5" style={{ color }} />;
      case 'server': return <Server className="h-5 w-5" style={{ color }} />;
      case 'database': return <Database className="h-5 w-5" style={{ color }} />;
      default: return <Server className="h-5 w-5" style={{ color }} />;
    }
  };

  // Explanation text generator
  const currentStageExplanation = useMemo(() => {
    if (!currentStep) {
      return {
        title: currentScenario.stages[0]?.stage || 'Ready to Simulate',
        what: 'The simulation environment is armed and waiting for execution.',
        why: 'Select parameters and click "Execute Attack Simulation" to observe packet progression.',
        system: `${sourceNode} (Origin) → ${targetNode} (Target)`,
        vulnerability: currentScenario.vulnerabilities[0]?.text || 'Awaiting evaluation',
        next: 'Packet transmission along network edge.',
        prevention: 'Configure security rules and authentication policies.'
      };
    }

    const stepStage = currentStep.stage || 'Transit';
    const isAllowed = currentStep.allowed;

    if (explanationMode === 'beginner') {
      return {
        title: `Stage: ${stepStage}`,
        what: isAllowed 
          ? `The virtual network permitted simulated traffic from ${currentStep.from} to ${currentStep.to}.` 
          : `The security perimeter successfully blocked the simulated traffic between ${currentStep.from} and ${currentStep.to}.`,
        why: isAllowed
          ? `Like an unlocked office door, the network has no rule telling it to stop packets for port ${currentStep.port || 'Any'}.`
          : `Like a security guard checking ID cards, the firewall inspected the packet and refused entry based on policy.`,
        system: `Involved: ${currentStep.from} → ${currentStep.to}`,
        vulnerability: isAllowed 
          ? `Permissive rule: "${currentStep.rule_or_reason}"` 
          : 'None triggered on this hop (Defense enforced)',
        next: isAllowed 
          ? 'The attacker advances closer to core backend systems.' 
          : 'The attack stops here. The adversary cannot reach further assets.',
        prevention: 'Deploy strict firewall boundary ACLs, enforce least privilege, and enable rate limiting.'
      };
    } else {
      return {
        title: `MITRE ${currentScenario.mitre} [${stepStage}]`,
        what: `Evaluating hop: ${currentStep.from} → ${currentStep.to} on service "${currentStep.service}" (Port ${currentStep.port || '*'}). Disposition: ${isAllowed ? 'PERMITTED' : 'DROPPED'}.`,
        why: `Rule evaluation result: "${currentStep.rule_or_reason}". Protocol state matched ingress/egress security policy.`,
        system: `Socket: ${currentStep.from} → ${currentStep.to}:${currentStep.port || '*'} (${currentStep.service})`,
        vulnerability: `Evidence: ${currentStep.evidence || 'Standard boundary check'}`,
        next: isAllowed ? 'Graph reachability traversal to subsequent hop.' : 'TCP RST or ICMP Admin Prohibited generated; traversal terminated.',
        prevention: 'Stateful firewall packet inspection, 802.1Q VLAN segmentation, and TLS 1.3 mutual authentication.'
      };
    }
  }, [currentStep, explanationMode, currentScenario, sourceNode, targetNode]);

  return (
    <div className={`space-y-4 ${isFullScreen ? 'fixed inset-0 z-50 bg-[#080E19] p-4 overflow-y-auto' : ''}`}>
      {/* Top Cyber Range Command Header */}
      <div className="bg-[#101B2B] text-[#E7EDF7] px-5 py-3 rounded-2xl border border-[#1E3553] flex flex-col md:flex-row items-start md:items-center justify-between gap-3 shadow-lg">
        <div className="flex items-center space-x-3">
          <div className="h-9 w-9 rounded-xl bg-[#111F32] border border-[#248DD8]/40 flex items-center justify-center text-[#248DD8] shadow-[0_0_12px_rgba(36,141,216,0.3)]">
            <Radio className="h-5 w-5 animate-pulse text-[#FF5265]" />
          </div>
          <div>
            <div className="flex items-center space-x-2 text-[10px] font-mono text-[#248DD8]">
              <span className="font-bold tracking-wider uppercase">CYBERTWIN COMMAND RANGE</span>
              <span>•</span>
              <span className="text-[#39D69B]">VIRTUAL SPATIAL DIGITAL TWIN</span>
            </div>
            <h1 className="text-lg font-bold tracking-tight text-[#E7EDF7] flex items-center space-x-2">
              <span>{currentScenario.name}</span>
            </h1>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Explanation Mode Switcher */}
          <div className="flex bg-[#080E19] p-0.5 rounded-lg border border-[#1E3553] text-[11px] font-semibold">
            <button
              onClick={() => setExplanationMode('beginner')}
              className={`px-2.5 py-1 rounded transition-colors ${
                explanationMode === 'beginner' ? 'bg-[#248DD8] text-white' : 'text-[#91A2B8] hover:text-[#E7EDF7]'
              }`}
            >
              Beginner View
            </button>
            <button
              onClick={() => setExplanationMode('technical')}
              className={`px-2.5 py-1 rounded transition-colors ${
                explanationMode === 'technical' ? 'bg-[#248DD8] text-white' : 'text-[#91A2B8] hover:text-[#E7EDF7]'
              }`}
            >
              Technical View
            </button>
          </div>

          {/* Repeatable Before vs After Experiment Button */}
          <button
            onClick={handleRunComparison}
            disabled={isComparing}
            className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded-lg bg-gradient-to-r from-[#248DD8] to-[#1F74B2] hover:from-[#1F74B2] hover:to-[#175C8F] text-white text-xs font-semibold shadow-[0_0_12px_rgba(36,141,216,0.4)] transition-all"
          >
            <Sparkles className={`h-3.5 w-3.5 ${isComparing ? 'animate-spin' : ''}`} />
            <span>{isComparing ? 'Comparing...' : 'Before vs After'}</span>
          </button>

          {/* Full Screen Toggle */}
          <button
            onClick={() => setIsFullScreen(!isFullScreen)}
            className="p-1.5 rounded-lg bg-[#080E19] hover:bg-[#111F32] text-[#91A2B8] hover:text-[#E7EDF7] border border-[#1E3553] transition-colors"
            title={isFullScreen ? 'Exit Full Screen' : 'Full Screen Cyber Range'}
          >
            {isFullScreen ? <Minimize2 className="h-4 w-4" /> : <Maximize2 className="h-4 w-4" />}
          </button>

          {/* Toggle Right Inspector Panel */}
          <button
            onClick={() => setIsRightPanelOpen(!isRightPanelOpen)}
            className="p-1.5 rounded-lg bg-[#080E19] hover:bg-[#111F32] text-[#91A2B8] hover:text-[#E7EDF7] border border-[#1E3553] transition-colors"
            title={isRightPanelOpen ? 'Collapse Inspector Panel' : 'Expand Inspector Panel'}
          >
            {isRightPanelOpen ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
          </button>
        </div>
      </div>

      {/* Main 3-Section Command Centre Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* LEFT PANEL: Scenario Selector & Execution Config (2 or 3 cols) */}
        <div className="lg:col-span-3 space-y-3">
          <div className="bg-[#101B2B] rounded-2xl border border-[#1E3553] p-4 text-[#E7EDF7] space-y-3 shadow-md">
            <div className="flex items-center justify-between border-b border-[#1E3553] pb-2">
              <span className="text-xs font-bold uppercase tracking-wider text-[#91A2B8]">Attack Scenarios</span>
              <span className="text-[10px] font-mono text-[#248DD8]">8 Vectors</span>
            </div>

            {/* Compact Scenario List */}
            <div className="space-y-1.5 max-h-[290px] overflow-y-auto pr-1">
              {SCENARIOS.map(sc => {
                const isSelected = selectedScenarioId === sc.id;
                return (
                  <button
                    key={sc.id}
                    onClick={() => handleSelectScenario(sc.id)}
                    className={`w-full text-left p-2 rounded-xl border text-xs transition-all ${
                      isSelected
                        ? 'border-[#248DD8] bg-[#111F32] shadow-[0_0_10px_rgba(36,141,216,0.3)] ring-1 ring-[#248DD8]/50'
                        : 'border-[#1E3553] bg-[#080E19]/60 hover:bg-[#111F32]/80 text-[#91A2B8]'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-0.5">
                      <span className={`font-bold truncate ${isSelected ? 'text-[#E7EDF7]' : 'text-[#91A2B8]'}`}>
                        {sc.name}
                      </span>
                      <span className={`text-[9px] font-bold uppercase px-1 rounded ${
                        sc.severity === 'critical' ? 'bg-[#FF5265]/20 text-[#FF5265]' : 'bg-[#F5AE48]/20 text-[#F5AE48]'
                      }`}>
                        {sc.severity}
                      </span>
                    </div>
                    <div className="text-[10px] text-[#248DD8] font-mono truncate">{sc.mitre}</div>
                  </button>
                );
              })}
            </div>

            {/* Target Endpoints & Trigger */}
            <div className="pt-2 border-t border-[#1E3553] space-y-2.5 text-xs">
              <div>
                <label className="block text-[10px] font-bold text-[#91A2B8] uppercase mb-1">
                  Source Attacker Node
                </label>
                <select
                  value={sourceNode}
                  onChange={(e) => setSourceNode(e.target.value)}
                  className="w-full bg-[#080E19] border border-[#1E3553] text-[#E7EDF7] text-xs rounded-lg p-1.5 focus:border-[#248DD8] focus:outline-hidden"
                >
                  {devices.map(d => (
                    <option key={d.id} value={d.id}>{d.name} ({d.ip})</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-[10px] font-bold text-[#91A2B8] uppercase mb-1">
                  Target Asset
                </label>
                <select
                  value={targetNode}
                  onChange={(e) => setTargetNode(e.target.value)}
                  className="w-full bg-[#080E19] border border-[#1E3553] text-[#E7EDF7] text-xs rounded-lg p-1.5 focus:border-[#248DD8] focus:outline-hidden"
                >
                  {devices.map(d => (
                    <option key={d.id} value={d.id}>{d.name} ({d.ip})</option>
                  ))}
                </select>
              </div>

              {/* Specific Tuners for Scenarios */}
              {selectedScenarioId === 'sqli_attempt' && (
                <div>
                  <label className="block text-[10px] font-bold text-[#91A2B8] uppercase mb-1">
                    SQLi Test Pattern
                  </label>
                  <select
                    value={sqliInputPayload}
                    onChange={(e) => setSqliInputPayload(e.target.value)}
                    className="w-full bg-[#080E19] border border-[#1E3553] text-[#E7EDF7] text-[11px] font-mono rounded-lg p-1.5"
                  >
                    <option value="' OR '1'='1 --">' OR '1'='1 -- (Auth Bypass)</option>
                    <option value="' UNION SELECT id, name, gpa FROM students --">' UNION SELECT (Schema Dump)</option>
                    <option value="admin'--">admin'-- (Admin Hijack)</option>
                  </select>
                </div>
              )}

              {selectedScenarioId === 'repeated_login_failures' && (
                <div>
                  <label className="block text-[10px] font-bold text-[#91A2B8] uppercase mb-1">
                    Target Account
                  </label>
                  <select
                    value={selectedDemoAccount}
                    onChange={(e) => setSelectedDemoAccount(e.target.value)}
                    className="w-full bg-[#080E19] border border-[#1E3553] text-[#E7EDF7] text-xs rounded-lg p-1.5"
                  >
                    <option value="admin">admin (Administrator)</option>
                    <option value="operator">operator (Staff)</option>
                    <option value="student_dev">student_dev (Lab User)</option>
                  </select>
                </div>
              )}

              <button
                onClick={() => handleStartSimulation()}
                disabled={executionState === 'RUNNING'}
                className="w-full flex items-center justify-center space-x-2 py-2.5 px-3 rounded-xl bg-gradient-to-r from-[#FF5265] to-[#E03B4E] hover:from-[#E03B4E] hover:to-[#C2293C] text-white text-xs font-bold uppercase tracking-wider shadow-[0_0_16px_rgba(255,82,101,0.5)] transition-all disabled:opacity-50"
              >
                <Flame className={`h-4 w-4 ${executionState === 'RUNNING' ? 'animate-spin' : ''}`} />
                <span>{executionState === 'RUNNING' ? 'Simulating...' : 'Execute Attack'}</span>
              </button>
            </div>
          </div>
        </div>

        {/* CENTER MAIN WORKSPACE: Spatial Hexagonal Network Topology (~65-75% width) */}
        <div className={isRightPanelOpen ? 'lg:col-span-6 space-y-3' : 'lg:col-span-9 space-y-3'}>
          <div className="bg-[#101B2B] rounded-2xl border border-[#1E3553] p-4 text-[#E7EDF7] shadow-xl space-y-3 relative overflow-hidden">
            {/* Top Toolbar overlay on canvas */}
            <div className="flex items-center justify-between border-b border-[#1E3553] pb-2.5">
              <div className="flex items-center space-x-2">
                <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                  executionState === 'RUNNING' ? 'bg-[#F5AE48]/20 text-[#F5AE48] border border-[#F5AE48]/40 animate-pulse' :
                  executionState === 'COMPLETED' ? 'bg-[#39D69B]/20 text-[#39D69B] border border-[#39D69B]/40' :
                  executionState === 'PAUSED' ? 'bg-[#248DD8]/20 text-[#248DD8] border border-[#248DD8]/40' :
                  'bg-[#1E3553] text-[#91A2B8]'
                }`}>
                  {executionState}
                </span>
                <span className="text-[11px] font-mono text-[#91A2B8]">
                  Step {activeStepIndex >= 0 ? activeStepIndex + 1 : 0} of {simResult?.steps?.length || 0}
                </span>
              </div>

              {/* Simulation Stepper Controls */}
              <div className="flex items-center space-x-1.5">
                <div className="flex items-center space-x-1 bg-[#080E19] border border-[#1E3553] rounded-lg p-0.5">
                  <button
                    onClick={handleStepBack}
                    disabled={!simResult || activeStepIndex <= 0}
                    className="p-1 rounded text-[#91A2B8] hover:text-white disabled:opacity-30"
                    title="Previous Step"
                  >
                    <SkipBack className="h-3.5 w-3.5" />
                  </button>

                  {executionState === 'RUNNING' ? (
                    <button
                      onClick={handlePause}
                      className="px-2 py-0.5 rounded bg-[#F5AE48] text-[#080E19] font-bold text-[11px] flex items-center space-x-1"
                    >
                      <Pause className="h-3 w-3" />
                      <span>Pause</span>
                    </button>
                  ) : (
                    <button
                      onClick={simResult ? handleResume : () => handleStartSimulation()}
                      className="px-2 py-0.5 rounded bg-[#248DD8] text-white font-bold text-[11px] flex items-center space-x-1"
                    >
                      <Play className="h-3 w-3" />
                      <span>{activeStepIndex >= 0 ? 'Resume' : 'Play'}</span>
                    </button>
                  )}

                  <button
                    onClick={handleStepForward}
                    disabled={!simResult || activeStepIndex >= (simResult?.steps?.length || 1) - 1}
                    className="p-1 rounded text-[#91A2B8] hover:text-white disabled:opacity-30"
                    title="Next Step"
                  >
                    <SkipForward className="h-3.5 w-3.5" />
                  </button>

                  <button
                    onClick={handleStop}
                    disabled={executionState === 'IDLE'}
                    className="p-1 rounded text-[#FF5265] hover:bg-[#FF5265]/10 disabled:opacity-30"
                    title="Stop"
                  >
                    <Square className="h-3.5 w-3.5" />
                  </button>

                  <button
                    onClick={handleReset}
                    className="p-1 rounded text-[#91A2B8] hover:text-white"
                    title="Reset"
                  >
                    <RotateCcw className="h-3.5 w-3.5" />
                  </button>
                </div>

                {/* Speed Multiplier */}
                <div className="flex bg-[#080E19] border border-[#1E3553] rounded-lg overflow-hidden text-[10px] font-mono font-bold">
                  {[0.5, 1, 2].map(sp => (
                    <button
                      key={sp}
                      onClick={() => setSpeed(sp)}
                      className={`px-1.5 py-0.5 transition-colors ${speed === sp ? 'bg-[#248DD8] text-white' : 'text-[#91A2B8] hover:text-white'}`}
                    >
                      {sp}x
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* THE SPATIAL NETWORK TOPOLOGY CANVAS (SVG Hexagonal Cyber Range) */}
            <div className="relative w-full h-[430px] bg-[#080E19] rounded-xl border border-[#1E3553] overflow-hidden select-none shadow-inner">
              {/* Subtle background tech grid */}
              <svg className="absolute inset-0 w-full h-full pointer-events-none" xmlns="http://www.w3.org/2000/svg">
                <defs>
                  <pattern id="cyberGrid" width="24" height="24" patternUnits="userSpaceOnUse">
                    <path d="M 24 0 L 0 0 0 24" fill="none" stroke="#101F33" strokeWidth="0.8" />
                  </pattern>
                  <filter id="laserGlowRed" x="-20%" y="-20%" width="140%" height="140%">
                    <feDropShadow dx="0" dy="0" stdDeviation="4" floodColor="#FF5265" floodOpacity="0.8" />
                  </filter>
                  <filter id="laserGlowGreen" x="-20%" y="-20%" width="140%" height="140%">
                    <feDropShadow dx="0" dy="0" stdDeviation="4" floodColor="#39D69B" floodOpacity="0.8" />
                  </filter>
                  <filter id="laserGlowBlue" x="-20%" y="-20%" width="140%" height="140%">
                    <feDropShadow dx="0" dy="0" stdDeviation="4" floodColor="#248DD8" floodOpacity="0.8" />
                  </filter>
                </defs>
                <rect width="100%" height="100%" fill="url(#cyberGrid)" />
              </svg>

              {/* Main SVG Vector Canvas */}
              <svg 
                viewBox="0 0 1020 500" 
                className="w-full h-full"
                preserveAspectRatio="xMidYMid meet"
              >
                {/* 1. Hexagonal Network Zones */}
                {SPATIAL_TOPOLOGY.zones.map(zone => (
                  <g key={zone.id}>
                    <polygon
                      points={zone.polygon}
                      fill="#111F32"
                      fillOpacity="0.6"
                      stroke="#1E3553"
                      strokeWidth="1.5"
                      strokeDasharray="6,4"
                      className="transition-all duration-300 hover:fill-opacity-80"
                    />
                    <text
                      x={zone.labelPos.x}
                      y={zone.labelPos.y}
                      textAnchor="middle"
                      fill="#91A2B8"
                      fontSize="9"
                      fontWeight="bold"
                      letterSpacing="0.08em"
                      className="pointer-events-none uppercase font-mono"
                    >
                      {zone.name}
                    </text>
                  </g>
                ))}

                {/* 2. Connected Network Edges */}
                {SPATIAL_TOPOLOGY.edges.map((edge, idx) => {
                  const isActive = activeStepIndex >= 0 && (
                    (currentStep?.from === edge.from && currentStep?.to === edge.to) ||
                    (currentStep?.from === edge.to && currentStep?.to === edge.from) ||
                    (edge.from === 'student_pc_01' && edge.to === 'gw_firewall_01' && activeStepIndex === 0) ||
                    (edge.from === 'gw_firewall_01' && edge.to === 'app_server_01' && activeStepIndex >= 1 && simResult?.target_compromised) ||
                    (edge.from === 'app_server_01' && edge.to === 'db_server_01' && activeStepIndex >= 2 && simResult?.target_compromised)
                  );

                  const isBlockedHop = simResult && !simResult.target_compromised && activeStepIndex >= 1 && edge.to === 'gw_firewall_01';

                  let strokeColor = '#1E3553';
                  let filterAttr = '';
                  if (isBlockedHop) {
                    strokeColor = '#39D69B';
                    filterAttr = 'url(#laserGlowGreen)';
                  } else if (isActive) {
                    strokeColor = '#FF5265';
                    filterAttr = 'url(#laserGlowRed)';
                  }

                  return (
                    <g key={idx}>
                      {/* Base Track Line */}
                      <path
                        d={edge.d}
                        fill="none"
                        stroke={strokeColor}
                        strokeWidth={isActive || isBlockedHop ? '2.5' : '1.2'}
                        strokeDasharray={isBlockedHop ? '5,5' : 'none'}
                        filter={filterAttr}
                        className="transition-all duration-500"
                      />

                      {/* Moving Attack Particle along Active Edge */}
                      {isActive && executionState === 'RUNNING' && (
                        <circle r="4" fill="#FF5265" filter="url(#laserGlowRed)">
                          <animateMotion
                            path={edge.d}
                            dur={`${Math.max(0.6, 1.4 / speed)}s`}
                            repeatCount="indefinite"
                          />
                        </circle>
                      )}
                    </g>
                  );
                })}

                {/* 3. Interactive Hexagonal / Circular Network Nodes */}
                {Object.entries(SPATIAL_TOPOLOGY.nodes).map(([nodeId, nodeConfig]) => {
                  const visualState = getNodeVisualState(nodeId);
                  const dev = devices.find(d => d.id === nodeId) || { name: nodeConfig.label, ip: nodeConfig.ip };

                  return (
                    <g 
                      key={nodeId}
                      transform={`translate(${nodeConfig.x}, ${nodeConfig.y})`}
                      onClick={() => setInspectedAsset({ ...dev, ...nodeConfig, id: nodeId })}
                      className="cursor-pointer group"
                    >
                      {/* Pulsing Radar Aura on Attacker or Compromised Target */}
                      {(visualState.status === 'ATTACKER' || visualState.status === 'BREACHED') && (
                        <circle r="28" fill="none" stroke="#FF5265" strokeWidth="1.5" opacity="0.6">
                          <animate attributeName="r" values="20;36;20" dur="2s" repeatCount="indefinite" />
                          <animate attributeName="opacity" values="0.8;0;0.8" dur="2s" repeatCount="indefinite" />
                        </circle>
                      )}

                      {/* Shield Aura if Intercepted/Defended */}
                      {(visualState.status === 'DEFENDED' || visualState.status === 'INTERCEPTED') && (
                        <circle r="28" fill="none" stroke="#39D69B" strokeWidth="1.5" opacity="0.6">
                          <animate attributeName="r" values="20;32;20" dur="2s" repeatCount="indefinite" />
                          <animate attributeName="opacity" values="0.8;0.2;0.8" dur="2s" repeatCount="indefinite" />
                        </circle>
                      )}

                      {/* Outer Hexagon / Circle Node Body */}
                      <circle
                        r="20"
                        fill={visualState.fill}
                        stroke={visualState.border}
                        strokeWidth="2"
                        style={{ filter: visualState.glow !== 'none' ? `drop-shadow(${visualState.glow})` : 'none' }}
                        className="transition-all duration-300 group-hover:stroke-[#00E5FF]"
                      />

                      {/* Inner System Icon (SVG ForeignObject) */}
                      <foreignObject x="-10" y="-10" width="20" height="20" className="pointer-events-none">
                        <div className="flex items-center justify-center w-full h-full">
                          {renderNodeIcon(nodeConfig.icon, visualState.text)}
                        </div>
                      </foreignObject>

                      {/* Node Label Below */}
                      <text
                        y="34"
                        textAnchor="middle"
                        fill="#E7EDF7"
                        fontSize="10"
                        fontWeight="bold"
                        className="pointer-events-none font-sans"
                      >
                        {nodeConfig.label}
                      </text>

                      {/* IP Address Below */}
                      <text
                        y="46"
                        textAnchor="middle"
                        fill="#91A2B8"
                        fontSize="8.5"
                        fontFamily="monospace"
                        className="pointer-events-none"
                      >
                        {nodeConfig.ip}
                      </text>

                      {/* Small Status Tag */}
                      <g transform="translate(0, -25)">
                        <rect
                          x="-28"
                          y="-7"
                          width="56"
                          height="14"
                          rx="4"
                          fill="#101B2B"
                          stroke={visualState.border}
                          strokeWidth="1"
                        />
                        <text
                          textAnchor="middle"
                          y="3"
                          fill={visualState.text}
                          fontSize="7"
                          fontWeight="bold"
                          className="uppercase font-mono tracking-wider"
                        >
                          {visualState.status}
                        </text>
                      </g>
                    </g>
                  );
                })}

                {/* Firewall Interception Shield Glyph */}
                {simResult && !simResult.target_compromised && activeStepIndex >= 1 && (
                  <g transform="translate(425, 210)">
                    <rect x="-45" y="-48" width="90" height="18" rx="4" fill="#102B23" stroke="#39D69B" strokeWidth="1.2" />
                    <text textAnchor="middle" y="-36" fill="#39D69B" fontSize="8" fontWeight="bold" className="font-mono uppercase">
                      SHIELD: BLOCKED
                    </text>
                  </g>
                )}
              </svg>

              {/* Bottom Visual Legend */}
              <div className="absolute bottom-2.5 left-4 right-4 flex flex-wrap items-center justify-between text-[10px] text-[#91A2B8] bg-[#101B2B]/90 backdrop-blur-xs p-2 rounded-lg border border-[#1E3553]">
                <span className="font-mono font-bold text-[#E7EDF7]">VISUAL STATES:</span>
                <div className="flex items-center space-x-3 flex-wrap">
                  <span className="flex items-center space-x-1">
                    <span className="h-2 w-2 rounded-full bg-[#FF5265]" />
                    <span>Attack Vector</span>
                  </span>
                  <span className="flex items-center space-x-1">
                    <span className="h-2 w-2 rounded-full bg-[#F5AE48]" />
                    <span>Suspicious</span>
                  </span>
                  <span className="flex items-center space-x-1">
                    <span className="h-2 w-2 rounded-full bg-[#248DD8]" />
                    <span>Normal Comm</span>
                  </span>
                  <span className="flex items-center space-x-1">
                    <span className="h-2 w-2 rounded-full bg-[#39D69B]" />
                    <span>Defended / Blocked</span>
                  </span>
                  <span className="flex items-center space-x-1">
                    <span className="h-2 w-2 rounded-full bg-[#1E3553]" />
                    <span>Inactive</span>
                  </span>
                </div>
              </div>
            </div>

            {/* Live Packet Terminal Below Canvas */}
            <div className="bg-[#080E19] rounded-xl border border-[#1E3553] p-3 text-xs font-mono space-y-1 max-h-32 overflow-y-auto">
              <div className="flex items-center justify-between border-b border-[#1E3553] pb-1 text-[10px] text-[#91A2B8]">
                <span className="flex items-center space-x-1 text-[#248DD8]">
                  <Terminal className="h-3 w-3" />
                  <span>LIVE REPRODUCIBLE EVENT TIMELINE (SEED: {seed})</span>
                </span>
                <span>{terminalLogs.length} Events</span>
              </div>
              {terminalLogs.length === 0 ? (
                <div className="text-slate-600 italic py-2">
                  Awaiting attack trigger... Click "Execute Attack" to begin synthetic telemetry stream.
                </div>
              ) : (
                terminalLogs.map((log, i) => (
                  <div key={i} className={`text-[11px] leading-relaxed ${
                    log.includes('PERMITTED') || log.includes('BREACHED') || log.includes('ERROR') ? 'text-[#FF5265]' :
                    log.includes('BLOCKED') || log.includes('DEFENDED') ? 'text-[#39D69B]' :
                    'text-[#91A2B8]'
                  }`}>
                    {log}
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* RIGHT PANEL: Collapsible Contextual Explainer & Defenses (~20% width) */}
        {isRightPanelOpen && (
          <div className="lg:col-span-3 space-y-3">
            <div className="bg-[#101B2B] rounded-2xl border border-[#1E3553] p-4 text-[#E7EDF7] space-y-3 shadow-md">
              <div className="flex items-center justify-between border-b border-[#1E3553] pb-2">
                <span className="text-xs font-bold uppercase tracking-wider text-[#91A2B8]">
                  Attack Explainer
                </span>
                <span className="text-[10px] font-mono text-[#39D69B]">Stage Insights</span>
              </div>

              {/* Contextual Q&A */}
              <div className="p-3 rounded-xl bg-[#080E19] border border-[#1E3553] space-y-2 text-xs">
                <span className="font-bold text-[#248DD8] block text-[11px] uppercase tracking-wide">
                  {currentStageExplanation.title}
                </span>
                <div>
                  <span className="font-bold text-[#E7EDF7] block text-[10px] uppercase">1. What is happening?</span>
                  <p className="text-[#91A2B8] text-[11px] leading-relaxed">{currentStageExplanation.what}</p>
                </div>
                <div>
                  <span className="font-bold text-[#E7EDF7] block text-[10px] uppercase">2. Why is it happening?</span>
                  <p className="text-[#91A2B8] text-[11px] leading-relaxed">{currentStageExplanation.why}</p>
                </div>
                <div>
                  <span className="font-bold text-[#E7EDF7] block text-[10px] uppercase">3. Relevant Weakness</span>
                  <p className="text-[#FF5265] text-[11px] font-medium leading-relaxed">{currentStageExplanation.vulnerability}</p>
                </div>
                <div>
                  <span className="font-bold text-[#E7EDF7] block text-[10px] uppercase">4. Prevention</span>
                  <p className="text-[#39D69B] text-[11px] font-medium leading-relaxed">{currentStageExplanation.prevention}</p>
                </div>
              </div>

              {/* Actionable Defense Buttons */}
              <div className="pt-2 border-t border-[#1E3553] space-y-2">
                <span className="text-[10px] font-bold text-[#91A2B8] uppercase block">
                  Interactive Defenses
                </span>

                <button
                  onClick={() => handleApplyDefense('restrict_db_access')}
                  disabled={isRemediating}
                  className="w-full p-2.5 rounded-xl border border-[#248DD8]/60 bg-[#111F32] hover:bg-[#248DD8] text-[#248DD8] hover:text-white font-semibold text-xs transition-colors flex items-center justify-between"
                >
                  <span className="truncate">Restrict DB Port to App Server</span>
                  <Zap className="h-3.5 w-3.5 shrink-0 ml-1" />
                </button>

                <button
                  onClick={() => handleApplyDefense('strengthen_auth')}
                  disabled={isRemediating}
                  className="w-full p-2.5 rounded-xl border border-[#248DD8]/60 bg-[#111F32] hover:bg-[#248DD8] text-[#248DD8] hover:text-white font-semibold text-xs transition-colors flex items-center justify-between"
                >
                  <span className="truncate">Enforce Lockout & MFA</span>
                  <Lock className="h-3.5 w-3.5 shrink-0 ml-1" />
                </button>

                <button
                  onClick={() => handleApplyDefense('disable_service')}
                  disabled={isRemediating}
                  className="w-full p-2.5 rounded-xl border border-[#248DD8]/60 bg-[#111F32] hover:bg-[#248DD8] text-[#248DD8] hover:text-white font-semibold text-xs transition-colors flex items-center justify-between"
                >
                  <span className="truncate">Disable Telnet/FTP Daemons</span>
                  <ShieldCheck className="h-3.5 w-3.5 shrink-0 ml-1" />
                </button>

                {remediationMsg && (
                  <div className="p-2 rounded-lg bg-[#102B23] border border-[#39D69B]/40 text-[#39D69B] text-[11px] leading-relaxed">
                    {remediationMsg}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* FLOATING ASSET INSPECTION MODAL */}
      {inspectedAsset && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-[#101B2B] rounded-2xl max-w-md w-full p-5 shadow-2xl border border-[#248DD8]/50 text-[#E7EDF7] space-y-3 animate-in fade-in zoom-in-95 duration-200">
            <div className="flex items-center justify-between border-b border-[#1E3553] pb-2">
              <div className="flex items-center space-x-2">
                <div className="p-2 rounded-lg bg-[#111F32] text-[#248DD8]">
                  {renderNodeIcon(inspectedAsset.icon || 'server', '#248DD8')}
                </div>
                <div>
                  <h3 className="font-bold text-sm text-[#E7EDF7]">{inspectedAsset.name}</h3>
                  <span className="text-[11px] font-mono text-[#91A2B8]">{inspectedAsset.ip} ({inspectedAsset.zone})</span>
                </div>
              </div>
              <button onClick={() => setInspectedAsset(null)} className="text-[#91A2B8] hover:text-white">✕</button>
            </div>

            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="p-2 rounded bg-[#080E19] border border-[#1E3553]">
                <span className="text-[#91A2B8] block text-[9px] uppercase font-bold">Criticality</span>
                <span className="font-bold text-[#E7EDF7] capitalize">{inspectedAsset.criticality || 'Medium'}</span>
              </div>
              <div className="p-2 rounded bg-[#080E19] border border-[#1E3553]">
                <span className="text-[#91A2B8] block text-[9px] uppercase font-bold">Security State</span>
                <span className={`font-bold capitalize ${
                  inspectedAsset.security_status === 'compromised' ? 'text-[#FF5265]' :
                  inspectedAsset.security_status === 'isolated' ? 'text-[#F5AE48]' : 'text-[#39D69B]'
                }`}>
                  {inspectedAsset.security_status || 'Normal'}
                </span>
              </div>
            </div>

            <div>
              <span className="font-bold text-[11px] text-[#91A2B8] block mb-1">Open Services & Daemons:</span>
              <div className="flex flex-wrap gap-1 text-[11px] font-mono">
                {inspectedAsset.services?.length ? (
                  inspectedAsset.services.map((s, idx) => (
                    <span key={idx} className="px-2 py-0.5 rounded bg-[#111F32] border border-[#1E3553] text-[#248DD8]">
                      {s.name} (Port {s.port})
                    </span>
                  ))
                ) : (
                  <span className="text-[#91A2B8] italic text-[10px]">No listening services configured.</span>
                )}
              </div>
            </div>

            <div className="flex justify-between items-center pt-2 border-t border-[#1E3553]">
              <button
                onClick={() => handleToggleIsolation(inspectedAsset.id, inspectedAsset.security_status)}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold ${
                  inspectedAsset.security_status === 'isolated'
                    ? 'bg-[#39D69B] text-[#080E19]'
                    : 'bg-[#FF5265] text-white'
                }`}
              >
                {inspectedAsset.security_status === 'isolated' ? 'Restore Asset' : 'Isolate Asset'}
              </button>

              <div className="flex space-x-2">
                <button
                  onClick={() => {
                    setSourceNode(inspectedAsset.id);
                    setInspectedAsset(null);
                  }}
                  className="px-2.5 py-1.5 rounded-lg border border-[#1E3553] hover:bg-[#111F32] text-xs text-[#91A2B8]"
                >
                  Set as Source
                </button>
                <button
                  onClick={() => {
                    setTargetNode(inspectedAsset.id);
                    setInspectedAsset(null);
                  }}
                  className="px-2.5 py-1.5 rounded-lg bg-[#248DD8] hover:bg-[#1F74B2] text-xs text-white"
                >
                  Set as Target
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* REPEATABLE BEFORE-AND-AFTER COMPARISON EXPERIMENT MODAL */}
      {compareModalOpen && compareData && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-xs flex items-center justify-center p-4 overflow-y-auto">
          <div className="bg-[#101B2B] rounded-2xl max-w-3xl w-full p-6 shadow-2xl border border-[#248DD8]/50 text-[#E7EDF7] space-y-4 animate-in fade-in zoom-in-95 duration-200">
            <div className="flex items-center justify-between border-b border-[#1E3553] pb-3">
              <div>
                <h3 className="text-base font-bold text-[#E7EDF7] flex items-center space-x-2">
                  <Sparkles className="h-5 w-5 text-[#248DD8]" />
                  <span>Repeatable Experiment: Before vs After Defense</span>
                </h3>
                <p className="text-xs text-[#91A2B8]">
                  Same vector, same attacker, same seed (42). Evaluating quantitative security posture improvement.
                </p>
              </div>
              <button
                onClick={() => setCompareModalOpen(false)}
                className="p-1 rounded-lg text-[#91A2B8] hover:text-white"
              >
                ✕
              </button>
            </div>

            {/* Side-by-Side Comparison Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
              <div className="p-4 rounded-xl border border-[#FF5265]/40 bg-[#1F1524] space-y-2.5">
                <div className="flex items-center justify-between">
                  <span className="font-bold uppercase tracking-wider text-[#FF5265] text-[11px]">
                    Run 1: Vulnerable Baseline
                  </span>
                  <span className="px-2 py-0.5 rounded bg-[#FF5265]/20 text-[#FF5265] font-bold text-[10px]">
                    BREACHED
                  </span>
                </div>
                <div className="space-y-1">
                  <div className="flex justify-between">
                    <span className="text-[#91A2B8]">Security Score:</span>
                    <strong className="text-[#FF5265] font-mono">{compareData.before?.security_score} / 100</strong>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#91A2B8]">Calculated Risk:</span>
                    <strong className="text-[#FF5265] font-mono">{compareData.before?.risk_score} / 100</strong>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#91A2B8]">Target Disposition:</span>
                    <strong className="text-[#FF5265]">{compareData.before?.target_compromised ? '🚨 Compromised' : 'Protected'}</strong>
                  </div>
                </div>
              </div>

              <div className="p-4 rounded-xl border border-[#39D69B]/40 bg-[#102B23] space-y-2.5">
                <div className="flex items-center justify-between">
                  <span className="font-bold uppercase tracking-wider text-[#39D69B] text-[11px]">
                    Run 2: Hardened Defense
                  </span>
                  <span className="px-2 py-0.5 rounded bg-[#39D69B]/20 text-[#39D69B] font-bold text-[10px]">
                    DEFENDED
                  </span>
                </div>
                <div className="space-y-1">
                  <div className="flex justify-between">
                    <span className="text-[#91A2B8]">Security Score:</span>
                    <strong className="text-[#39D69B] font-mono">{compareData.after?.security_score} / 100</strong>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#91A2B8]">Calculated Risk:</span>
                    <strong className="text-[#39D69B] font-mono">{compareData.after?.risk_score} / 100</strong>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#91A2B8]">Target Disposition:</span>
                    <strong className="text-[#39D69B]">{compareData.after?.target_compromised ? 'Compromised' : '🛡️ Attack Blocked'}</strong>
                  </div>
                </div>
              </div>
            </div>

            {/* Impact Banner */}
            <div className="p-3 rounded-xl bg-[#080E19] border border-[#1E3553] text-xs space-y-1">
              <div className="flex items-center justify-between">
                <span className="font-bold text-[#E7EDF7]">Defense Assessment:</span>
                <span className="text-[#39D69B] font-bold font-mono">
                  +{compareData.comparison_summary?.risk_reduction_points} Points Posture Improvement
                </span>
              </div>
              <p className="text-[#91A2B8] text-[11px] leading-relaxed">
                {compareData.comparison_summary?.remediation_details}
              </p>
              <div className="text-[11px] text-[#248DD8] font-mono pt-0.5">
                Blocked Boundary Hop: <strong>{compareData.comparison_summary?.blocked_hop}</strong>
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setCompareModalOpen(false)}
                className="px-5 py-2 rounded-xl bg-[#248DD8] hover:bg-[#1F74B2] text-white text-xs font-semibold"
              >
                Close Comparison
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
