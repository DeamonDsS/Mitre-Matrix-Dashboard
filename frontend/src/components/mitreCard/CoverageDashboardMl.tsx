import React, { useEffect, useState, useRef } from 'react';
import {
    Activity,
    TrendingUp,
    Shield,
    AlertTriangle,
    Target,
    Eye,
    Zap,
    ChevronUp,
    Download,
    CheckCircle2,
    XCircle,
    Info,
    Brain,
    ToggleLeft,
    ToggleRight,
} from 'lucide-react';
import {
    fetchCyberKillChainCoverage,
    getCyberKillChainSummary,
    sortPhasesByActivity,
    sortPhasesByCoverage,
    getCoverageColor,
    getKillChainBlindSpots,
    detectActiveAttackChain,
    getPhaseThreadLevel,
    getPhaseDescription,
    exportKillChainToCSV,
    generateKillChainReport,
    type CyberKillChainResponse,
    type PhaseCoverage
} from '../../services/killChainService';
// import { fetchMLKillChainCoverage, type MLKillChainResponse } from '../../services/mlKillChainService';
import { fetchMLKillChainCoverage, type MLKillChainResponse, getModelInfo } from '../../services/mockMLKillChainService';

interface KillChainDashboardProps {
    selectedIndices: string[];
    dayRange: number;
    onDayRangeChange?: (days: number) => void;
}

const CoveragedashboardMl: React.FC<KillChainDashboardProps> = ({
    selectedIndices,
    dayRange,
    onDayRangeChange
}) => {
    const [loading, setLoading] = useState(true);
    const [killChainData, setKillChainData] = useState<CyberKillChainResponse | null>(null);
    const [timeFilter, setTimeFilter] = useState(dayRange);
    const [error, setError] = useState<string | null>(null);
    const [selectedPhase, setSelectedPhase] = useState<string | null>(null);
    const [showReport, setShowReport] = useState(false);

    // ML
    const [useMLPrediction, setUseMLPrediction] = useState(true);
    const [confidenceThreshold, setConfidenceThreshold] = useState(0.6);
    const [mlData, setMlData] = useState<MLKillChainResponse | null>(null);

    // --- CHANGE 2: Explicitly type the ref to be an HTMLDivElement ---
    const detailsPanelRef = useRef<HTMLDivElement>(null);

    // --- CHANGE 3: Add the useEffect hook to handle the scroll animation ---
    useEffect(() => {
        // Check if a phase is selected and the ref is attached to the DOM element
        if (selectedPhase && detailsPanelRef.current) {
            // Scroll to the panel with a smooth animation
            detailsPanelRef.current.scrollIntoView({
                behavior: 'smooth',
                block: 'start', // Aligns the top of the panel with the top of the viewport
            });
        }
    }, [selectedPhase]); // This effect will run every time `selectedPhase` changes

    // Mock data
    const killChainDataMock: CyberKillChainResponse = {
        total_detections: 30,
        unique_techniques: 12,
        time_range: {
            start: "2025-10-01",
            end: "2025-10-31"
        },
        indices_queried: ["palo-xsiam-*", "crowdstrike-*"],

        // Required by your interface
        active_phases: 7,
        methodology: "Cyber Kill Chain",
        phases: [
            {
                phase_id: 'reconnaissance',
                phase_name: 'Reconnaissance',
                phase_name_th: 'การสำรวจ',
                total_detections: 1250,
                techniques_detected: 8,
                available_techniques: 10,
                coverage_percentage: 80,
                sources: { SIEM: 500, EDR: 300, NDR: 450 },
                mitre_tactics: ['TA0043'],
                top_techniques: [
                    {
                        technique_id: 'T1595',
                        technique_name: 'Active Scanning',
                        count: 420,
                        sources: { SIEM: 210, NDR: 210 },
                        tactic_id: 'TA0043',
                        tactic_name: 'Reconnaissance',
                    },
                    {
                        technique_id: 'T1590',
                        technique_name: 'Gather Victim Information',
                        count: 300,
                        sources: { SIEM: 150, EDR: 150 },
                    },
                ],
            },
            {
                phase_id: 'weaponization',
                phase_name: 'Weaponization',
                phase_name_th: 'การสร้างอาวุธ',
                total_detections: 890,
                techniques_detected: 6,
                available_techniques: 8,
                coverage_percentage: 75,
                sources: { SIEM: 400, EDR: 490 },
                mitre_tactics: ['TA0042'],
                top_techniques: [
                    {
                        technique_id: 'T1505',
                        technique_name: 'Server Component',
                        count: 250,
                        sources: { EDR: 150, SIEM: 100 },
                    },
                ],
            },
            {
                phase_id: 'delivery',
                phase_name: 'Delivery',
                phase_name_th: 'การส่งมอบ',
                total_detections: 2100,
                techniques_detected: 12,
                available_techniques: 15,
                coverage_percentage: 80,
                sources: { EDR: 1100, NDR: 1000 },
                mitre_tactics: ['TA0011'],
                top_techniques: [
                    {
                        technique_id: 'T1566',
                        technique_name: 'Phishing',
                        count: 800,
                        sources: { EDR: 450, NDR: 350 },
                    },
                ],
            },
            {
                phase_id: 'exploitation',
                phase_name: 'Exploitation',
                phase_name_th: 'การโจมตี',
                total_detections: 3400,
                techniques_detected: 18,
                available_techniques: 20,
                coverage_percentage: 90,
                sources: { SIEM: 1800, EDR: 1600 },
                mitre_tactics: ['TA0001'],
                top_techniques: [
                    {
                        technique_id: 'T1203',
                        technique_name: 'Exploitation for Client Execution',
                        count: 1200,
                        sources: { EDR: 800, SIEM: 400 },
                    },
                ],
            },
            {
                phase_id: 'installation',
                phase_name: 'Installation',
                phase_name_th: 'การติดตั้ง',
                total_detections: 1680,
                techniques_detected: 10,
                available_techniques: 12,
                coverage_percentage: 83,
                sources: { EDR: 1000, NDR: 680 },
                mitre_tactics: ['TA0003'],
                top_techniques: [
                    {
                        technique_id: 'T1547',
                        technique_name: 'Boot or Logon Autostart Execution',
                        count: 650,
                        sources: { EDR: 500, NDR: 150 },
                    },
                ],
            },
            {
                phase_id: 'command_control',
                phase_name: 'Command & Control',
                phase_name_th: 'การควบคุม',
                total_detections: 2890,
                techniques_detected: 15,
                available_techniques: 18,
                coverage_percentage: 83,
                sources: { SIEM: 1200, NDR: 1690 },
                mitre_tactics: ['TA0011'],
                top_techniques: [
                    {
                        technique_id: 'T1090',
                        technique_name: 'Proxy',
                        count: 900,
                        sources: { NDR: 650, SIEM: 250 },
                    },
                ],
            },
            {
                phase_id: 'actions_objectives',
                phase_name: 'Actions on Objectives',
                phase_name_th: 'การดำเนินการ',
                total_detections: 1456,
                techniques_detected: 11,
                available_techniques: 14,
                coverage_percentage: 78,
                sources: { SIEM: 600, EDR: 856 },
                mitre_tactics: ['TA0040'],
                top_techniques: [
                    {
                        technique_id: 'T1020',
                        technique_name: 'Automatic Exfiltration',
                        count: 520,
                        sources: { EDR: 300, SIEM: 220 },
                    },
                ],
            },
        ],
    };


    useEffect(() => {
        loadKillChainData();
    }, [selectedIndices, timeFilter]);

    const loadKillChainData = async () => {
        if (!selectedIndices.length) {
            setKillChainData(null);
            setMlData(null);
            setLoading(false);
            return;
        }

        setLoading(true);
        setError(null);

        try {
            if (useMLPrediction) {
                // Use ML-based prediction
                const data = await fetchMLKillChainCoverage(selectedIndices, {
                    dayRange: timeFilter,
                    confidenceThreshold: confidenceThreshold,
                });
                setMlData(data);

                // Convert ML response to existing format for backward compatibility
                setKillChainData({
                    ...data,
                    total_detections: data.ml_predictions,
                    unique_techniques: data.unique_techniques,
                    active_phases: data.active_phases,
                    methodology: data.methodology,
                    // Map ML phases to existing phase structure
                    phases: data.phases.map(p => ({
                        ...p,
                        total_detections: p.predicted_detections,
                    }))
                });
            } else {
                // Use existing rule-based approach
                const data = await fetchCyberKillChainCoverage(selectedIndices, {
                    dayRange: timeFilter,
                    search: null,
                });
                setKillChainData(data || killChainDataMock);
                setMlData(null);
            }
        } catch (err) {
            console.error("Error loading kill chain data:", err);
            setError(`Failed to load data: ${err}`);
            setKillChainData(killChainDataMock);
        } finally {
            setLoading(false);
        }
    };


    const handleExportCSV = () => {
        if (!killChainData) return;

        const csv = exportKillChainToCSV(killChainData);
        const blob = new Blob([csv], { type: 'text/csv' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `cyber-kill-chain-${new Date().toISOString().split('T')[0]}.csv`;
        a.click();
        window.URL.revokeObjectURL(url);
    };

    if (loading) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
            </div>
        );
    }

    if (error) {
        return (
            <div className="bg-red-50 border border-red-200 rounded-lg p-4">
                <div className="flex items-center gap-2 text-red-800">
                    <AlertTriangle className="w-5 h-5" />
                    <span>{error}</span>
                </div>
            </div>
        );
    }

    if (!killChainData || killChainData.phases.length === 0) {
        return (
            <div className="bg-gray-50 border border-gray-200 rounded-lg p-8 text-center">
                <Shield className="w-12 h-12 text-gray-400 mx-auto mb-3" />
                <p className="text-gray-600">No kill chain data available</p>
                <p className="text-sm text-gray-500 mt-1">Select indices and time range to view coverage</p>
            </div>
        );
    }

    const summary = getCyberKillChainSummary(killChainData);
    const attackChain = detectActiveAttackChain(killChainData);
    const blindSpots = getKillChainBlindSpots(killChainData);
    const report = generateKillChainReport(killChainData);

    const getRiskLevelColor = (level: string) => {
        switch (level) {
            case 'critical': return 'text-red-600 bg-red-100';
            case 'high': return 'text-orange-600 bg-orange-100';
            case 'medium': return 'text-yellow-600 bg-yellow-100';
            case 'low': return 'text-blue-600 bg-blue-100';
            default: return 'text-gray-600 bg-gray-100';
        }
    };

    const selectedPhaseData = selectedPhase
        ? killChainData.phases.find(p => p.phase_id === selectedPhase)
        : null;

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-2xl font-bold text-white flex items-center gap-2">
                        <Target className="w-7 h-7 text-blue-600" />
                        Cyber Kill Chain Coverage
                    </h2>
                    <div className="flex items-center gap-2 mt-1">
                        <p className="text-sm text-gray-400">
                            {killChainData.methodology} - 7 Phase Analysis
                        </p>
                        {useMLPrediction && (
                            <div className="inline-flex items-center gap-1 px-2 py-0.5 bg-purple-900/30 text-purple-300 rounded-full text-xs font-medium border border-purple-700/30">
                                <Brain className="w-3 h-3" />
                                ML Powered
                            </div>
                        )}
                    </div>
                </div>

                <div className="flex items-center gap-3">
                    {/* ML Toggle */}
                    <div className="flex items-center gap-2 bg-gray-800 rounded-lg px-3 py-2 border border-gray-700">
                        <Brain className={`w-5 h-5 ${useMLPrediction ? 'text-purple-400' : 'text-gray-500'}`} />
                        <button
                            onClick={() => setUseMLPrediction(!useMLPrediction)}
                            className="flex items-center gap-2 text-sm font-medium text-gray-200"
                        >
                            <span>{useMLPrediction ? 'ML Prediction' : 'Rule-Based'}</span>
                            {useMLPrediction ? (
                                <ToggleRight className="w-5 h-5 text-purple-400" />
                            ) : (
                                <ToggleLeft className="w-5 h-5 text-gray-500" />
                            )}
                        </button>
                    </div>

                    {/* Confidence Threshold (only show when ML is enabled) */}
                    {useMLPrediction && (
                        <div className="flex items-center gap-2">
                            <label className="text-sm text-gray-300">Confidence:</label>
                            <select
                                value={confidenceThreshold}
                                onChange={(e) => setConfidenceThreshold(parseFloat(e.target.value))}
                                className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm text-gray-200 focus:outline-none focus:ring-2 focus:ring-purple-500"
                            >
                                <option value={0.5}>50%</option>
                                <option value={0.6}>60%</option>
                                <option value={0.7}>70%</option>
                                <option value={0.8}>80%</option>
                                <option value={0.9}>90%</option>
                            </select>
                        </div>
                    )}

                    <select
                        value={timeFilter}
                        onChange={(e) => {
                            const days = parseInt(e.target.value);
                            setTimeFilter(days);
                            onDayRangeChange?.(days);
                        }}
                        className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                    >
                        <option value={1}>Last 24 hours</option>
                        <option value={7}>Last 7 days</option>
                        <option value={30}>Last 30 days</option>
                        <option value={90}>Last 90 days</option>
                    </select>

                    <button
                        onClick={handleExportCSV}
                        className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700 transition-colors flex items-center gap-2"
                    >
                        <Download className="w-4 h-4" />
                        Export CSV
                    </button>
                </div>
            </div>



            {/* Attack Chain Alert */}
            {attackChain.isActive && (
                <div className="bg-red-50 border-l-4 border-red-500 rounded-lg p-4">
                    <div className="flex items-start gap-3">
                        <AlertTriangle className="w-5 h-5 text-red-600 mt-0.5" />
                        <div className="flex-1">
                            <h3 className="font-semibold text-red-900">
                                Active Attack Chain Detected
                            </h3>
                            <p className="text-sm text-red-700 mt-1">
                                Consecutive activity detected across {attackChain.longestChain} phases:
                                <span className="font-medium"> {attackChain.startPhase} → {attackChain.endPhase}</span>
                            </p>
                        </div>
                    </div>
                </div>
            )}

            {/* Summary Cards */}
            <div className={`grid grid-cols-1 md:grid-cols-2 ${useMLPrediction && mlData ? 'lg:grid-cols-5' : 'lg:grid-cols-4'} gap-4`}>
                <div className="bg-gray-900 rounded-lg shadow-sm border border-gray-700 p-4">
                    <div className="flex items-center justify-between mb-2">
                        <span className="text-sm text-white">Active Phases</span>
                        <Activity className="w-4 h-4 text-blue-600" />
                    </div>
                    <div className="flex items-baseline gap-2">
                        <span className="text-2xl font-bold text-gray-200">{summary.activePhases}</span>
                        <span className="text-sm text-gray-300">/ {summary.totalPhases}</span>
                    </div>
                    <div className="mt-2 text-xs text-gray-400">
                        {summary.completionPercentage.toFixed(0)}% completion
                    </div>
                </div>

                <div className="bg-gray-900 rounded-lg shadow-sm border border-gray-700 p-4">
                    <div className="flex items-center justify-between mb-2">
                        <span className="text-sm text-white">Total Detections</span>
                        <Zap className="w-4 h-4 text-orange-600" />
                    </div>
                    <div className="text-2xl font-bold text-gray-200">
                        {summary.totalDetections.toLocaleString()}
                    </div>
                    <div className="mt-2 text-xs text-gray-400">
                        {summary.uniqueTechniques} unique techniques
                    </div>
                </div>

                <div className="bg-gray-900 rounded-lg shadow-sm border border-gray-700 p-4">
                    <div className="flex items-center justify-between mb-2">
                        <span className="text-sm text-white">Avg Coverage</span>
                        <Shield className="w-4 h-4 text-green-600" />
                    </div>
                    <div className="text-2xl font-bold text-gray-200">
                        {summary.averageCoverage.toFixed(1)}%
                    </div>
                    <div className="mt-2">
                        <div className="w-full bg-gray-200 rounded-full h-1.5">
                            <div
                                className="bg-green-600 h-1.5 rounded-full transition-all"
                                style={{ width: `${summary.averageCoverage}%` }}
                            />
                        </div>
                    </div>
                </div>

                <div className="bg-gray-900 rounded-lg shadow-sm border border-gray-700 p-4">
                    <div className="flex items-center justify-between mb-2">
                        <span className="text-sm text-white">Risk Level</span>
                        <AlertTriangle className="w-4 h-4 text-red-600" />
                    </div>
                    <div className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ${getRiskLevelColor(report.riskLevel)}`}>
                        {report.riskLevel.toUpperCase()}
                    </div>
                    <div className="mt-2 text-xs text-gray-200">
                        {report.keyFindings.length} key findings
                    </div>
                </div>

                {/* // Add ML confidence indicator to summary cards */}
                {mlData && useMLPrediction && (
                    <div className="bg-gray-900 rounded-lg shadow-sm border border-gray-700 p-4">
                        <div className="flex items-center justify-between mb-2">
                            <span className="text-sm text-white">ML Confidence</span>
                            <Brain className="w-4 h-4 text-purple-600" />
                        </div>
                        <div className="text-2xl font-bold text-gray-200">
                            {(mlData.phases.reduce((sum, p) => sum + p.confidence_score, 0) / mlData.phases.length * 100).toFixed(1)}%
                        </div>
                        <div className="mt-2 text-xs text-gray-400">
                            Model: {mlData.model_version}
                        </div>
                    </div>
                )}

            </div>

            {/* Zigzag Kill Chain Roadmap */}
            <div className="bg-gradient-to-br from-gray-900/90 to-gray-800/90 backdrop-blur rounded-2xl shadow-2xl border border-gray-700/50 p-8 overflow-x-auto">
                <h3 className="text-xl font-semibold text-gray-100 mb-10 flex items-center gap-2">
                    <Shield className="w-6 h-6 text-blue-400" />
                    Kill Chain Progression
                </h3>

                <div className="relative" style={{ minHeight: useMLPrediction && mlData ? '800px' : '700px' }}>
                    {/* Horizontal Center Line - เส้นตรงแนวนอนตรงกลาง */}
                    <svg
                        className="absolute inset-0 w-full h-full pointer-events-none"
                        style={{ minHeight: useMLPrediction && mlData ? '800px' : '700px' }}
                    >
                        {killChainData.phases.map((phase, index) => {
                            if (index === killChainData.phases.length - 1) return null;

                            const startX = index * 200 + 75;
                            const centerY = useMLPrediction && mlData ? 450 : 400;
                            const endX = (index + 1) * 200 + 100;

                            const currentActive = phase.total_detections > 0;
                            const nextActive = killChainData.phases[index + 1].total_detections > 0;

                            // สีพื้นหลังที่แตกต่างกันสำหรับแต่ละ phase
                            const phaseColors = [
                                '#ff3b3b', '#ff7b3b', '#ffbb3b', '#ffeb3b',
                                '#9aff3b', '#3bff9a', '#3bbbff'
                            ];
                            const currentColor = phaseColors[index] || '#9ca3af';
                            const nextColor = phaseColors[index + 1] || '#9ca3af';

                            return (
                                <g key={`line-${index}`}>
                                    <defs>
                                        <linearGradient id={`gradient-${index}`} x1="0%" y1="0%" x2="100%" y2="0%">
                                            <stop offset="0%" stopColor={currentActive ? currentColor : '#9ca3af'} />
                                            <stop offset="100%" stopColor={nextActive ? nextColor : '#9ca3af'} />
                                        </linearGradient>
                                    </defs>
                                    {/* Shadow line for depth */}
                                    <line
                                        x1={startX}
                                        y1={centerY + 2}
                                        x2={endX}
                                        y2={centerY + 2}
                                        stroke="rgba(0,0,0,0.3)"
                                        strokeWidth="28"
                                        opacity="0.5"
                                    />
                                    {/* Main horizontal line */}
                                    <line
                                        x1={startX}
                                        y1={centerY}
                                        x2={endX}
                                        y2={centerY}
                                        stroke={currentActive || nextActive ? `url(#gradient-${index})` : '#6b7280'}
                                        strokeWidth="20"
                                        strokeLinecap="round"
                                        opacity="1"
                                    />
                                    {/* Highlight line */}
                                    {(currentActive || nextActive) && (
                                        <line
                                            x1={startX}
                                            y1={centerY}
                                            x2={endX}
                                            y2={centerY}
                                            stroke="rgba(255,255,255,0.5)"
                                            strokeWidth="14"
                                            strokeLinecap="round"
                                        />
                                    )}
                                </g>
                            );
                        })}
                    </svg>

                    {/* Phase Nodes - Zigzag positions */}
                    <div className="relative flex justify-center gap-8" style={{ minWidth: 'max-content', width: '100%' }}>
                        {killChainData.phases.map((phase, index) => {
                            const coverageColor = getCoverageColor(phase.coverage_percentage);
                            const threatLevel = getPhaseThreadLevel(phase);
                            const phaseDesc = getPhaseDescription(phase.phase_id);
                            const isActive = phase.total_detections > 0;
                            const isSelected = selectedPhase === phase.phase_id;
                            const isEven = index % 2 === 0;

                            const phasePalettes = [
                                { big: '#ff4d4d', small: '#ff9999' }, // แดงสด - ชมพูแดง (เด่นชัดมากบนพื้นเข้ม)
                                { big: '#4d6dff', small: '#99a9ff' }, // น้ำเงินสด - ฟ้าอ่อน (เท่แต่สว่าง)
                                { big: '#34d058', small: '#8aff9a' }, // เขียวสด - เขียวมิ้นต์ (ชัดตา, สด)
                                { big: '#ffcc00', small: '#fff275' }, // เหลืองทอง - เหลืองอ่อน (สว่างตัดพื้น)
                                { big: '#b366ff', small: '#d8a9ff' }, // ม่วงสด - ม่วงอ่อน (หรูหราแต่ไม่มืด)
                                { big: '#00d4b3', small: '#6affdf' }, // เขียวอมฟ้า - มิ้นต์สว่าง (สดใส modern)
                                { big: '#ff7849', small: '#ffb899' }  // ส้มสด - ส้มอ่อน (อบอุ่น, โดดดี)
                            ];

                            const baseColor = phasePalettes[index]?.big || '#6b7280';
                            const smallBaseColor = phasePalettes[index]?.small || '#6b7280';

                            return (
                                <div
                                    key={phase.phase_id}
                                    className="relative flex flex-col items-center"
                                    style={{
                                        width: '160px',
                                        marginTop: isEven ? '0' : (useMLPrediction && mlData ? '480px' : '420px')
                                    }}
                                >
                                    {/* Circle Node - ใหญ่ขึ้น */}
                                    <div className="relative z-10 mb-6 group">
                                        {/* Outer glow ring on hover */}
                                        <div
                                            className="absolute inset-0 w-24 h-24 rounded-full opacity-0 group-hover:opacity-100 transition-all duration-300 blur-xl pointer-events-none"
                                            style={{
                                                backgroundColor: baseColor,
                                                transform: 'scale(1.3)'
                                            }}
                                        />

                                        <div
                                            onClick={() => setSelectedPhase(phase.phase_id)}
                                            className={`relative w-24 h-24 rounded-full flex items-center justify-center text-4xl cursor-pointer transition-all duration-300 ${isSelected
                                                ? 'scale-125 animate-pulse'
                                                : 'hover:scale-115 group-hover:rotate-6'
                                                }`}
                                            style={{
                                                backgroundColor: baseColor,
                                                boxShadow: isSelected
                                                    ? `0 0 50px ${baseColor}, 0 0 80px ${baseColor}60, 0 15px 30px rgba(0,0,0,0.5), inset 0 0 30px ${baseColor}40`
                                                    : isActive
                                                        ? `0 0 30px ${baseColor}80, 0 10px 20px rgba(0,0,0,0.4), inset 0 0 20px ${baseColor}20`
                                                        : `0 0 15px ${baseColor}40, 0 10px 20px rgba(0,0,0,0.3)`,
                                                border: isSelected
                                                    ? `5px solid ${smallBaseColor}`
                                                    : `4px solid ${baseColor}60`,
                                                opacity: isActive ? 1 : 0.6,
                                                filter: isSelected ? 'brightness(1.2)' : 'none'
                                            }}
                                        >
                                            <span
                                                className="transition-all duration-300 group-hover:scale-110 pointer-events-none"
                                                style={{
                                                    filter: isSelected ? 'brightness(1.3) drop-shadow(0 0 8px white)' : 'brightness(1.2)',
                                                    textShadow: isSelected ? `0 0 20px ${baseColor}` : 'none'
                                                }}
                                            >
                                                {phaseDesc.icon}
                                            </span>
                                        </div>

                                        {/* Ripple effect on hover */}
                                        <div
                                            className="absolute inset-0 w-24 h-24 rounded-full border-2 opacity-0 group-hover:opacity-100 group-hover:scale-150 transition-all duration-700 pointer-events-none"
                                            style={{
                                                borderColor: baseColor,
                                                animation: 'ping 1.5s cubic-bezier(0, 0, 0.2, 1) infinite'
                                            }}
                                        />

                                        {/* Status Indicator */}
                                        <div className="absolute -top-2 -right-2">
                                            {isActive ? (
                                                <CheckCircle2
                                                    className="w-8 h-8 bg-gray-900 rounded-full"
                                                    style={{ color: baseColor }}
                                                />
                                            ) : (
                                                <XCircle className="w-8 h-8 text-gray-500 bg-gray-900 rounded-full" />
                                            )}
                                        </div>

                                        {/* Phase Number - refined glass style */}
                                        <div className="absolute -bottom-5 left-1/2 transform -translate-x-1/2">
                                            <div
                                                className={`flex items-center justify-center w-11 h-11 rounded-full font-extrabold text-white text-lg transition-all duration-300 ${isSelected ? 'scale-110 shadow-lg' : 'scale-100'
                                                    }`}
                                                style={{
                                                    background: `linear-gradient(145deg, ${smallBaseColor}dd, ${baseColor}cc)`,
                                                    border: `2px solid ${baseColor}80`,
                                                    boxShadow: isSelected
                                                        ? `0 0 15px ${smallBaseColor}80, inset 0 0 6px rgba(255,255,255,0.2)`
                                                        : `inset 0 0 6px rgba(255,255,255,0.1), 0 2px 6px rgba(0,0,0,0.4)`,
                                                    backdropFilter: 'blur(6px)',
                                                    WebkitBackdropFilter: 'blur(6px)',
                                                    filter: isSelected ? 'brightness(1.15)' : 'none',
                                                }}
                                            >
                                                {index + 1}
                                            </div>
                                        </div>
                                    </div>

                                    {/* Phase Info */}
                                    <div className="text-center space-y-3 w-full">
                                        <div>
                                            {/* <h4 className="font-semibold text-gray-100 text-[18px]">
                                                {phase.phase_name}
                                            </h4>
                                            <p className="text-xs text-gray-400">
                                                {phase.phase_name_th}
                                            </p> */}
                                            <h4
                                                className="font-semibold text-gray-100 text-[22px] truncate"
                                                title={phase.phase_name}
                                            >
                                                {phase.phase_name}
                                            </h4>
                                            <p
                                                className="text-xs text-gray-400 truncate"
                                                title={phase.phase_name_th}
                                            >
                                                {phase.phase_name_th}
                                            </p>
                                        </div>

                                        {/* Metrics */}
                                        <div
                                            className="space-y-2 rounded-lg p-3 border"
                                            style={{
                                                backgroundColor: `${baseColor}15`,
                                                borderColor: `${baseColor}40`
                                            }}
                                        >
                                            <div>
                                                <div className="text-xl font-bold text-gray-200">
                                                    {phase.total_detections.toLocaleString()}
                                                </div>
                                                <div className="text-xs text-gray-400">detections</div>
                                            </div>

                                            <div>
                                                <div className="text-sm font-semibold text-gray-200">
                                                    {phase.techniques_detected}/{phase.available_techniques}
                                                </div>
                                                <div className="text-xs text-gray-400">techniques</div>
                                            </div>

                                            <div>
                                                <div
                                                    className="text-lg font-bold"
                                                    style={{ color: baseColor }}
                                                >
                                                    {phase.coverage_percentage.toFixed(0)}%
                                                </div>
                                                <div className="text-xs text-gray-400">coverage</div>
                                            </div>

                                            {/* ML Confidence Score */}
                                            {mlData && useMLPrediction && (
                                                <div className="pt-2 border-t border-gray-700">
                                                    <div className="flex items-center justify-between text-xs mb-1">
                                                        <span className="text-gray-400">Confidence</span>
                                                        <span className="font-semibold text-purple-400">
                                                            {((mlData.phases[index]?.confidence_score || 0) * 100).toFixed(0)}%
                                                        </span>
                                                    </div>
                                                    <div className="w-full bg-gray-700 rounded-full h-1">
                                                        <div
                                                            className="bg-purple-500 h-1 rounded-full transition-all"
                                                            style={{ width: `${(mlData.phases[index]?.confidence_score || 0) * 100}%` }}
                                                        />
                                                    </div>
                                                </div>
                                            )}
                                        </div>

                                        {/* Threat Badge */}
                                        {threatLevel.level !== 'info' && (
                                            <div
                                                className="inline-flex items-center px-3 py-1.5 rounded-full text-xs font-medium whitespace-nowrap"
                                                style={{
                                                    backgroundColor: threatLevel.color + '20',
                                                    color: threatLevel.color,
                                                    border: `1px solid ${threatLevel.color}40`
                                                }}
                                            >
                                                {threatLevel.label}
                                            </div>
                                        )}

                                    </div>
                                </div>
                            );
                        })}
                    </div>
                </div>
            </div>

            {/* Phase Details Panel */}
            {selectedPhaseData && (
                <div
                    ref={detailsPanelRef}
                    className="rounded-2xl border p-6 transition-all duration-500 shadow-xl"
                    style={{
                        background: `linear-gradient(145deg, rgba(30,30,35,0.95), rgba(20,20,25,0.9))`,
                        borderColor: getPhaseThreadLevel(selectedPhaseData).color + '40',
                        boxShadow: `0 0 30px ${getPhaseThreadLevel(selectedPhaseData).color}20`,
                    }}
                >
                    {/* Header */}
                    <div className="flex items-start gap-4 pb-5 border-b border-gray-700/70 mb-6">
                        <div
                            className="flex items-center justify-center w-12 h-12 rounded-xl text-3xl"
                            style={{
                                backgroundColor: getPhaseThreadLevel(selectedPhaseData).color + '15',
                                color: getPhaseThreadLevel(selectedPhaseData).color,
                            }}
                        >
                            {getPhaseDescription(selectedPhaseData.phase_id).icon}
                        </div>

                        <div className="flex-1">
                            <h3 className="text-xl font-semibold text-white tracking-wide">
                                {selectedPhaseData.phase_name}{' '}
                                <span className="text-gray-400">({selectedPhaseData.phase_name_th})</span>
                            </h3>
                            <p className="text-sm text-gray-400 mt-1 leading-snug">
                                {getPhaseDescription(selectedPhaseData.phase_id).th}
                            </p>
                        </div>

                        <button
                            onClick={() => setSelectedPhase(null)}
                            className="text-gray-500 hover:text-gray-300 transition-colors"
                        >
                            <ChevronUp className="w-5 h-5" />
                        </button>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        {/* Top Techniques */}
                        <div>
                            <h4 className="text-sm font-semibold text-gray-300 mb-3 flex items-center gap-2 uppercase tracking-wide">
                                <TrendingUp className="w-4 h-4 text-blue-500" />
                                Top Techniques
                            </h4>
                            <div className="space-y-2">
                                {selectedPhaseData.top_techniques.length > 0 ? (
                                    selectedPhaseData.top_techniques.map((tech) => (
                                        <div
                                            key={tech.technique_id}
                                            className="bg-gray-800/60 hover:bg-gray-800/90 rounded-lg p-3 border border-gray-700/70 transition-all"
                                        >
                                            <div className="flex items-center justify-between mb-1">
                                                <span className="font-medium text-gray-100 text-sm">
                                                    {tech.technique_id}
                                                </span>
                                                <span className="text-sm font-bold text-blue-400">
                                                    {tech.count.toLocaleString()}
                                                </span>
                                            </div>
                                            <div className="text-xs text-gray-400">
                                                {tech.technique_name}
                                            </div>
                                            {tech.tactic_name && (
                                                <div className="text-xs text-gray-500 mt-1">
                                                    MITRE: {tech.tactic_name}
                                                </div>
                                            )}
                                        </div>
                                    ))
                                ) : (
                                    <p className="text-sm text-gray-400 italic">No techniques detected</p>
                                )}
                            </div>
                        </div>

                        {/* Detection Sources */}
                        <div>
                            <h4 className="text-sm font-semibold text-gray-300 mb-3 flex items-center gap-2 uppercase tracking-wide">
                                <Eye className="w-4 h-4 text-green-500" />
                                Detection Sources
                            </h4>
                            <div className="space-y-2">
                                {Object.entries(selectedPhaseData.sources).map(([source, count]) => (
                                    <div
                                        key={source}
                                        className="bg-gray-800/60 hover:bg-gray-800/90 rounded-lg p-3 border border-gray-700/70 transition-all"
                                    >
                                        <div className="flex items-center justify-between mb-2">
                                            <span className="text-sm text-gray-100 font-medium truncate">
                                                {source}
                                            </span>
                                            <span className="text-sm font-bold text-gray-100 ml-2">
                                                {count.toLocaleString()}
                                            </span>
                                        </div>
                                        <div className="w-full bg-gray-700 rounded-full h-1.5 overflow-hidden">
                                            <div
                                                className="h-full rounded-full transition-all"
                                                style={{
                                                    width: `${(count / selectedPhaseData.total_detections) * 100}%`,
                                                    backgroundColor: getPhaseThreadLevel(selectedPhaseData).color,
                                                }}
                                            />
                                        </div>
                                    </div>
                                ))}
                                {Object.keys(selectedPhaseData.sources).length === 0 && (
                                    <p className="text-sm text-gray-400 italic">No sources</p>
                                )}
                            </div>

                            {/* MITRE Mapping */}
                            {selectedPhaseData.mitre_tactics?.length > 0 && (
                                <div className="mt-4">
                                    <h4 className="text-sm font-semibold text-gray-300 mb-2 uppercase tracking-wide">
                                        MITRE Tactics
                                    </h4>
                                    <div className="flex flex-wrap gap-2">
                                        {selectedPhaseData.mitre_tactics.map((tactic) => (
                                            <span
                                                key={tactic}
                                                className="inline-flex items-center px-2 py-1 rounded-lg bg-blue-900/30 text-blue-300 text-xs font-medium border border-blue-700/50"
                                            >
                                                {tactic}
                                            </span>
                                        ))}
                                    </div>
                                </div>
                            )}
                        </div>
                    </div>

                    {/* Threat Alert */}
                    {getPhaseThreadLevel(selectedPhaseData).level !== 'info' && (
                        <div
                            className="mt-8 rounded-xl p-4 border transition-all duration-300"
                            style={{
                                backgroundColor: getPhaseThreadLevel(selectedPhaseData).color + '15',
                                borderColor: getPhaseThreadLevel(selectedPhaseData).color + '40',
                            }}
                        >
                            <p
                                className="text-sm font-semibold flex items-center gap-2"
                                style={{ color: getPhaseThreadLevel(selectedPhaseData).color }}
                            >
                                ⚠ {getPhaseThreadLevel(selectedPhaseData).description}
                            </p>
                        </div>
                    )}
                </div>
            )}


            {/* Blind Spots Warning */}
            {blindSpots.length > 0 && (
                <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
                    <div className="flex items-start gap-3">
                        <Eye className="w-5 h-5 text-yellow-600 mt-0.5" />
                        <div>
                            <h3 className="font-semibold text-yellow-900 mb-1">
                                Detection Blind Spots
                            </h3>
                            <p className="text-sm text-yellow-700">
                                No detection coverage for {blindSpots.length} phases: {' '}
                                <span className="font-medium">
                                    {blindSpots.map(p => p.phase_name).join(', ')}
                                </span>
                            </p>
                        </div>
                    </div>
                </div>
            )}

            {/* Executive Report */}
            {showReport && (
                <div className="bg-gray-900 rounded-lg shadow-sm border border-gray-700 p-6">
                    <div className="flex items-center justify-between mb-4">
                        <h3 className="text-lg font-semibold text-gray-200">Executive Summary</h3>
                        <button
                            onClick={() => setShowReport(false)}
                            className="text-gray-3 hover:text-gray-700"
                        >
                            <ChevronUp className="w-5 h-5 text-gray-200" />
                        </button>
                    </div>

                    <p className="text-gray-300 mb-4">{report.executiveSummary}</p>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <div>
                            <h4 className="font-semibold text-gray-200 mb-2">Key Findings</h4>
                            <ul className="space-y-2">
                                {report.keyFindings.map((finding, idx) => (
                                    <li key={idx} className="flex items-start gap-2 text-sm text-gray-300">
                                        <span className="text-blue-600 mt-1">•</span>
                                        <span>{finding}</span>
                                    </li>
                                ))}
                            </ul>
                        </div>

                        <div>
                            <h4 className="font-semibold text-gray-300 mb-2">Recommendations</h4>
                            <ul className="space-y-2">
                                {report.recommendations.map((rec, idx) => (
                                    <li key={idx} className="flex items-start gap-2 text-sm text-gray-300">
                                        <span className="text-orange-600 mt-1">•</span>
                                        <span>{rec}</span>
                                    </li>
                                ))}
                            </ul>
                        </div>
                    </div>
                </div>
            )}

            {!showReport && (
                <button
                    onClick={() => setShowReport(true)}
                    className="w-full py-2 text-sm text-blue-600 hover:text-blue-700 font-medium flex items-center justify-center gap-2"
                >
                    <Info className="w-4 h-4" />
                    Show Executive Report
                </button>
            )}



            {/* Footer Info */}
            <div className="text-center text-xs text-gray-500 pt-4 border-t border-gray-200">
                <p>
                    Data from {killChainData.indices_queried.length} indices •
                    Time range: {new Date(killChainData.time_range.start).toLocaleDateString()} - {new Date(killChainData.time_range.end).toLocaleDateString()}
                </p>
                <p className="mt-1">
                    Methodology: {killChainData.methodology}
                </p>
            </div>
        </div>
    );
};

export default CoveragedashboardMl;