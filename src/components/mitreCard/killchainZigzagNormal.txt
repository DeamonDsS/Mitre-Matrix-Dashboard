import React, { useEffect, useState } from 'react';
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
  Info
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

interface KillChainDashboardProps {
  selectedIndices: string[];
  dayRange: number;
  onDayRangeChange?: (days: number) => void;
}

const KillChainDashboard: React.FC<KillChainDashboardProps> = ({ 
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

  useEffect(() => {
    loadKillChainData();
  }, [selectedIndices, timeFilter]);

  const loadKillChainData = async () => {
    if (!selectedIndices.length) {
      setLoading(false);
      return;
    }

    try {
      setLoading(true);
      setError(null);
      
      const data = await fetchCyberKillChainCoverage(selectedIndices, {
        dayRange: timeFilter,
        search: null
      });
      
      setKillChainData(data);
    } catch (err) {
      console.error('Error loading cyber kill chain data:', err);
      setError('Failed to load cyber kill chain data');
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
          <p className="text-sm text-gray-400 mt-1">
            {killChainData.methodology} - 7 Phase Analysis
          </p>
        </div>
        
        <div className="flex items-center gap-3">
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
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
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
      </div>

      {/* Zigzag Kill Chain Roadmap */}
      <div className="bg-gray-900 rounded-lg shadow-sm border border-gray-700 p-8 overflow-x-auto">
        <h3 className="text-lg font-semibold text-gray-200 mb-8">Kill Chain Progression</h3>
        
        <div className="relative" style={{ minHeight: '600px' }}>
          {/* Zigzag Path */}
          <svg 
            className="absolute inset-0 w-full h-full pointer-events-none" 
            style={{ minHeight: '600px' }}
          >
            {killChainData.phases.map((phase, index) => {
              if (index === killChainData.phases.length - 1) return null;
              
              const isEven = index % 2 === 0;
              const startX = index * 180 + 90;
              const startY = isEven ? 120 : 380;
              const endX = (index + 1) * 180 + 90;
              const endY = isEven ? 380 : 120;
              
              const currentActive = phase.total_detections > 0;
              const nextActive = killChainData.phases[index + 1].total_detections > 0;
              const currentColor = getCoverageColor(phase.coverage_percentage).color;
              const nextColor = getCoverageColor(killChainData.phases[index + 1].coverage_percentage).color;
              
              return (
                <g key={`line-${index}`}>
                  <defs>
                    <linearGradient id={`gradient-${index}`} x1="0%" y1="0%" x2="100%" y2="0%">
                      <stop offset="0%" stopColor={currentActive ? currentColor : '#4b5563'} />
                      <stop offset="100%" stopColor={nextActive ? nextColor : '#4b5563'} />
                    </linearGradient>
                  </defs>
                  <path
                    d={`M ${startX} ${startY} Q ${startX + 60} ${(startY + endY) / 2}, ${endX} ${endY}`}
                    fill="none"
                    stroke={currentActive || nextActive ? `url(#gradient-${index})` : '#4b5563'}
                    strokeWidth="3"
                    strokeDasharray={currentActive || nextActive ? '0' : '8 4'}
                    opacity={currentActive || nextActive ? '0.8' : '0.3'}
                  />
                </g>
              );
            })}
          </svg>

          {/* Phase Nodes */}
          <div className="relative flex justify-start gap-8" style={{ minWidth: 'max-content' }}>
            {killChainData.phases.map((phase, index) => {
              const coverageColor = getCoverageColor(phase.coverage_percentage);
              const threatLevel = getPhaseThreadLevel(phase);
              const phaseDesc = getPhaseDescription(phase.phase_id);
              const isActive = phase.total_detections > 0;
              const isSelected = selectedPhase === phase.phase_id;
              const isEven = index % 2 === 0;

              return (
                <div 
                  key={phase.phase_id} 
                  className="relative flex flex-col items-center"
                  style={{ 
                    width: '160px',
                    marginTop: isEven ? '0' : '260px'
                  }}
                >
                  {/* Circle Node - ใหญ่ขึ้น */}
                  <div className="relative z-10 mb-6">
                    <div
                      onClick={() => setSelectedPhase(phase.phase_id)}
                      className={`w-24 h-24 rounded-full flex items-center justify-center text-4xl shadow-xl cursor-pointer transition-all ${
                        isSelected 
                          ? 'scale-110' 
                          : 'hover:scale-105'
                      }`}
                      style={{
                        backgroundColor: isActive ? coverageColor.color : '#4b5563',
                        boxShadow: isActive 
                          ? `0 0 30px ${coverageColor.color}60, 0 10px 20px rgba(0,0,0,0.3)`
                          : '0 10px 20px rgba(0,0,0,0.3)',
                        border: isActive ? `4px solid ${coverageColor.color}40` : '4px solid #6b7280'
                      }}
                    >
                      {phaseDesc.icon}
                    </div>
                    
                    {/* Status Indicator */}
                    <div className="absolute -top-2 -right-2">
                      {isActive ? (
                        <CheckCircle2 
                          className="w-8 h-8 bg-gray-900 rounded-full" 
                          style={{ color: coverageColor.color }}
                        />
                      ) : (
                        <XCircle className="w-8 h-8 text-gray-500 bg-gray-900 rounded-full" />
                      )}
                    </div>

                    {/* Phase Number */}
                    <div className="absolute -bottom-3 left-1/2 transform -translate-x-1/2">
                      <span className="inline-flex items-center justify-center w-8 h-8 rounded-full bg-blue-600 text-white text-sm font-bold shadow-lg">
                        {index + 1}
                      </span>
                    </div>
                  </div>

                  {/* Phase Info */}
                  <div className="text-center space-y-3 w-full">
                    <div>
                      <h4 className="font-semibold text-gray-200 text-sm">
                        {phase.phase_name}
                      </h4>
                      <p className="text-xs text-gray-400">
                        {phase.phase_name_th}
                      </p>
                    </div>

                    {/* Metrics */}
                    <div className="space-y-2 bg-gray-800 rounded-lg p-3 border border-gray-700">
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
                          style={{ color: coverageColor.color }}
                        >
                          {phase.coverage_percentage.toFixed(0)}%
                        </div>
                        <div className="text-xs text-gray-400">coverage</div>
                      </div>
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
        <div className="bg-gray-900 rounded-lg shadow-sm border border-gray-700 p-6">
          <div className="flex items-center gap-3 pb-4 border-b border-gray-200 mb-6">
            <span className="text-3xl">
              {getPhaseDescription(selectedPhaseData.phase_id).icon}
            </span>
            <div className="flex-1">
              <h3 className="text-lg font-semibold text-gray-200">
                {selectedPhaseData.phase_name} ({selectedPhaseData.phase_name_th})
              </h3>
              <p className="text-sm text-gray-400 mt-1">
                {getPhaseDescription(selectedPhaseData.phase_id).th}
              </p>
            </div>
            <button
              onClick={() => setSelectedPhase(null)}
              className="text-gray-400 hover:text-gray-300"
            >
              <ChevronUp className="w-5 h-5" />
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Top Techniques */}
            <div>
              <h4 className="text-sm font-semibold text-gray-300 mb-3 flex items-center gap-2">
                <TrendingUp className="w-4 h-4 text-blue-600" />
                Top Techniques
              </h4>
              <div className="space-y-2">
                {selectedPhaseData.top_techniques.length > 0 ? (
                  selectedPhaseData.top_techniques.map((tech) => (
                    <div 
                      key={tech.technique_id}
                      className="bg-gray-50 rounded-lg p-3 border border-gray-200"
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span className="font-medium text-gray-900 text-sm">
                          {tech.technique_id}
                        </span>
                        <span className="text-sm font-bold text-blue-600">
                          {tech.count.toLocaleString()}
                        </span>
                      </div>
                      <div className="text-xs text-gray-600">
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
                  <p className="text-sm text-gray-300 italic">
                    No techniques detected
                  </p>
                )}
              </div>
            </div>

            {/* Sources */}
            <div>
              <h4 className="text-sm font-semibold text-gray-200 mb-3 flex items-center gap-2">
                <Eye className="w-4 h-4 text-green-600" />
                Detection Sources
              </h4>
              <div className="space-y-2">
                {Object.entries(selectedPhaseData.sources).map(([source, count]) => (
                  <div 
                    key={source}
                    className="bg-gray-50 rounded-lg p-3 border border-gray-200"
                  >
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm text-gray-300 font-medium truncate">
                        {source}
                      </span>
                      <span className="text-sm font-bold text-gray-900 ml-2">
                        {count.toLocaleString()}
                      </span>
                    </div>
                    <div className="w-full bg-gray-200 rounded-full h-1.5">
                      <div 
                        className="bg-green-600 h-1.5 rounded-full"
                        style={{ 
                          width: `${(count / selectedPhaseData.total_detections) * 100}%` 
                        }}
                      />
                    </div>
                  </div>
                ))}
                {Object.keys(selectedPhaseData.sources).length === 0 && (
                  <p className="text-sm text-gray-300 italic">No sources</p>
                )}
              </div>

              {/* MITRE Mapping */}
              {selectedPhaseData.mitre_tactics && selectedPhaseData.mitre_tactics.length > 0 && (
                <div className="mt-4">
                  <h4 className="text-sm font-semibold text-gray-700 mb-2">
                    MITRE Tactics
                  </h4>
                  <div className="flex flex-wrap gap-2">
                    {selectedPhaseData.mitre_tactics.map((tactic) => (
                      <span
                        key={tactic}
                        className="inline-flex items-center px-2 py-1 rounded bg-blue-100 text-blue-700 text-xs font-medium"
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
              className="mt-6 rounded-lg p-4 border"
              style={{
                backgroundColor: getPhaseThreadLevel(selectedPhaseData).color + '10',
                borderColor: getPhaseThreadLevel(selectedPhaseData).color + '40'
              }}
            >
              <p 
                className="text-sm font-medium"
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
              <ChevronUp className="w-5 h-5" />
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

export default KillChainDashboard;