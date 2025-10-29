import React, { useEffect, useState } from 'react';
import { 
  Activity, 
  TrendingUp, 
  Shield, 
  AlertTriangle, 
  Clock, 
  Filter, 
  Target, 
  Eye, 
  Zap,
  ChevronDown,
  ChevronUp,
  Download,
  Search,
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

const KillChainCircular: React.FC<KillChainDashboardProps> = ({ 
  selectedIndices, 
  dayRange,
  onDayRangeChange 
}) => {
  const [loading, setLoading] = useState(true);
  const [killChainData, setKillChainData] = useState<CyberKillChainResponse | null>(null);
  const [timeFilter, setTimeFilter] = useState(dayRange);
  const [error, setError] = useState<string | null>(null);
  const [expandedPhase, setExpandedPhase] = useState<string | null>(null);
  const [sortBy, setSortBy] = useState<'activity' | 'coverage'>('activity');
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
  
  const sortedPhases = sortBy === 'activity' 
    ? sortPhasesByActivity(killChainData.phases)
    : sortPhasesByCoverage(killChainData.phases);

  const getRiskLevelColor = (level: string) => {
    switch (level) {
      case 'critical': return 'text-red-600 bg-red-100';
      case 'high': return 'text-orange-600 bg-orange-100';
      case 'medium': return 'text-yellow-600 bg-yellow-100';
      case 'low': return 'text-blue-600 bg-blue-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-gray-900 flex items-center gap-2">
            <Target className="w-7 h-7 text-blue-600" />
            Cyber Kill Chain Coverage
          </h2>
          <p className="text-sm text-gray-600 mt-1">
            {killChainData.methodology} - 7 Phase Analysis
          </p>
        </div>
        
        <div className="flex items-center gap-3">
          {/* Time Filter */}
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

          {/* Sort */}
          <select
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value as 'activity' | 'coverage')}
            className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="activity">Sort by Activity</option>
            <option value="coverage">Sort by Coverage</option>
          </select>

          {/* Export */}
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
              <p className="text-xs text-red-600 mt-2">
                This pattern suggests an ongoing coordinated attack. Immediate investigation recommended.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Active Phases */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm text-gray-600">Active Phases</span>
            <Activity className="w-4 h-4 text-blue-600" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold text-gray-900">{summary.activePhases}</span>
            <span className="text-sm text-gray-500">/ {summary.totalPhases}</span>
          </div>
          <div className="mt-2 text-xs text-gray-600">
            {summary.completionPercentage.toFixed(0)}% kill chain completion
          </div>
        </div>

        {/* Total Detections */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm text-gray-600">Total Detections</span>
            <Zap className="w-4 h-4 text-orange-600" />
          </div>
          <div className="text-2xl font-bold text-gray-900">
            {summary.totalDetections.toLocaleString()}
          </div>
          <div className="mt-2 text-xs text-gray-600">
            {summary.uniqueTechniques} unique techniques
          </div>
        </div>

        {/* Average Coverage */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm text-gray-600">Avg Coverage</span>
            <Shield className="w-4 h-4 text-green-600" />
          </div>
          <div className="text-2xl font-bold text-gray-900">
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

        {/* Risk Level */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm text-gray-600">Risk Level</span>
            <AlertTriangle className="w-4 h-4 text-red-600" />
          </div>
          <div className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ${getRiskLevelColor(report.riskLevel)}`}>
            {report.riskLevel.toUpperCase()}
          </div>
          <div className="mt-2 text-xs text-gray-600">
            {report.keyFindings.length} key findings
          </div>
        </div>
      </div>

      {/* Executive Report */}
      {showReport && (
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-gray-900">Executive Summary</h3>
            <button
              onClick={() => setShowReport(false)}
              className="text-gray-500 hover:text-gray-700"
            >
              <ChevronUp className="w-5 h-5" />
            </button>
          </div>
          
          <p className="text-gray-700 mb-4">{report.executiveSummary}</p>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <h4 className="font-semibold text-gray-900 mb-2">Key Findings</h4>
              <ul className="space-y-2">
                {report.keyFindings.map((finding, idx) => (
                  <li key={idx} className="flex items-start gap-2 text-sm text-gray-700">
                    <span className="text-blue-600 mt-1">•</span>
                    <span>{finding}</span>
                  </li>
                ))}
              </ul>
            </div>
            
            <div>
              <h4 className="font-semibold text-gray-900 mb-2">Recommendations</h4>
              <ul className="space-y-2">
                {report.recommendations.map((rec, idx) => (
                  <li key={idx} className="flex items-start gap-2 text-sm text-gray-700">
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

      {/* Kill Chain Phases */}
      <div className="space-y-3">
        {sortedPhases.map((phase, index) => {
          const coverageColor = getCoverageColor(phase.coverage_percentage);
          const threatLevel = getPhaseThreadLevel(phase);
          const phaseDesc = getPhaseDescription(phase.phase_id);
          const isExpanded = expandedPhase === phase.phase_id;

          return (
            <div
              key={phase.phase_id}
              className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden hover:shadow-md transition-shadow"
            >
              {/* Phase Header */}
              <div
                className="p-4 cursor-pointer"
                onClick={() => setExpandedPhase(isExpanded ? null : phase.phase_id)}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4 flex-1">
                    {/* Phase Number */}
                    <div className="flex items-center justify-center w-10 h-10 rounded-full bg-blue-100 text-blue-600 font-semibold">
                      {index + 1}
                    </div>

                    {/* Phase Info */}
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-1">
                        <span className="text-xl">{phaseDesc.icon}</span>
                        <h3 className="text-lg font-semibold text-gray-900">
                          {phase.phase_name}
                        </h3>
                        <span className="text-sm text-gray-500">
                          ({phase.phase_name_th})
                        </span>
                      </div>
                      <p className="text-sm text-gray-600">
                        {phaseDesc.th}
                      </p>
                    </div>

                    {/* Metrics */}
                    <div className="flex items-center gap-6">
                      {/* Detections */}
                      <div className="text-right">
                        <div className="text-2xl font-bold text-gray-900">
                          {phase.total_detections.toLocaleString()}
                        </div>
                        <div className="text-xs text-gray-500">detections</div>
                      </div>

                      {/* Techniques */}
                      <div className="text-right">
                        <div className="text-lg font-semibold text-gray-700">
                          {phase.techniques_detected} / {phase.available_techniques}
                        </div>
                        <div className="text-xs text-gray-500">techniques</div>
                      </div>

                      {/* Coverage */}
                      <div className="text-right min-w-[100px]">
                        <div 
                          className="text-lg font-bold"
                          style={{ color: coverageColor.color }}
                        >
                          {phase.coverage_percentage.toFixed(1)}%
                        </div>
                        <div className="text-xs" style={{ color: coverageColor.color }}>
                          {coverageColor.label}
                        </div>
                      </div>

                      {/* Threat Level */}
                      <div className="min-w-[120px]">
                        <div 
                          className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium"
                          style={{ 
                            backgroundColor: threatLevel.color + '20',
                            color: threatLevel.color 
                          }}
                        >
                          {threatLevel.label}
                        </div>
                      </div>
                    </div>

                    {/* Expand Icon */}
                    <button className="text-gray-400 hover:text-gray-600">
                      {isExpanded ? (
                        <ChevronUp className="w-5 h-5" />
                      ) : (
                        <ChevronDown className="w-5 h-5" />
                      )}
                    </button>
                  </div>
                </div>

                {/* Progress Bar */}
                <div className="mt-3">
                  <div className="w-full bg-gray-200 rounded-full h-2">
                    <div 
                      className="h-2 rounded-full transition-all"
                      style={{ 
                        width: `${phase.coverage_percentage}%`,
                        backgroundColor: coverageColor.color 
                      }}
                    />
                  </div>
                </div>
              </div>

              {/* Expanded Details */}
              {isExpanded && (
                <div className="border-t border-gray-200 bg-gray-50 p-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    {/* Top Techniques */}
                    <div>
                      <h4 className="font-semibold text-gray-900 mb-3 flex items-center gap-2">
                        <TrendingUp className="w-4 h-4 text-blue-600" />
                        Top Techniques
                      </h4>
                      <div className="space-y-2">
                        {phase.top_techniques.length > 0 ? (
                          phase.top_techniques.map((tech) => (
                            <div 
                              key={tech.technique_id}
                              className="bg-white rounded-lg p-3 border border-gray-200"
                            >
                              <div className="flex items-center justify-between mb-1">
                                <span className="font-medium text-gray-900 text-sm">
                                  {tech.technique_id}
                                </span>
                                <span className="text-lg font-bold text-blue-600">
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
                          <div className="text-sm text-gray-500 italic">
                            No techniques detected in this phase
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Sources */}
                    <div>
                      <h4 className="font-semibold text-gray-900 mb-3 flex items-center gap-2">
                        <Eye className="w-4 h-4 text-green-600" />
                        Detection Sources
                      </h4>
                      <div className="space-y-2">
                        {Object.entries(phase.sources).map(([source, count]) => (
                          <div 
                            key={source}
                            className="bg-white rounded-lg p-3 border border-gray-200"
                          >
                            <div className="flex items-center justify-between">
                              <span className="text-sm text-gray-700 font-medium">
                                {source}
                              </span>
                              <span className="text-sm font-bold text-gray-900">
                                {count.toLocaleString()}
                              </span>
                            </div>
                            <div className="mt-2">
                              <div className="w-full bg-gray-200 rounded-full h-1.5">
                                <div 
                                  className="bg-green-600 h-1.5 rounded-full"
                                  style={{ 
                                    width: `${(count / phase.total_detections) * 100}%` 
                                  }}
                                />
                              </div>
                            </div>
                          </div>
                        ))}
                        {Object.keys(phase.sources).length === 0 && (
                          <div className="text-sm text-gray-500 italic">
                            No sources detected
                          </div>
                        )}
                      </div>

                      {/* MITRE Tactics Mapping */}
                      {phase.mitre_tactics && phase.mitre_tactics.length > 0 && (
                        <div className="mt-4">
                          <h4 className="text-xs font-semibold text-gray-700 mb-2">
                            Mapped MITRE Tactics:
                          </h4>
                          <div className="flex flex-wrap gap-2">
                            {phase.mitre_tactics.map((tactic) => (
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

                  {/* Phase Description */}
                  <div className="mt-4 pt-4 border-t border-gray-200">
                    <p className="text-sm text-gray-600">
                      <span className="font-semibold">Description: </span>
                      {phaseDesc.en}
                    </p>
                    {threatLevel.level !== 'info' && (
                      <p className="text-sm mt-2" style={{ color: threatLevel.color }}>
                        <span className="font-semibold">⚠ Alert: </span>
                        {threatLevel.description}
                      </p>
                    )}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>

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
              <p className="text-xs text-yellow-600 mt-2">
                Consider enhancing detection capabilities for these phases to improve overall security posture.
              </p>
            </div>
          </div>
        </div>
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

export default KillChainCircular;