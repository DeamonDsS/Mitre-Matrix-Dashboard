import React, { useState, useEffect } from "react";
import { Shield, Search, RefreshCw, Calendar, Grid3x3, BarChart3, TrendingUp } from "lucide-react";
import TechniqueCard from "../../components/mitreCard/TechniqueCard";
import TechniqueModal from "../../components/mitreCard/TechniqueModal";
import type {
  MitreTacticFramework,
  MitreTechniqueFramework,
  TechniqueStatsFramework,
} from "../../types/mitre";
import { loadMitreData } from "../../components/mitreCard/mitreData";
import { getSeverityColor } from "../../components/mitreCard/mitreData";


// PostgreSQL service 
import {
  fetchPostgresStats,
  fetchPostgresSummaryStats,
  fetchPostgresAggregateStats,
  flattenTechniqueStats,
  type FlattenedTechniqueStats,
} from "../../services/postgreService";

import SummaryView, { type SummaryStats } from "../../components/mitreCard/SummaryView";
import type { SoloSummaryStats } from "../../services/multiMitreService";
import CoveragedashboardStat from "../killchain";

type ViewMode = "matrix" | "summary" | "kill chain";
type DataSourceType = "elasticsearch" | "postgresql";


const MitreAttackNavigator: React.FC = () => {
  const [selectedTechnique, setSelectedTechnique] =
    useState<MitreTechniqueFramework | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const [tactics, setTactics] = useState<MitreTacticFramework[]>([]);
  const [techniques, setTechniques] = useState<MitreTechniqueFramework[]>([]);
  const [techniqueStats, setTechniqueStats] = useState<FlattenedTechniqueStats>({});
  const [dateRange, setDateRange] = useState({
    start: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)
      .toISOString()
      .split("T")[0],
    end: new Date().toISOString().split("T")[0],
  });
  const [showDatePicker, setShowDatePicker] = useState(false);
  const [summaryStats, setSummaryStats] = useState<SummaryStats>({
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    tactics: [],
    sources: {},
  })
  const [stats, setStats] = useState<SoloSummaryStats>({
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    tactics: 0,
  });

  // Separate state for event-level severity (direct from events)
  const [eventStats, setEventStats] = useState<SoloSummaryStats>({
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    tactics: 0,
  });

  // Helper function to validate the stored view mode
  const getInitialViewMode = (): ViewMode => {
    const savedViewMode = localStorage.getItem("mitreViewMode");
    if (
      savedViewMode === "matrix" ||
      savedViewMode === "summary" ||
      savedViewMode === "kill chain"
    ) {
      return savedViewMode;
    }
    return "matrix";
  };

  const [viewMode, setViewMode] = useState<ViewMode>(getInitialViewMode());

  useEffect(() => {
    localStorage.setItem("mitreViewMode", viewMode);
  }, [viewMode]);

  const datePresets = [
    { label: "Last 24h", hours: 24 },
    { label: "Last 7d", days: 7 },
    { label: "Last 30d", days: 30 },
    { label: "Last 90d", days: 90 },
  ];

  // Data source type selection
  const [dataSourceType, setDataSourceType] = useState<DataSourceType>(
    () => (localStorage.getItem("dataSourceType") as DataSourceType) || "postgresql"
  );

  useEffect(() => {
    localStorage.setItem("dataSourceType", dataSourceType);
  }, [dataSourceType]);

  // Elasticsearch index - single index now
  const ES_INDEX = "rtarf-events-beat-*";

  // Helper function to check if a technique is a parent (no dot in ID)
  const isParentTechnique = (techniqueId: string): boolean => {
    return !techniqueId.includes('.');
  };


  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      const dateDropdown = document.getElementById("date-dropdown");

      if (dateDropdown && !dateDropdown.contains(event.target as Node)) {
        setShowDatePicker(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    setLoading(true);
    try {
      const { tactics: tacticsData, techniques: techniquesData } =
        await loadMitreData();

      setTactics(tacticsData);
      setTechniques(techniquesData);

      await loadStats(techniquesData);
      await loadOverallStats();
    } catch (error) {
      console.error("Error loading data:", error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadOverallStats();
  }, [dateRange]);

  // Load technique statistics
  const loadStats = async (_techniquesData: MitreTechniqueFramework[]) => {
    try {
      
        console.log("🚀 Fetching stats from PostgreSQL using aggregate endpoint");

        const dayRange = getDaysInRange();

        // Use the aggregate stats endpoint
        const aggregateResponse = await fetchPostgresAggregateStats({
          dayRange: dayRange,
          search: searchTerm || undefined,
          tactic: "all",
          severity: severityFilter === "all" ? "all" : severityFilter,
          includeSubTechniques: true,
          includeCrowdStrikeSpecific: false,
        });

        // Flatten the response for TechniqueCard compatibility
        const flattenedStats = flattenTechniqueStats(aggregateResponse);
        setTechniqueStats(flattenedStats);

        console.log("✅ Loaded stats from aggregate endpoint:", {
          total: aggregateResponse.total,
          techniquesCount: Object.keys(aggregateResponse.techniques).length,
          severityCounts: aggregateResponse.severityCounts,
        });

    } catch (error) {
      console.error("Error loading stats:", error);
      setTechniqueStats({});
    }
  };

  // Load overall statistics
  const loadOverallStats = async () => {
    try {
      const dayRange = getDaysInRange();

        console.log("🚀 Fetching overall stats from PostgreSQL");
        // Get calculated severity from aggregate endpoint (technique-based)
        const aggregateResponse = await fetchPostgresAggregateStats({
          dayRange: dayRange,
          search: undefined,
          tactic: "all",
          severity: "all",
          includeSubTechniques: true,
          includeCrowdStrikeSpecific: false,
        });

        // Get direct event severity from stats endpoint
        const eventStatsData = await fetchPostgresStats({
          search: undefined,
          tactic: "all",
          severity: "all",
          dayRange: dayRange,
        });

        const sumstatsData = await fetchPostgresSummaryStats({
          search: undefined,
          tactic: "all",
          severity: "all",
          dayRange: dayRange,
        });

        setSummaryStats(sumstatsData);
        
        // Set calculated severity (from techniques)
        setStats({
          total: aggregateResponse.total,
          critical: aggregateResponse.severityCounts.critical,
          high: aggregateResponse.severityCounts.high,
          medium: aggregateResponse.severityCounts.medium,
          low: aggregateResponse.severityCounts.low,
          tactics: Object.keys(aggregateResponse.techniques).length,
        });

        // Set event-level severity (direct from events)
        setEventStats(eventStatsData);
     
    } catch (error) {
      console.error("Error loading overall stats:", error);
      setStats({
        total: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        tactics: 0,
      });
      setEventStats({
        total: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        tactics: 0,
      });
    }
  };

  // Reload stats when data source or date range changes
  useEffect(() => {
    if (techniques.length > 0) {
      loadStats(techniques);
      loadOverallStats();
    }
  }, [dataSourceType, dateRange]);

  const handleDatePreset = (preset: {
    label: string;
    hours?: number;
    days?: number;
  }) => {
    const end = new Date();
    const start = new Date();

    if (preset.hours) {
      start.setHours(start.getHours() - preset.hours);
    } else if (preset.days) {
      start.setDate(start.getDate() - preset.days);
    }

    setDateRange({
      start: start.toISOString().split("T")[0],
      end: end.toISOString().split("T")[0],
    });
  };

  const handleDateChange = (field: "start" | "end", value: string) => {
    setDateRange((prev) => ({
      ...prev,
      [field]: value,
    }));
  };

  const handleRefresh = async () => {
    setRefreshing(true);
    await loadStats(techniques);
    await loadOverallStats();
    setRefreshing(false);
  };

  const getDaysInRange = () => {
    const start = new Date(dateRange.start);
    const end = new Date(dateRange.end);
    const days = Math.ceil((end.getTime() - start.getTime()) / (1000 * 60 * 60 * 24));
    return days;
  };

  const filteredTechniques = techniques.filter((tech) => {
    const matchesSearch =
      tech.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      tech.id.toLowerCase().includes(searchTerm.toLowerCase());
    const stats = techniqueStats[tech.id];
    const matchesSeverity =
      severityFilter === "all" ||
      stats?.severity === severityFilter ||
      (severityFilter === "detected" && stats?.count > 0);
    return matchesSearch && matchesSeverity;
  });

  const getTechniquesForTactic = (tacticShortName: string) => {
    const allMatching = filteredTechniques.filter((tech) =>
      tech.tactics.some(
        (t) => t.toLowerCase() === tacticShortName.toLowerCase()
      )
    );

    return allMatching.filter(t => isParentTechnique(t.id));
  };

  const getSubTechniquesForParent = (parentId: string) => {
    // Get sub-techniques from the flattened stats
    const parentStats = techniqueStats[parentId];
    if (!parentStats?.subTechniques) {
      return [];
    }

    return parentStats.subTechniques
      .map(sub => {
        // Find the full technique object
        const subTechnique = techniques.find(t => t.id === sub.id);
        
        // Only return if we found the technique definition
        if (!subTechnique) {
          console.warn(`Sub-technique ${sub.id} not found in techniques list`);
          return null;
        }

        return {
          technique: subTechnique,
          stats: {
            count: sub.count,
            severity: sub.severity,
            lastSeen: sub.lastSeen,
          }
        };
      })
      .filter((item): item is { technique: MitreTechniqueFramework; stats: TechniqueStatsFramework } => item !== null);
  };

  const detectedCount = techniques.filter((tech) => {
    const stats = techniqueStats[tech.id];
    return stats && stats.count > 0;
  }).length;

  const parentTechniquesCount = techniques.filter(t => isParentTechnique(t.id)).length;

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-500 mx-auto mb-3"></div>
          <p className="text-white">Loading MITRE ATT&CK</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-900 p-4">
      <div className="max-w-[1600px] mx-auto space-y-4">
        <div className="bg-gray-800 rounded-lg shadow-xl p-4">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-red-600 rounded flex items-center justify-center">
                <Shield className="w-6 h-6 text-white" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-white">
                  MITRE ATT&CK Navigator
                </h1>
                <p className="text-gray-400 text-xs">
                  {parentTechniquesCount} Parent Techniques ({techniques.length} total with sub-techniques)
                </p>
              </div>
            </div>
            <div className="flex gap-2">
              {/* Data Source Type Selector */}
              <div className="flex bg-gray-700 rounded overflow-hidden">
                <button
                  onClick={() => setDataSourceType("postgresql")}
                  className={`px-3 py-1.5 text-sm font-medium transition-colors ${dataSourceType === "postgresql"
                    ? "bg-red-600 text-white"
                    : "text-gray-300 hover:bg-gray-600"
                    }`}
                >
                  PostgreSQL
                </button>
              </div>

              <div className="relative" id="date-dropdown">
                <button
                  onClick={() => setShowDatePicker(!showDatePicker)}
                  className="px-3 py-1.5 bg-gray-700 text-white rounded hover:bg-gray-600 transition-colors flex items-center gap-2 text-sm"
                >
                  <Calendar className="w-4 h-4" />
                  {getDaysInRange()}d
                </button>

                {showDatePicker && (
                  <div className="absolute right-0 mt-2 bg-gray-700 rounded-lg shadow-xl p-4 z-50 w-80">
                    <div className="mb-3">
                      <div className="text-white text-sm font-bold mb-2">
                        Quick Select
                      </div>
                      <div className="grid grid-cols-2 gap-2">
                        {datePresets.map((preset) => (
                          <button
                            key={preset.label}
                            onClick={() => handleDatePreset(preset)}
                            className="px-3 py-1.5 bg-gray-600 text-white rounded hover:bg-gray-500 transition-colors text-xs"
                          >
                            {preset.label}
                          </button>
                        ))}
                      </div>
                    </div>

                    <div className="space-y-3">
                      <div>
                        <label className="text-white text-xs mb-1 block">
                          Start Date
                        </label>
                        <input
                          type="date"
                          value={dateRange.start}
                          onChange={(e) =>
                            handleDateChange("start", e.target.value)
                          }
                          max={dateRange.end}
                          className="w-full px-3 py-1.5 bg-gray-600 border border-gray-500 rounded text-white text-sm focus:outline-none focus:ring-1 focus:ring-red-500"
                        />
                      </div>
                      <div>
                        <label className="text-white text-xs mb-1 block">
                          End Date
                        </label>
                        <input
                          type="date"
                          value={dateRange.end}
                          onChange={(e) =>
                            handleDateChange("end", e.target.value)
                          }
                          min={dateRange.start}
                          max={new Date().toISOString().split("T")[0]}
                          className="w-full px-3 py-1.5 bg-gray-600 border border-gray-500 rounded text-white text-sm focus:outline-none focus:ring-1 focus:ring-red-500"
                        />
                      </div>
                      <button
                        onClick={() => {
                          setShowDatePicker(false);
                          handleRefresh();
                        }}
                        className="w-full px-3 py-2 bg-red-600 text-white rounded hover:bg-red-700 transition-colors text-sm font-medium"
                      >
                        Apply Date Range
                      </button>
                    </div>
                  </div>
                )}
              </div>

              <button
                onClick={handleRefresh}
                disabled={refreshing}
                className="px-3 py-1.5 bg-gray-700 text-white rounded hover:bg-gray-600 transition-colors flex items-center gap-2 text-sm disabled:opacity-50"
              >
                <RefreshCw
                  className={`w-4 h-4 ${refreshing ? "animate-spin" : ""}`}
                />
                Refresh
              </button>
            </div>
          </div>

          {/* View Mode Tabs */}
          <div className="flex gap-2 mb-4 border-b border-gray-700">
            <button
              onClick={() => setViewMode("matrix")}
              className={`flex items-center gap-2 px-4 py-2 text-sm font-medium transition-colors ${viewMode === "matrix"
                ? "text-white border-b-2 border-red-500"
                : "text-gray-400 hover:text-white"
                }`}
            >
              <Grid3x3 className="w-4 h-4" />
              Matrix View
            </button>
            <button
              onClick={() => setViewMode("summary")}
              className={`flex items-center gap-2 px-4 py-2 text-sm font-medium transition-colors ${viewMode === "summary"
                ? "text-white border-b-2 border-red-500"
                : "text-gray-400 hover:text-white"
                }`}
            >
              <BarChart3 className="w-4 h-4" />
              Analytics
            </button>
            <button
              onClick={() => setViewMode("kill chain")}
              className={`flex items-center gap-2 px-4 py-2 text-sm font-medium transition-colors ${viewMode === "kill chain"
                ? "text-white border-b-2 border-red-500"
                : "text-gray-400 hover:text-white"
                }`}
            >
              <TrendingUp className="w-4 h-4" />
              Kill Chain Statistics
            </button>
          </div>

          {/* Data Source Info */}
          <div className="bg-gray-900 rounded p-3 mb-4">
            <div className="text-gray-400 text-xs mb-2 font-semibold">
              Active Data Source
            </div>
            <div className="bg-gray-800 rounded p-2 flex justify-between items-center">
              <span className="text-white text-sm">
                {dataSourceType === "postgresql" ? "PostgreSQL (rtarf_event table)" : "Elasticsearch (rtarf-events-beat-*)"}
              </span>
              <span className="text-red-400 font-bold text-sm">
                {stats.total.toLocaleString()} events
              </span>
            </div>
          </div>

          {(viewMode === "matrix" || viewMode === "summary") && (
            <div className="grid grid-cols-3 gap-3 mb-4">
              <div className="bg-gray-900 rounded p-3">
                <div className="text-gray-400 text-xs mb-1">
                  Detected Events ({getDaysInRange()} Days)
                </div>
                <div className="text-2xl font-bold text-white">
                  {stats.total.toLocaleString()}
                </div>
              </div>
              <div className="bg-gray-900 rounded p-3">
                <div className="text-gray-400 text-xs mb-1">Data Source</div>
                <div className="text-2xl font-bold text-white">
                  {dataSourceType === "postgresql" ? "PostgreSQL" : "Elasticsearch"}
                </div>
              </div>
              <div className="bg-gray-900 rounded p-3">
                <div className="text-gray-400 text-xs mb-1">
                  Techniques Detected
                </div>
                <div className="text-2xl font-bold text-white">
                  {detectedCount} / {techniques.length}
                </div>
              </div>
            </div>
          )}

          
          {/* Severity from event logs */}
          {viewMode === "matrix" && (
            <div className="grid grid-cols-4 gap-3 mb-4">
              <div className="bg-gray-900 rounded p-3">
                <div className="text-gray-400 text-xs mb-1">
                  Critical Severity (Event)
                </div>
                <div className="text-2xl font-bold text-white">
                  {eventStats.critical.toLocaleString()}
                </div>
              </div>
              <div className="bg-gray-900 rounded p-3">
                <div className="text-gray-400 text-xs mb-1">High Severity (Event)</div>
                <div className="text-2xl font-bold text-white">
                  {eventStats.high.toLocaleString()}
                </div>
              </div>
              <div className="bg-gray-900 rounded p-3">
                <div className="text-gray-400 text-xs mb-1">Medium Severity (Event)</div>
                <div className="text-2xl font-bold text-white">
                  {eventStats.medium.toLocaleString()}
                </div>
              </div>
              <div className="bg-gray-900 rounded p-3">
                <div className="text-gray-400 text-xs mb-1">Low Severity (Event)</div>
                <div className="text-2xl font-bold text-white">
                  {eventStats.low.toLocaleString()}
                </div>
              </div>
            </div>
          )}


          {/* Calculated severity from techniques and sub-techniques */}
          {viewMode === "matrix" && (
            <div className="grid grid-cols-4 gap-3 mb-4">
              <div className="bg-gray-900 rounded p-3">
                <div className="text-gray-400 text-xs mb-1">
                  Critical Severity (Calculated)
                </div>
                <div className="text-2xl font-bold text-white">
                  {stats.critical.toLocaleString()}
                </div>
              </div>
              <div className="bg-gray-900 rounded p-3">
                <div className="text-gray-400 text-xs mb-1">High Severity (Calculated)</div>
                <div className="text-2xl font-bold text-white">
                  {stats.high.toLocaleString()}
                </div>
              </div>
              <div className="bg-gray-900 rounded p-3">
                <div className="text-gray-400 text-xs mb-1">Medium Severity (Calculated)</div>
                <div className="text-2xl font-bold text-white">
                  {stats.medium.toLocaleString()}
                </div>
              </div>
              <div className="bg-gray-900 rounded p-3">
                <div className="text-gray-400 text-xs mb-1">Low Severity (Calculated)</div>
                <div className="text-2xl font-bold text-white">
                  {stats.low.toLocaleString()}
                </div>
              </div>
            </div>
          )}

          {viewMode === "matrix" && (
            <div className="flex gap-2">
              <div className="flex-1 relative">
                <Search className="absolute left-2 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
                <input
                  type="text"
                  placeholder="Search techniques..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full pl-8 pr-3 py-1.5 bg-gray-900 border border-gray-700 rounded text-white text-sm placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-red-500"
                />
              </div>
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="px-3 py-1.5 bg-gray-900 border border-gray-700 rounded text-white text-sm focus:outline-none focus:ring-1 focus:ring-red-500"
              >
                <option value="all">All</option>
                <option value="detected">Detected</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
          )}

          {viewMode === "matrix" && (
            <div className="mt-3 flex items-center gap-4 text-xs">
              <span className="text-gray-400">Severity:</span>
              {["critical", "high", "medium", "low", "none"].map((sev) => (
                <div key={sev} className="flex items-center gap-1.5">
                  <div
                    className={`w-3 h-3 rounded ${getSeverityColor(sev)}`}
                  ></div>
                  <span className="text-gray-300 capitalize">{sev}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {viewMode === "matrix" && (
          <div className="bg-gray-800 rounded-lg shadow-xl p-3 overflow-x-auto">
            <div className="min-w-[1600px]">
              <div
                className="gap-1.5 mb-1.5"
                style={{
                  display: "grid",
                  gridTemplateColumns: `repeat(${tactics.length}, minmax(0, 1fr))`,
                }}
              >
                {tactics.map((tactic) => {
                  const tacticTechCount = getTechniquesForTactic(tactic.shortName).length;
                  const detectedInTactic = getTechniquesForTactic(tactic.shortName).filter(
                    tech => {
                      const parentDetected = techniqueStats[tech.id]?.count > 0;
                      const subDetected = getSubTechniquesForParent(tech.id).some(
                        sub => sub.stats.count > 0
                      );
                      return parentDetected || subDetected;
                    }
                  ).length;

                  return (
                    <div
                      key={tactic.id}
                      className="bg-red-600 rounded-t p-2 text-center"
                      title={`${tactic.description}\n\nParent Techniques: ${tacticTechCount}\nDetected: ${detectedInTactic}`}
                    >
                      <div className="text-white font-bold text-[10px] leading-tight mb-1">
                        {tactic.name}
                      </div>
                      <div className="text-white text-[9px] opacity-90">
                        {detectedInTactic}/{tacticTechCount}
                      </div>
                    </div>
                  );
                })}
              </div>

              <div
                className="gap-1.5"
                style={{
                  display: "grid",
                  gridTemplateColumns: `repeat(${tactics.length}, minmax(0, 1fr))`,
                }}
              >
                {tactics.map((tactic) => {
                  const tacticTechniques = getTechniquesForTactic(
                    tactic.shortName
                  );
                  return (
                    <div key={tactic.id} className="space-y-1.5">
                      {tacticTechniques.map((tech) => {
                        const subTechniques = getSubTechniquesForParent(tech.id);
                        const techStats = techniqueStats[tech.id];
                        
                        return (
                          <TechniqueCard
                            key={tech.id}
                            technique={tech}
                            stats={{
                              count: techStats?.count || 0,
                              severity: techStats?.severity || "none",
                              lastSeen: techStats?.lastSeen || null,
                            }}
                            isSelected={selectedTechnique?.id === tech.id}
                            onClick={() => setSelectedTechnique(tech)}
                            subTechniques={subTechniques}
                            onSubTechniqueClick={(subTech) => setSelectedTechnique(subTech)}
                          />
                        );
                      })}
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        )}

        {viewMode === "summary" && (
          <div className="bg-gray-800 rounded-lg shadow-xl p-6">
            <div className="text-center text-gray-400 py-0">
              <SummaryView
                stats={summaryStats}
                loading={refreshing}
                dayRange={getDaysInRange()}
              />
            </div>
          </div>
        )}

        {viewMode === "kill chain" && (
          <div className="bg-gray-800 rounded-lg shadow-xl p-6">
              <div className="text-center text-gray-400 py-2">
                <CoveragedashboardStat
                  selectedIndices={ES_INDEX}
                  dayRange={getDaysInRange()}
            
                />
              </div>
          </div>
        )}
      </div>

      {selectedTechnique && (
        <TechniqueModal
          technique={selectedTechnique}
          stats={
            techniqueStats[selectedTechnique.id] || {
              count: 0,
              severity: "none",
              lastSeen: null,
            }
          }
          tactics={tactics}
          onClose={() => setSelectedTechnique(null)}
        />
      )}
    </div>
  );
};

export default MitreAttackNavigator;