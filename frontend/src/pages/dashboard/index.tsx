import React from "react";
import { useState, useEffect } from "react";
import {
  Shield,
  Activity,
  AlertTriangle,
  TrendingUp,
  Settings,
  RefreshCw,
  FileText,
  Target,
  ChevronLeft,
  ChevronRight,
  ClipboardCheck,
} from "lucide-react";
import TechniqueCard from "../../components/TechniqueCard";
import EventLogCard from "../../components/EventsLogCard";
import FilterBar from "../../components/FilterBar";
import StatsCard from "../../components/StatCard";
import ConfigModal from "../../components/ConfigModal";
import SummaryView from "../../components/SummaryView";
import type {
  MitreTechnique,
  FilterState,
  MitreStats,
} from "../../types/mitre";
import {
  fetchMitreTechniques,
  getMockData,
  fetchStats,
} from "../../services/elasticsearch";

type ViewMode = "mitre" | "events" | "summary";

const Dashboard: React.FC = () => {
  const [viewMode, setViewMode] = useState<ViewMode>("events");
  const [techniques, setTechniques] = useState<MitreTechnique[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [usingMockData, setUsingMockData] = useState(false);
  const [configModalOpen, setConfigModalOpen] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage, setItemsPerPage] = useState(9);
  const [totalItems, setTotalItems] = useState(0); // State ใหม่สำหรับเก็บ total
  const [esConfig, setEsConfig] = useState({
    esUrl: localStorage.getItem("esUrl") || "http://localhost:9200",
    esIndex: localStorage.getItem("esIndex") || ".ds-winlogbeat-9.1.5-*",
  });

  const [filters, setFilters] = useState<FilterState>({
    search: "",
    tactic: "all",
    severity: "all",
  });

  const [mstats, setmStats] = useState<MitreStats>({
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    tactics: 0,
  });

  const loadTechniques = async () => {
    setLoading(true);
    setError(null);
    try {
      if (esConfig.esUrl) {
        // 1. เรียก API พร้อมส่ง filter และ pagination state ปัจจุบัน
        const data = await fetchMitreTechniques(esConfig.esIndex, filters, {
          page: currentPage,
          size: itemsPerPage,
        });
        setTechniques(data.events);
        setTotalItems(data.total); // 2. อัปเดต total จาก response
        setUsingMockData(false);
      } else {
        throw new Error("No Elasticsearch URL configured");
      }
    } catch (err) {
      console.warn("Failed to fetch from Elasticsearch, using mock data:", err);
      setTechniques(getMockData());
      setUsingMockData(true);
      setError(
        "Using demo data. Configure Elasticsearch to connect to your data."
      );
    } finally {
      setLoading(false);
    }
  };

  const loadStats = async () => {
    try {
      if (esConfig.esUrl) {
        const statsData = await fetchStats(esConfig.esIndex, filters);
        setmStats(statsData);
      }
    } catch (err) {
      console.error("Failed to load stats", err);
    }
  };

  useEffect(() => {
    loadTechniques();
  }, [esConfig, filters, currentPage, itemsPerPage]);

  useEffect(() => {
    // โหลดเฉพาะ stats เมื่อ filter เปลี่ยน (ไม่ต้องรอ debounce)
    const timer = setTimeout(() => {
      loadStats();
    }, 500); // ใส่ debounce เล็กน้อย
    return () => clearTimeout(timer);
  }, [esConfig, filters]);

  const totalPages = Math.ceil(totalItems / itemsPerPage);

  const handleConfigSave = (config: { esUrl: string; esIndex: string }) => {
    localStorage.setItem("esUrl", config.esUrl);
    localStorage.setItem("esIndex", config.esIndex);
    setEsConfig(config);
  };

  const goToPage = (page: number) => {
    setCurrentPage(Math.max(1, Math.min(page, totalPages)));
  };

  const getPageNumbers = () => {
    const pages = [];
    const maxVisible = 5;

    if (totalPages <= maxVisible) {
      for (let i = 1; i <= totalPages; i++) {
        pages.push(i);
      }
    } else {
      if (currentPage <= 3) {
        for (let i = 1; i <= 4; i++) pages.push(i);
        pages.push("...");
        pages.push(totalPages);
      } else if (currentPage >= totalPages - 2) {
        pages.push(1);
        pages.push("...");
        for (let i = totalPages - 3; i <= totalPages; i++) pages.push(i);
      } else {
        pages.push(1);
        pages.push("...");
        pages.push(currentPage - 1);
        pages.push(currentPage);
        pages.push(currentPage + 1);
        pages.push("...");
        pages.push(totalPages);
      }
    }

    return pages;
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto px-4 py-8">
        {/* Header */}
        <div className="flex flex-col md:flex-row md:items-center md:justify-between mb-6">
          <div className="flex items-center gap-3 mb-4 md:mb-0">
            <div className="w-12 h-12 bg-gray-900 rounded-lg flex items-center justify-center">
              <Shield className="w-7 h-7 text-white" />
            </div>
            <div>
              <h1 className="text-2xl md:text-3xl font-bold text-gray-900">
                Security Events Dashboard
              </h1>
              <p className="text-sm text-gray-600">
                Real-time security monitoring
                {usingMockData && (
                  <span className="ml-2 text-orange-600 font-medium">
                    (Demo Mode)
                  </span>
                )}
              </p>
            </div>
          </div>

          <div className="flex gap-2">
            <button
              onClick={loadTechniques}
              disabled={loading}
              className="px-4 py-2 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors text-sm font-medium text-gray-700 flex items-center gap-2 disabled:opacity-50"
            >
              <RefreshCw
                className={`w-4 h-4 ${loading ? "animate-spin" : ""}`}
              />
              Refresh
            </button>
            <button
              onClick={() => setConfigModalOpen(true)}
              className="px-4 py-2 bg-gray-900 text-white rounded-lg hover:bg-gray-800 transition-colors text-sm font-medium flex items-center gap-2"
            >
              <Settings className="w-4 h-4" />
              Configure
            </button>
          </div>
        </div>

        {/* Tabs */}
        <div className="mb-6">
          <div className="border-b border-gray-200">
            <nav className="-mb-px flex space-x-8">
              <button
                onClick={() => setViewMode("events")}
                className={`py-4 px-1 border-b-2 font-medium text-sm flex items-center gap-2 transition-colors ${
                  viewMode === "events"
                    ? "border-gray-900 text-gray-900"
                    : "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300"
                }`}
              >
                <FileText className="w-4 h-4" />
                <div className="text-left">
                  <div>Windows Event Logs</div>
                  <div className="text-xs font-normal text-gray-500">
                    Raw event data
                  </div>
                </div>
              </button>
              <button
                onClick={() => setViewMode("mitre")}
                className={`py-4 px-1 border-b-2 font-medium text-sm flex items-center gap-2 transition-colors ${
                  viewMode === "mitre"
                    ? "border-gray-900 text-gray-900"
                    : "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300"
                }`}
              >
                <Target className="w-4 h-4" />
                <div className="text-left">
                  <div>MITRE ATT&CK View</div>
                  <div className="text-xs font-normal text-gray-500">
                    Threat intelligence
                  </div>
                </div>
              </button>
              <button
                onClick={() => setViewMode("summary")}
                className={`py-4 px-1 border-b-2 font-medium text-sm flex items-center gap-2 transition-colors ${
                  viewMode === "summary"
                    ? "border-gray-900 text-gray-900"
                    : "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300"
                }`}
              >
                <ClipboardCheck className="w-4 h-4" />
                <div className="text-left">
                  <div>Logs Summary</div>
                  <div className="text-xs font-normal text-gray-500">
                    summary of data
                  </div>
                </div>
              </button>
            </nav>
          </div>
        </div>

        {error && (
          <div className="mb-6 bg-orange-50 border border-orange-200 rounded-lg p-4 flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-orange-600 flex-shrink-0 mt-0.5" />
            <div>
              <p className="text-sm text-orange-800">{error}</p>
            </div>
          </div>
        )}

        {/* Stats Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
          <StatsCard
            title={viewMode === "events" ? "Total Events" : "Total Techniques"}
            value={mstats.total} // 6. ใช้ค่าจาก state โดยตรง
            icon={Activity}
            color="bg-gray-900"
          />
          <StatsCard
            title="Critical Severity"
            value={mstats.critical} // 6. ใช้ค่าจาก state โดยตรง
            icon={AlertTriangle}
            color="bg-red-500"
          />
          <StatsCard
            title="High Severity"
            value={mstats.high} // 6. ใช้ค่าจาก state โดยตรง
            icon={TrendingUp}
            color="bg-orange-500"
          />
          <StatsCard
            title={viewMode === "events" ? "Event Types" : "Unique Tactics"}
            value={mstats.tactics} // 6. ใช้ค่าจาก state โดยตรง
            icon={Shield}
            color="bg-blue-500"
          />
        </div>

        {/* Filters */}
        <FilterBar filters={filters} onFilterChange={setFilters} />

        {/* Pagination Controls - Top */}
        {!loading && techniques.length > 0 && (
          <div className="mb-4 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
            <div className="flex items-center gap-2">
              <span className="text-sm text-gray-600">Items per page:</span>
              <select
                value={itemsPerPage}
                onChange={(e) => {
                  setItemsPerPage(Number(e.target.value));
                  setCurrentPage(1);
                }}
                className="px-3 py-1.5 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-gray-900"
              >
                <option value={6}>6</option>
                <option value={9}>9</option>
                <option value={12}>12</option>
                <option value={24}>24</option>
                <option value={48}>48</option>
              </select>
            </div>
            <div className="text-sm text-gray-600">
              Showing {(currentPage - 1) * itemsPerPage + 1} to{" "}
              {Math.min(currentPage * itemsPerPage, techniques.length)} of{" "}
              {techniques.length} results
            </div>
          </div>
        )}

        {/* Content */}
        {loading && viewMode !== "summary" ? ( // Show spinner only for events/mitre view initially
          <div className="flex items-center justify-center py-20">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-gray-900"></div>
          </div>
        ) : viewMode === "summary" ? ( // 2. Render SummaryView when viewMode is 'summary'
          <SummaryView stats={mstats} loading={loading} />
        ) : techniques.length === 0 ? (
          <div className="text-center py-20">
            <Shield className="w-16 h-16 text-gray-300 mx-auto mb-4" />
            {/* 3. Update the "No found" message to include summary */}
            <h3 className="text-lg font-semibold text-gray-900 mb-2">
              No {viewMode === "events" ? "events" : "techniques"} found
            </h3>
            <p className="text-gray-600">
              Try adjusting your filters or search criteria
            </p>
          </div>
        ) : (
          <>
            {/* This part for 'events' and 'mitre' remains the same */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-6">
              {techniques.map((technique) =>
                viewMode === "events" ? (
                  <EventLogCard key={technique.id} event={technique} />
                ) : (
                  <TechniqueCard key={technique.id} technique={technique} />
                )
              )}
            </div>

            {/* Pagination Controls - Bottom */}
            {totalPages > 1 && (
              <div className="flex items-center justify-center gap-2">
                <button
                  onClick={() => goToPage(currentPage - 1)}
                  disabled={currentPage === 1}
                  className="px-3 py-2 border border-gray-300 rounded-lg hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                  aria-label="Previous page"
                >
                  <ChevronLeft className="w-4 h-4" />
                </button>

                {getPageNumbers().map((page, idx) =>
                  page === "..." ? (
                    <span
                      key={`ellipsis-${idx}`}
                      className="px-3 py-2 text-gray-500"
                    >
                      ...
                    </span>
                  ) : (
                    <button
                      key={page}
                      onClick={() => goToPage(page as number)}
                      className={`px-4 py-2 rounded-lg transition-colors ${
                        currentPage === page
                          ? "bg-gray-900 text-white"
                          : "border border-gray-300 hover:bg-gray-50"
                      }`}
                    >
                      {page}
                    </button>
                  )
                )}

                <button
                  onClick={() => goToPage(currentPage + 1)}
                  disabled={currentPage === totalPages}
                  className="px-3 py-2 border border-gray-300 rounded-lg hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                  aria-label="Next page"
                >
                  <ChevronRight className="w-4 h-4" />
                </button>
              </div>
            )}
          </>
        )}
      </div>

      <ConfigModal
        isOpen={configModalOpen}
        onClose={() => setConfigModalOpen(false)}
        onSave={handleConfigSave}
        currentConfig={esConfig}
      />
    </div>
  );
};

export default Dashboard;
