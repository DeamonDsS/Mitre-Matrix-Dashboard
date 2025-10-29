import React, { useState, useEffect } from "react";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, Cell } from "recharts";
import { Shield, TrendingUp, Activity, AlertCircle, Download, Filter } from "lucide-react";

// Types
interface TopTechniqueResult {
  technique_id: string;
  technique_name: string;
  count: number;
  tactic_ids: string[];
  tactic_names: string[];
  sources: Record<string, number>;
}

interface TopTechniquesResponse {
  techniques: TopTechniqueResult[];
  total_detections: number;
  time_range: {
    start: string;
    end: string;
  };
  limit: number;
  tactic_filter: string;
}

interface TopTechniquesViewProps {
  indices: string[];
  dayRange: number;
  loading: boolean;
}

// Color palette for bars
const COLORS = ["#ef4444", "#f97316", "#f59e0b", "#eab308", "#84cc16", "#22c55e", "#14b8a6", "#06b6d4", "#3b82f6", "#6366f1"];

const TopTechniquesView: React.FC<TopTechniquesViewProps> = ({
  indices,
  dayRange,
  loading: parentLoading,
}) => {
  const [data, setData] = useState<TopTechniquesResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedBar, setSelectedBar] = useState<string | null>(null);
  const [limit, setLimit] = useState(10);
  const [tacticFilter, setTacticFilter] = useState("all");

  const tacticOptions = [
    { value: "all", label: "All Tactics" },
    { value: "TA0001", label: "Initial Access" },
    { value: "TA0002", label: "Execution" },
    { value: "TA0003", label: "Persistence" },
    { value: "TA0004", label: "Privilege Escalation" },
    { value: "TA0005", label: "Defense Evasion" },
    { value: "TA0006", label: "Credential Access" },
    { value: "TA0007", label: "Discovery" },
    { value: "TA0008", label: "Lateral Movement" },
    { value: "TA0009", label: "Collection" },
    { value: "TA0010", label: "Exfiltration" },
    { value: "TA0011", label: "Command and Control" },
    { value: "TA0040", label: "Impact" },
  ];

  const fetchData = async () => {
    try {
      setLoading(true);
      setError(null);

      const BACKEND_API_URL = import.meta.env.VITE_BACKEND_URL || "http://localhost:8000";

      // Filter out Windows indices
      const validIndices = indices.filter((idx) => {
        const indexLower = idx.toLowerCase();
        return !indexLower.includes("windows") && !indexLower.includes("winlog");
      });

      if (validIndices.length === 0) {
        setError("No valid indices selected");
        setLoading(false);
        return;
      }

      const response = await fetch(`${BACKEND_API_URL}/api/unified/top-techniques`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          indices: validIndices,
          dayRange,
          limit,
          tactic: tacticFilter,
        }),
      });

      if (!response.ok) {
        throw new Error(`API error: ${response.status}`);
      }

      const result = await response.json();
      setData(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch data");
      console.error("Error fetching top techniques:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [indices, dayRange, limit, tacticFilter]);

  // Transform data for recharts
  const chartData =
    data?.techniques.map((tech, idx) => ({
      name: tech.technique_id,
      fullName: tech.technique_name,
      count: tech.count,
      tactics: tech.tactic_names.join(", "),
      color: COLORS[idx % COLORS.length],
      sources: tech.sources,
    })) || [];

  // Custom tooltip
  const CustomTooltip = ({ active, payload }: any) => {
    if (active && payload && payload.length) {
      const data = payload[0].payload;
      return (
        <div className="bg-gray-900 border border-gray-700 rounded-lg p-4 shadow-xl max-w-sm">
          <p className="text-white font-bold mb-2">{data.name}</p>
          <p className="text-gray-300 text-sm mb-2">{data.fullName}</p>
          <p className="text-blue-400 font-semibold mb-2">
            Detections: {data.count.toLocaleString()}
          </p>
          <p className="text-gray-400 text-xs mb-2">Tactics: {data.tactics || "Unknown"}</p>
          {data.sources && Object.keys(data.sources).length > 0 && (
            <div className="border-t border-gray-700 mt-2 pt-2">
              <p className="text-gray-400 text-xs mb-1">Sources:</p>
              {Object.entries(data.sources).map(([source, count]) => (
                <p key={source} className="text-gray-300 text-xs">
                  • {source.split("-")[0]}: {(count as number).toLocaleString()}
                </p>
              ))}
            </div>
          )}
        </div>
      );
    }
    return null;
  };

  const exportToCSV = () => {
    if (!data) return;

    const csvRows = [
      ["Rank", "Technique ID", "Technique Name", "Count", "Tactics", "Sources"].join(","),
      ...data.techniques.map((tech, idx) =>
        [
          idx + 1,
          tech.technique_id,
          `"${tech.technique_name}"`,
          tech.count,
          `"${tech.tactic_names.join("; ")}"`,
          `"${Object.entries(tech.sources).map(([k, v]) => `${k}:${v}`).join("; ")}"`,
        ].join(",")
      ),
    ];

    const blob = new Blob([csvRows.join("\n")], { type: "text/csv" });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `top-techniques-${new Date().toISOString().split("T")[0]}.csv`;
    a.click();
    window.URL.revokeObjectURL(url);
  };

  if (parentLoading || loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="flex flex-col items-center gap-3">
          <Activity className="w-8 h-8 text-blue-500 animate-pulse" />
          <p className="text-gray-400">Loading top techniques...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="flex flex-col items-center gap-3 text-red-400">
          <AlertCircle className="w-8 h-8" />
          <p>Error: {error}</p>
          <button
            onClick={fetchData}
            className="mt-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-md transition-colors"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Controls Bar */}
      <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-600 rounded-lg">
              <TrendingUp className="w-5 h-5 text-white" />
            </div>
            <div>
              <h3 className="text-lg font-bold text-white">Top Detected Techniques</h3>
              <p className="text-xs text-gray-400">
                {data?.total_detections.toLocaleString()} total detections analyzed
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2">
              <Filter className="w-4 h-4 text-gray-400" />
              <select
                value={tacticFilter}
                onChange={(e) => setTacticFilter(e.target.value)}
                className="px-3 py-1.5 bg-gray-700 text-white rounded text-sm border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                {tacticOptions.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </div>

            <div className="flex items-center gap-2">
              <span className="text-gray-400 text-sm">Show:</span>
              <select
                value={limit}
                onChange={(e) => setLimit(Number(e.target.value))}
                className="px-3 py-1.5 bg-gray-700 text-white rounded text-sm border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value={5}>Top 5</option>
                <option value={10}>Top 10</option>
                <option value={15}>Top 15</option>
                <option value={20}>Top 20</option>
              </select>
            </div>

            <button
              onClick={exportToCSV}
              className="flex items-center gap-2 px-3 py-1.5 bg-gray-700 text-white rounded hover:bg-gray-600 transition-colors text-sm"
            >
              <Download className="w-4 h-4" />
              Export CSV
            </button>
          </div>
        </div>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <div className="flex items-center justify-between mb-2">
            <span className="text-gray-400 text-sm">Total Detections</span>
            <Shield className="w-5 h-5 text-blue-400" />
          </div>
          <p className="text-2xl font-bold text-white">
            {data?.total_detections.toLocaleString()}
          </p>
        </div>

        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <div className="flex items-center justify-between mb-2">
            <span className="text-gray-400 text-sm">Unique Techniques</span>
            <Activity className="w-5 h-5 text-green-400" />
          </div>
          <p className="text-2xl font-bold text-white">{data?.techniques.length}</p>
        </div>

        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <div className="flex items-center justify-between mb-2">
            <span className="text-gray-400 text-sm">Top Technique</span>
            <TrendingUp className="w-5 h-5 text-red-400" />
          </div>
          <p className="text-lg font-bold text-white truncate">
            {data?.techniques[0]?.technique_id || "N/A"}
          </p>
          <p className="text-xs text-gray-400 truncate">
            {data?.techniques[0]?.count.toLocaleString()} detections
          </p>
        </div>

        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <div className="flex items-center justify-between mb-2">
            <span className="text-gray-400 text-sm">Time Range</span>
            <Activity className="w-5 h-5 text-purple-400" />
          </div>
          <p className="text-lg font-bold text-white">{dayRange} Days</p>
          <p className="text-xs text-gray-400">Analysis period</p>
        </div>
      </div>

      {/* Chart */}
      <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
        <ResponsiveContainer width="100%" height={400}>
          <BarChart
            data={chartData}
            margin={{ top: 20, right: 30, left: 20, bottom: 80 }}
            onMouseMove={(state) => {
              if (state.activeTooltipIndex !== undefined) {
                setSelectedBar(chartData[state.activeTooltipIndex]?.name || null);
              }
            }}
            onMouseLeave={() => setSelectedBar(null)}
          >
            <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
            <XAxis
              dataKey="name"
              stroke="#9CA3AF"
              angle={-45}
              textAnchor="end"
              height={80}
              tick={{ fill: "#9CA3AF", fontSize: 12 }}
            />
            <YAxis
              stroke="#9CA3AF"
              tick={{ fill: "#9CA3AF" }}
              label={{
                value: "Detections",
                angle: -90,
                position: "insideLeft",
                fill: "#9CA3AF",
              }}
            />
            <Tooltip content={<CustomTooltip />} cursor={{ fill: "rgba(59, 130, 246, 0.1)" }} />
            <Bar dataKey="count" radius={[8, 8, 0, 0]}>
              {chartData.map((entry, index) => (
                <Cell
                  key={`cell-${index}`}
                  fill={entry.color}
                  opacity={selectedBar === null || selectedBar === entry.name ? 1 : 0.3}
                />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Detailed Table */}
      <div className="bg-gray-800 rounded-lg border border-gray-700">
        <div className="p-4 border-b border-gray-700">
          <h4 className="text-lg font-semibold text-white">Technique Details</h4>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-gray-900">
              <tr>
                <th className="px-4 py-3 text-left text-gray-400 font-medium">Rank</th>
                <th className="px-4 py-3 text-left text-gray-400 font-medium">Technique ID</th>
                <th className="px-4 py-3 text-left text-gray-400 font-medium">Name</th>
                <th className="px-4 py-3 text-left text-gray-400 font-medium">Tactics</th>
                <th className="px-4 py-3 text-right text-gray-400 font-medium">Detections</th>
                <th className="px-4 py-3 text-right text-gray-400 font-medium">Percentage</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700">
              {data?.techniques.map((tech, idx) => {
                const percentage = ((tech.count / (data?.total_detections || 1)) * 100).toFixed(1);
                return (
                  <tr key={tech.technique_id} className="hover:bg-gray-750 transition-colors">
                    <td className="px-4 py-3 text-right text-white font-semibold">
                      {tech.count.toLocaleString()}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <span className="text-blue-400">{percentage}%</span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default TopTechniquesView;="px-4 py-3">