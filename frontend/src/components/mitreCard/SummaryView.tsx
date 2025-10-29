// SummaryView.tsx
import React from "react";
import { Bar, Pie, Line } from "react-chartjs-2";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
} from "chart.js";
import { TrendingUp, Shield, Target, Activity } from "lucide-react";
import type { UnifiedStats } from "../../services/multiMitreService";

// Register Chart.js components
ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  ArcElement
);

interface SummaryViewProps {
  stats: UnifiedStats;
  loading: boolean;
  selectedIndices: string[];
  dayRange: number;
}

const SummaryView: React.FC<SummaryViewProps> = ({
  stats,
  loading,
  selectedIndices,
  dayRange,
}) => {
  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="flex flex-col items-center gap-3">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-500"></div>
          <p className="text-gray-400">Loading analytics...</p>
        </div>
      </div>
    );
  }

  // Data for Tactics Distribution Bar Chart
  const tacticsData = {
    labels: stats.tactics.slice(0, 10).map((t) => t.name || t.id),
    datasets: [
      {
        label: "Detections by Tactic",
        data: stats.tactics.slice(0, 10).map((t) => t.count),
        backgroundColor: "rgba(239, 68, 68, 0.6)",
        borderColor: "rgba(239, 68, 68, 1)",
        borderWidth: 1,
      },
    ],
  };

  // Data for Sources Distribution Pie Chart
  const sourcesData = {
    labels: Object.keys(stats.sources),
    datasets: [
      {
        label: "Events by Source",
        data: Object.values(stats.sources),
        backgroundColor: [
          "rgba(239, 68, 68, 0.6)",
          "rgba(249, 115, 22, 0.6)",
          "rgba(234, 179, 8, 0.6)",
          "rgba(59, 130, 246, 0.6)",
          "rgba(139, 92, 246, 0.6)",
        ],
        borderWidth: 1,
      },
    ],
  };

  // Data for Source Breakdown Bar Chart
  const sourceBreakdownData = {
    labels: stats.breakdown.map((b) => b.index.split("-")[0]),
    datasets: [
      {
        label: "Total Events",
        data: stats.breakdown.map((b) => b.total),
        backgroundColor: "rgba(59, 130, 246, 0.6)",
        borderColor: "rgba(59, 130, 246, 1)",
        borderWidth: 1,
      },
      {
        label: "Unique Tactics",
        data: stats.breakdown.map((b) => b.tactics),
        backgroundColor: "rgba(139, 92, 246, 0.6)",
        borderColor: "rgba(139, 92, 246, 1)",
        borderWidth: 1,
      },
    ],
  };

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: "top" as const,
        labels: {
          color: "#9CA3AF",
          font: {
            size: 12,
          },
        },
      },
      title: {
        display: false,
      },
    },
    scales: {
      x: {
        ticks: {
          color: "#9CA3AF",
          font: {
            size: 11,
          },
        },
        grid: {
          color: "rgba(75, 85, 99, 0.3)",
        },
      },
      y: {
        ticks: {
          color: "#9CA3AF",
          font: {
            size: 11,
          },
        },
        grid: {
          color: "rgba(75, 85, 99, 0.3)",
        },
      },
    },
  };

  const pieOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: "right" as const,
        labels: {
          color: "#9CA3AF",
          font: {
            size: 12,
          },
          padding: 15,
        },
      },
      title: {
        display: false,
      },
    },
  };

  return (
    <div className="space-y-6">
      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm mb-1">Total Events</p>
              <p className="text-2xl font-bold text-white">
                {stats.total.toLocaleString()}
              </p>
            </div>
            <div className="p-3 bg-red-600 rounded-lg">
              <Activity className="w-6 h-6 text-white" />
            </div>
          </div>
          <p className="text-xs text-gray-500 mt-2">Last {dayRange} days</p>
        </div> */}

        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm mb-1">Active Tactics</p>
              <p className="text-2xl font-bold text-white">
                {stats.tactics.length}
              </p>
            </div>
            <div className="p-3 bg-orange-600 rounded-lg">
              <Target className="w-6 h-6 text-white" />
            </div>
          </div>
          <p className="text-xs text-gray-500 mt-2">Unique MITRE tactics</p>
        </div>

        {/* <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm mb-1">Data Sources</p>
              <p className="text-2xl font-bold text-white">
                {selectedIndices.length}
              </p>
            </div>
            <div className="p-3 bg-blue-600 rounded-lg">
              <Shield className="w-6 h-6 text-white" />
            </div>
          </div>
          <p className="text-xs text-gray-500 mt-2">Active indices</p>
        </div> */}

        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm mb-1">Top Tactic</p>
              <p className="text-2xl font-bold text-white">
                {stats.tactics[0]?.count.toLocaleString() || 0}
              </p>
            </div>
            <div className="p-3 bg-purple-600 rounded-lg">
              <TrendingUp className="w-6 h-6 text-white" />
            </div>
          </div>
          <p className="text-xs text-gray-500 mt-2">
            {stats.tactics[0]?.name || "N/A"}
          </p>
        </div>
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Tactics Distribution */}
        <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
          <h3 className="text-lg font-semibold text-white mb-4">
            Top 10 Tactics by Detection Count
          </h3>
          <div style={{ height: "300px" }}>
            <Bar options={chartOptions} data={tacticsData} />
          </div>
        </div>

        {/* Sources Distribution */}
        <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
          <h3 className="text-lg font-semibold text-white mb-4">
            Events Distribution by Source
          </h3>
          <div style={{ height: "300px" }}>
            <Pie options={pieOptions} data={sourcesData} />
          </div>
        </div>

        {/* Source Breakdown */}
        <div className="bg-gray-800 p-6 rounded-lg border border-gray-700 lg:col-span-2">
          <h3 className="text-lg font-semibold text-white mb-4">
            Source Breakdown Analysis
          </h3>
          <div style={{ height: "300px" }}>
            <Bar options={chartOptions} data={sourceBreakdownData} />
          </div>
        </div>
      </div>

      {/* Detailed Tactics Table */}
      <div className="bg-gray-800 rounded-lg border border-gray-700">
        <div className="p-4 border-b border-gray-700">
          <h3 className="text-lg font-semibold text-white">
            Detailed Tactics Breakdown
          </h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-gray-900">
              <tr>
                <th className="px-4 py-3 text-left text-gray-400 font-medium">
                  Rank
                </th>
                <th className="px-4 py-3 text-left text-gray-400 font-medium">
                  Tactic ID
                </th>
                <th className="px-4 py-3 text-left text-gray-400 font-medium">
                  Tactic Name
                </th>
                <th className="px-4 py-3 text-right text-gray-400 font-medium">
                  Detections
                </th>
                <th className="px-4 py-3 text-right text-gray-400 font-medium">
                  Percentage
                </th>
                <th className="px-4 py-3 text-left text-gray-400 font-medium">
                  Top Source
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700">
              {stats.tactics.map((tactic, index) => {
                const percentage = ((tactic.count / stats.total) * 100).toFixed(
                  1
                );
                const topSource = Object.entries(tactic.sources).sort(
                  ([, a], [, b]) => b - a
                )[0];

                return (
                  <tr
                    key={tactic.id}
                    className="hover:bg-gray-750 transition-colors"
                  >
                    <td className="px-4 py-3 text-gray-400">{index + 1}</td>
                    <td className="px-4 py-3">
                      <span className="text-red-400 font-mono text-xs">
                        {tactic.id}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-white">{tactic.name}</td>
                    <td className="px-4 py-3 text-right text-white font-semibold">
                      {tactic.count.toLocaleString()}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <span className="text-blue-400">{percentage}%</span>
                    </td>
                    <td className="px-4 py-3 text-gray-400 text-xs">
                      {topSource
                        ? `${topSource[0].split("-")[0]} (${topSource[1]})`
                        : "N/A"}
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

export default SummaryView;