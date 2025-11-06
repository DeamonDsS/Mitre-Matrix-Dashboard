// SummaryView.tsx
import React from "react";
import { Bar, Pie } from "react-chartjs-2";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
} from "chart.js";
import { TrendingUp, Target } from "lucide-react";

// Register Chart.js components
ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement
);

export interface SummaryStats {
  total: number; // จำนวนเหตุการณ์ทั้งหมดใน index เดียว
  critical: number;
  high: number;
  medium: number;
  low: number;
  tactics: Array<{
    id: string;               // MITRE tactic ID เช่น TA0001
    name: string;             // ชื่อ tactic เช่น "Initial Access"
    count: number;            // จำนวน detection ที่อยู่ใน tactic นั้น
    sources: Record<string, number>; // breakdown ต่อ source ภายใน tactic เดียว
  }>;
  sources: Record<string, number>;   // breakdown รวมทุก tactic แยกตาม source
}

interface SummaryViewProps {
  stats: SummaryStats;
  loading: boolean;
  dayRange: number;
}


const SummaryView: React.FC<SummaryViewProps> = ({
  stats,
  loading,
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

  // Data for Top 10 Tactics Bar Chart
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

  const severityData = {
  labels: ["critical", "high", "medium", "low"],
  datasets: [
    {
      label: "Detections by Severity",
      data: [stats.critical, stats.high, stats.medium, stats.low],
      backgroundColor: [
        "rgba(239, 68, 68, 0.6)", // Critical
        "rgba(249, 115, 22, 0.6)", // High
        "rgba(234, 179, 8, 0.6)", // Medium
        "rgba(59, 130, 246, 0.6)", // Low
      ],
      borderWidth: 1,
    },
  ],
};

  // Shared Chart Options
  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: "top" as const,
        labels: { color: "#9CA3AF", font: { size: 12 } },
      },
    },
    scales: {
      x: {
        ticks: { color: "#9CA3AF", font: { size: 11 } },
        grid: { color: "rgba(75,85,99,0.3)" },
      },
      y: {
        ticks: { color: "#9CA3AF", font: { size: 11 } },
        grid: { color: "rgba(75,85,99,0.3)" },
      },
    },
  };

  const pieOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: "right" as const,
        labels: { color: "#9CA3AF", font: { size: 12 }, padding: 15 },
      },
    },
  };

  return (
    <div className="space-y-6">
      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Active Tactics */}
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
          <p className="text-xs text-gray-200 mt-2">
            Unique MITRE Tactics in last {dayRange} days
          </p>
        </div>

        {/* Top Tactic */}
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
          <p className="text-xs text-gray-200 mt-2">
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

        {/* Severity Distribution */}
        <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
          <h3 className="text-lg font-semibold text-white mb-4">
            Detection Distribution by Severity
          </h3>
          <div style={{ height: "300px" }}>
            <Pie options={pieOptions} data={severityData} />
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
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700">
              {stats.tactics.map((tactic, index) => {
                const percentage = ((tactic.count / stats.total) * 100).toFixed(1);
                return (
                  <tr key={tactic.id} className="hover:bg-gray-750 transition-colors">
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
