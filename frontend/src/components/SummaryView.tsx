// src/components/SummaryView.tsx

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
import type { MitreStats } from "../types/mitre"; // Adjust the path if necessary

// Register the components Chart.js needs
ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement
);

interface SummaryViewProps {
  stats: MitreStats;
  loading: boolean;
}

const SummaryView: React.FC<SummaryViewProps> = ({ stats, loading }) => {
  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-gray-900"></div>
      </div>
    );
  }

  // Data for the Severity Distribution Bar Chart
  const severityData = {
    labels: ["Critical", "High", "Medium", "Low"],
    datasets: [
      {
        label: "Event Count by Severity",
        data: [stats.critical, stats.high, stats.medium, stats.low],
        backgroundColor: [
          "rgba(239, 68, 68, 0.6)", // Red-500
          "rgba(249, 115, 22, 0.6)", // Orange-500
          "rgba(234, 179, 8, 0.6)", // Yellow-500
          "rgba(59, 130, 246, 0.6)", // Blue-500
        ],
        borderColor: [
          "rgba(239, 68, 68, 1)",
          "rgba(249, 115, 22, 1)",
          "rgba(234, 179, 8, 1)",
          "rgba(59, 130, 246, 1)",
        ],
        borderWidth: 1,
      },
    ],
  };

  // Data for the Tactics Distribution Pie Chart (assuming you'll add tactic data to your stats)
  // For now, this is placeholder data.
  const tacticsData = {
    labels: ["Tactic A", "Tactic B", "Tactic C", "Tactic D"],
    datasets: [
      {
        label: "Tactics Distribution",
        data: [12, 19, 3, 5], // Replace with real data like stats.tacticsBreakdown
        backgroundColor: [
          "rgba(255, 99, 132, 0.6)",
          "rgba(54, 162, 235, 0.6)",
          "rgba(255, 206, 86, 0.6)",
          "rgba(75, 192, 192, 0.6)",
        ],
        borderWidth: 1,
      },
    ],
  };

  const chartOptions = {
    responsive: true,
    plugins: {
      legend: {
        position: "top" as const,
      },
      title: {
        display: true,
        font: {
          size: 16,
        },
      },
    },
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 py-6">
      <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
        <Bar
          options={{ ...chartOptions, plugins: { ...chartOptions.plugins, title: { ...chartOptions.plugins.title, text: "Event Severity Distribution" } } }}
          data={severityData}
        />
      </div>
      <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
        <Pie
          options={{ ...chartOptions, plugins: { ...chartOptions.plugins, title: { ...chartOptions.plugins.title, text: "MITRE ATT&CK Tactic Distribution" } } }}
          data={tacticsData}
        />
        <p className="text-center text-xs text-gray-500 mt-4">
          Note: Tactic data is currently a placeholder.
        </p>
      </div>
    </div>
  );
};

export default SummaryView;
