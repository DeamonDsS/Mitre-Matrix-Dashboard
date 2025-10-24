// src/components/StatCard.tsx
import type { LucideIcon } from "lucide-react";
import { ArrowUpRight, ArrowDownRight, Minus } from "lucide-react";

interface StatsCardProps {
  title: string;
  value: number;
  icon: LucideIcon;
  color: string;
  previousValue?: number; // (Optional) ค่าจากช่วงเวลาก่อนหน้า
  unit?: string; // (Optional) หน่วยนับ เช่น "events"
}

export default function StatsCard({ title, value, icon: Icon, color, previousValue, unit }: StatsCardProps) {
  const formattedValue = new Intl.NumberFormat('en-US').format(value);

  let percentageChange: number | null = null;
  if (previousValue !== undefined && previousValue > 0) {
    percentageChange = ((value - previousValue) / previousValue) * 100;
  } else if (previousValue === 0 && value > 0) {
    percentageChange = 100; // ถ้าค่าเก่าเป็น 0 แต่ค่าใหม่มี, ถือว่าเพิ่ม 100%
  }

  const ChangeIcon = percentageChange === null ? Minus : (percentageChange >= 0 ? ArrowUpRight : ArrowDownRight);
  const changeColor = percentageChange === null ? 'text-gray-500' : (percentageChange >= 0 ? 'text-green-600' : 'text-red-600');

  return (
    <div className="bg-white rounded-lg border border-gray-200 p-5 flex flex-col justify-between">
      {/* ส่วนบน: Title & Icon */}
      <div className="flex items-start justify-between mb-4">
        <p className="text-sm font-medium text-gray-600">{title}</p>
        <div className={`w-10 h-10 rounded-lg ${color} flex items-center justify-center flex-shrink-0`}>
          <Icon className="w-5 h-5 text-white" />
        </div>
      </div>

      {/* ส่วนล่าง: Value & Trend */}
      <div>
        <h3 className="text-3xl font-bold text-gray-900 mb-1">
          {formattedValue}
          {unit && <span className="text-lg font-medium text-gray-500 ml-2">{unit}</span>}
        </h3>
        {percentageChange !== null && (
          <div className="flex items-center text-sm">
            <ChangeIcon className={`w-4 h-4 mr-1 ${changeColor}`} />
            <span className={changeColor}>{percentageChange.toFixed(1)}%</span>
            <span className="text-gray-500 ml-1.5">vs. previous period</span>
          </div>
        )}
      </div>
    </div>
  );
}
