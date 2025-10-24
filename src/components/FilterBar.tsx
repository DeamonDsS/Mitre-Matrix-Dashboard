import { Search, Filter } from 'lucide-react';
import type { FilterState } from '../types/mitre';

interface FilterBarProps {
  filters: FilterState;
  onFilterChange: (filters: FilterState) => void;
}

const tactics = [
  'all',
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact',
];

const severities = ['all', 'low', 'medium', 'high', 'critical'];

export default function FilterBar({ filters, onFilterChange }: FilterBarProps) {
  return (
    <div className="bg-white rounded-lg border border-gray-200 p-4 mb-6">
      <div className="flex items-center gap-2 mb-4">
        <Filter className="w-4 h-4 text-gray-600" />
        <h2 className="text-sm font-semibold text-gray-700">Filters</h2>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
          <input
            type="text"
            placeholder="Search techniques..."
            value={filters.search}
            onChange={(e) => onFilterChange({ ...filters, search: e.target.value })}
            className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-gray-900 focus:border-transparent outline-none text-sm"
          />
        </div>

        <select
          value={filters.tactic}
          onChange={(e) => onFilterChange({ ...filters, tactic: e.target.value })}
          className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-gray-900 focus:border-transparent outline-none text-sm appearance-none bg-white cursor-pointer"
        >
          {tactics.map((tactic) => (
            <option key={tactic} value={tactic}>
              {tactic === 'all' ? 'All Tactics' : tactic}
            </option>
          ))}
        </select>

        <select
          value={filters.severity}
          onChange={(e) => onFilterChange({ ...filters, severity: e.target.value })}
          className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-gray-900 focus:border-transparent outline-none text-sm appearance-none bg-white cursor-pointer"
        >
          {severities.map((severity) => (
            <option key={severity} value={severity}>
              {severity === 'all' ? 'All Severities' : severity.toUpperCase()}
            </option>
          ))}
        </select>
      </div>
    </div>
  );
}
