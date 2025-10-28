import React, { useState, useRef, useEffect } from 'react';
import { ChevronDown } from 'lucide-react';
import type { MitreTechniqueFramework as MitreTechnique, TechniqueStatsFramework as TechniqueStats } from '../../types/mitre';
import { getSeverityColor } from './mitreData';

interface TechniqueCardProps {
  technique: MitreTechnique;
  stats: TechniqueStats;
  isSelected: boolean;
  onClick: () => void;
  subTechniques?: Array<{
    technique: MitreTechnique;
    stats: TechniqueStats;
  }>;
  onSubTechniqueClick?: (technique: MitreTechnique) => void;
}

const TechniqueCard: React.FC<TechniqueCardProps> = ({
  technique,
  stats,
  isSelected,
  onClick,
  subTechniques = [],
  onSubTechniqueClick
}) => {
  const [showDropdown, setShowDropdown] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const hasSubTechniques = subTechniques.length > 0;

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setShowDropdown(false);
      }
    };

    if (showDropdown) {
      document.addEventListener('mousedown', handleClickOutside);
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [showDropdown]);

  const handleDropdownToggle = (e: React.MouseEvent) => {
    e.stopPropagation();
    setShowDropdown(!showDropdown);
  };

  // Calculate total count including sub-techniques
  const totalCount = stats.count + subTechniques.reduce((sum, sub) => sum + sub.stats.count, 0);

  // Get highest severity among parent and sub-techniques
  const getHighestSeverity = () => {
    const severities = [stats.severity, ...subTechniques.map(sub => sub.stats.severity)];
    if (severities.includes('critical')) return 'critical';
    if (severities.includes('high')) return 'high';
    if (severities.includes('medium')) return 'medium';
    if (severities.includes('low')) return 'low';
    return 'none';
  };

  const displaySeverity = getHighestSeverity();

  return (
    <div className="relative" ref={dropdownRef}>
      {/* Changed from <button> to <div> with role="button" */}
      <div
        onClick={onClick}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            onClick();
          }
        }}
        role="button"
        tabIndex={0}
        className={`w-full p-2 rounded text-left transition-all hover:scale-105 cursor-pointer ${
          getSeverityColor(displaySeverity)
        } ${isSelected ? 'ring-2 ring-white shadow-lg' : ''}`}
        title={`${technique.id}: ${technique.name}\nEvents: ${totalCount}${hasSubTechniques ? `\n${subTechniques.length} sub-techniques` : ''}`}
      >
        <div className="space-y-1">
          <div className="flex items-center justify-between gap-1">
            <div className="text-[10px] font-bold text-gray-900 truncate flex-1">
              {technique.id}
            </div>
            {hasSubTechniques && (
              <button
                onClick={handleDropdownToggle}
                className="text-gray-900 hover:text-white transition-colors p-0.5 rounded hover:bg-black hover:bg-opacity-20"
                title={`${subTechniques.length} sub-techniques`}
              >
                <ChevronDown className={`w-3 h-3 transition-transform ${showDropdown ? 'rotate-180' : ''}`} />
              </button>
            )}
          </div>
          <div className="text-[9px] text-gray-800 leading-tight line-clamp-2 h-[28px]">
            {technique.name}
          </div>
          {totalCount > 0 && (
            <div className="flex items-center gap-1">
              <div className="text-[10px] font-semibold text-white bg-black bg-opacity-40 rounded px-1 inline-block">
                {totalCount}
              </div>
              {hasSubTechniques && subTechniques.some(sub => sub.stats.count > 0) && (
                <div className="text-[8px] text-gray-900 opacity-70">
                  +{subTechniques.length} sub
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Dropdown Menu */}
      {showDropdown && hasSubTechniques && (
        <div className="absolute left-0 top-full mt-1 w-full bg-gray-800 rounded shadow-lg border border-gray-700 z-50 max-h-64 overflow-y-auto">
          <div className="p-1 space-y-1">
            {subTechniques.map(({ technique: subTech, stats: subStats }) => (
              <button
                key={subTech.id}
                onClick={(e) => {
                  e.stopPropagation();
                  onSubTechniqueClick?.(subTech);
                  setShowDropdown(false);
                }}
                className={`w-full p-2 rounded text-left transition-all hover:bg-gray-700 ${
                  getSeverityColor(subStats.severity)
                } border-l-4`}
                style={{ borderLeftColor: getSeverityColor(subStats.severity).replace('bg-', '#') }}
                title={`${subTech.id}: ${subTech.name}\nEvents: ${subStats.count}`}
              >
                <div className="space-y-0.5">
                  <div className="flex items-center justify-between">
                    <div className="text-[9px] font-bold text-white">
                      {subTech.id}
                    </div>
                    {subStats.count > 0 && (
                      <div className="text-[9px] font-semibold text-white bg-black bg-opacity-60 rounded px-1">
                        {subStats.count}
                      </div>
                    )}
                  </div>
                  <div className="text-[8px] text-gray-300 leading-tight line-clamp-2">
                    {subTech.name}
                  </div>
                </div>
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default TechniqueCard;