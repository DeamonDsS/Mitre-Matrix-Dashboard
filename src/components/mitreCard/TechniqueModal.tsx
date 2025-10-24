import React from 'react';
import { X, ExternalLink } from 'lucide-react';
import type { MitreTechniqueFramework as MitreTechnique, TechniqueStatsFramework as TechniqueStats, MitreTacticFramework as MitreTactic } from '../../types/mitre';

import { getSeverityColor, getSeverityText } from './mitreData';

interface TechniqueModalProps {
  technique: MitreTechnique;
  stats: TechniqueStats;
  tactics: MitreTactic[];
  onClose: () => void;
}

const TechniqueModal: React.FC<TechniqueModalProps> = ({
  technique,
  stats,
  tactics,
  onClose
}) => {
  return (
    <div className="fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center p-4 z-50">
      <div className="bg-gray-800 rounded-lg shadow-2xl max-w-2xl w-full max-h-[85vh] overflow-y-auto">
        <div className="sticky top-0 bg-gray-900 p-4 border-b border-gray-700 flex items-start justify-between">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className={`px-2 py-0.5 rounded text-xs font-bold text-white ${getSeverityColor(stats.severity)}`}>
                {getSeverityText(stats.severity)}
              </span>
              <span className="text-gray-400 text-sm">{technique.id}</span>
            </div>
            <h2 className="text-xl font-bold text-white">{technique.name}</h2>
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-white">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-4 space-y-4">
          <div className="bg-gray-900 rounded p-3">
            <div className="grid grid-cols-2 gap-3 text-sm">
              <div>
                <div className="text-gray-400">Events (7d)</div>
                <div className="text-white font-semibold">{stats.count.toLocaleString()}</div>
              </div>
              <div>
                <div className="text-gray-400">Last Seen</div>
                <div className="text-white font-semibold text-xs">
                  {stats.lastSeen ? new Date(stats.lastSeen).toLocaleDateString() : 'Never'}
                </div>
              </div>
            </div>
          </div>

          <div>
            <h3 className="text-white font-semibold mb-1 text-sm">Description</h3>
            <p className="text-gray-300 text-sm leading-relaxed">{technique.description}</p>
          </div>

          <div>
            <h3 className="text-white font-semibold mb-1 text-sm">Tactics</h3>
            <div className="flex flex-wrap gap-1.5">
              {technique.tactics.map(tacticShortName => {
                const tactic = tactics.find(t => t.shortName.toLowerCase() === tacticShortName.toLowerCase());
                return (
                  <span key={tacticShortName} className="px-2 py-0.5 bg-red-600 text-white rounded text-xs">
                    {tactic?.name || tacticShortName}
                  </span>
                );
              })}
            </div>
          </div>

          {technique.eventIds.length > 0 && (
            <div>
              <h3 className="text-white font-semibold mb-1 text-sm">Event IDs</h3>
              <div className="flex flex-wrap gap-1.5">
                {technique.eventIds.map(eventId => (
                  <span key={eventId} className="px-2 py-0.5 bg-gray-700 text-white rounded text-xs font-mono">
                    {eventId}
                  </span>
                ))}
              </div>
            </div>
          )}

          {technique.detection && (
            <div>
              <h3 className="text-white font-semibold mb-1 text-sm">Detection</h3>
              <div className="bg-gray-900 rounded p-2">
                <p className="text-gray-300 text-xs leading-relaxed">{technique.detection}</p>
              </div>
            </div>
          )}

          <button
            onClick={() => window.open(`https://attack.mitre.org/techniques/${technique.id}/`, '_blank')}
            className="w-full px-4 py-2 bg-red-600 text-white rounded hover:bg-red-700 transition-colors text-sm font-semibold flex items-center justify-center gap-2"
          >
            View Full Details <ExternalLink className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
};

export default TechniqueModal;
