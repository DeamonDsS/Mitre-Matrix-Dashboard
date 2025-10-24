import type { MitreTechnique } from '../types/mitre';
import { Shield, Clock, Layers } from 'lucide-react';

interface TechniqueCardProps {
  technique: MitreTechnique;
}

const severityColors = {
  low: 'bg-blue-100 text-blue-800 border-blue-200',
  medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
  high: 'bg-orange-100 text-orange-800 border-orange-200',
  critical: 'bg-red-100 text-red-800 border-red-200',
  unknown: 'bg-gray-100 text-gray-800 border-gray-200',
};

const severityDots = {
  low: 'bg-blue-500',
  medium: 'bg-yellow-500',
  high: 'bg-orange-500',
  critical: 'bg-red-500',
  unknown: 'bg-gray-500',
};

type SeverityLevel = 'low' | 'medium' | 'high' | 'critical' | 'unknown';

export default function TechniqueCard({ technique }: TechniqueCardProps) {
  // Safe severity handling
  const severity = (technique.severity?.toLowerCase() || 'unknown') as SeverityLevel;
  
  const formatTime = (timestamp: string) => {
    try {
      const date = new Date(timestamp);
      const now = new Date();
      const diff = now.getTime() - date.getTime();
      const hours = Math.floor(diff / (1000 * 60 * 60));
      const days = Math.floor(hours / 24);

      if (days > 0) return `${days}d ago`;
      if (hours > 0) return `${hours}h ago`;
      return 'Just now';
    } catch {
      return 'Unknown';
    }
  };

  return (
    <div className="bg-white rounded-lg border border-gray-200 p-5 hover:shadow-lg transition-shadow duration-200">
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-2">
          <div className={`w-2 h-2 rounded-full ${severityDots[severity]}`} />
          <span className="text-sm font-mono text-gray-600">
            {technique.technique_id || 'N/A'}
          </span>
        </div>
        <span
          className={`px-2.5 py-0.5 rounded-full text-xs font-medium border ${severityColors[severity]}`}
        >
          {severity.toUpperCase()}
        </span>
      </div>

      <h3 className="text-lg font-semibold text-gray-900 mb-2 line-clamp-1">
        {technique.technique_name || 'Unknown Technique'}
      </h3>

      <p className="text-sm text-gray-600 mb-4 line-clamp-2">
        {technique.description || 'No description available'}
      </p>

      <div className="flex items-center justify-between text-xs text-gray-500">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1">
            <Shield className="w-3.5 h-3.5" />
            <span>{technique.tactic || 'Unknown'}</span>
          </div>
          {technique.platform && technique.platform.length > 0 && (
            <div className="flex items-center gap-1">
              <Layers className="w-3.5 h-3.5" />
              <span>
                {Array.isArray(technique.platform) 
                  ? technique.platform.join(', ') 
                  : technique.platform}
              </span>
            </div>
          )}
        </div>
        <div className="flex items-center gap-1">
          <Clock className="w-3.5 h-3.5" />
          <span>{formatTime(technique.timestamp || new Date().toISOString())}</span>
        </div>
      </div>
    </div>
  );
}