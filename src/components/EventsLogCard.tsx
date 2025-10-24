import type { MitreTechnique } from '../types/mitre';
import { Shield, Clock, Layers, User, Server, Terminal } from 'lucide-react';

interface EventLogCardProps {
  event: MitreTechnique;
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

export default function EventLogCard({ event }: EventLogCardProps) {
  const severity = (event.severity?.toLowerCase() || 'unknown') as SeverityLevel;
  
  // Debug: Log event properties
  console.log('EventLogCard received:', {
    event_code: event.event_code,
    technique_id: event.technique_id,
    channel: event.channel,
    host_name: event.host_name,
    user_name: event.user_name,
    process_name: event.process_name,
  });
  
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

  const formatDateTime = (timestamp: string) => {
    try {
      return new Date(timestamp).toLocaleString('en-US', {
        month: 'short',
        day: 'numeric',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      });
    } catch {
      return 'Invalid date';
    }
  };

  // Safe access to properties with fallbacks
  const eventCode = event.event_code || event.technique_id || 'Unknown';
  const channel = event.channel || 'System';
  const techniqueName = event.technique_name || 'Unknown Event';
  const description = event.description || 'No description available';
  const hostName = event.host_name;
  const userName = event.user_name;
  const processName = event.process_name;
  const tactic = event.tactic || 'Unknown';
  const platform = event.platform;
  const timestamp = event.timestamp || new Date().toISOString();

  return (
    <div className="bg-white rounded-lg border border-gray-200 p-5 hover:shadow-lg transition-shadow duration-200">
      {/* Header */}
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-2">
          <div className={`w-2 h-2 rounded-full ${severityDots[severity]}`} />
          <span className="text-sm font-mono text-gray-600 font-semibold">
            {eventCode}
          </span>
          <span className="text-xs text-gray-400">•</span>
          <span className="text-xs text-gray-500">{channel}</span>
        </div>
        <span
          className={`px-2.5 py-0.5 rounded-full text-xs font-medium border ${
            severityColors[severity]
          }`}
        >
          {severity.toUpperCase()}
        </span>
      </div>

      {/* Event Name */}
      <h3 className="text-base font-semibold text-gray-900 mb-2">
        {techniqueName}
      </h3>

      {/* Description */}
      <p className="text-sm text-gray-600 mb-4 line-clamp-2">
        {description}
      </p>

      {/* Details Grid */}
      <div className="space-y-2 mb-4 text-xs">
        {hostName && (
          <div className="flex items-center gap-2 text-gray-600">
            <Server className="w-3.5 h-3.5 flex-shrink-0" />
            <span className="font-medium">Host:</span>
            <span className="truncate">{hostName}</span>
          </div>
        )}
        
        {userName && userName !== 'N/A' && (
          <div className="flex items-center gap-2 text-gray-600">
            <User className="w-3.5 h-3.5 flex-shrink-0" />
            <span className="font-medium">User:</span>
            <span className="truncate">{userName}</span>
          </div>
        )}
        
        {processName && (
          <div className="flex items-center gap-2 text-gray-600">
            <Terminal className="w-3.5 h-3.5 flex-shrink-0" />
            <span className="font-medium">Process:</span>
            <span className="truncate">{processName}</span>
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="flex items-center justify-between text-xs text-gray-500 pt-3 border-t border-gray-100">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1">
            <Shield className="w-3.5 h-3.5" />
            <span>{tactic}</span>
          </div>
          {platform && platform.length > 0 && (
            <div className="flex items-center gap-1">
              <Layers className="w-3.5 h-3.5" />
              <span>
                {Array.isArray(platform) 
                  ? platform[0] 
                  : platform}
              </span>
            </div>
          )}
        </div>
        <div className="flex items-center gap-1" title={formatDateTime(timestamp)}>
          <Clock className="w-3.5 h-3.5" />
          <span>{formatTime(timestamp)}</span>
        </div>
      </div>
    </div>
  );
}