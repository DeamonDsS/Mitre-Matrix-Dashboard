export interface MitreTechnique {
  id: string;
  technique_id: string;
  technique_name: string;
  tactic: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical' | 'unknown';
  timestamp: string;
  source?: string;
  platform?: string[];
  
  // Windows Event Log specific fields
  event?: {
    event_code?: string,
  };
  host?: {
    host_name?: string,
  }

  host_name?: string;
  user_name?: string;
  process_name?: string;
  log_level?: string;
  channel?: string;
  
  // Allow additional fields from Elasticsearch
  [key: string]: any;
}

export interface FilterState {
  search: string;
  tactic: string;
  severity: string;
}

export interface ElasticsearchResponse {
  hits: {
    total: {
      value: number;
      relation: string;
    };
    hits: Array<{
      sort: any[] | undefined;
      _id: string;
      _source: any;
      _score?: number;
    }>;
  };
}

export interface StatsCardProps {
  title: string;
  value: number;
  icon: any;
  color: string;
}

export interface MitreStats {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  tactics: number;
}

export interface ConfigModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSave: (config: { esUrl: string; esIndex: string }) => void;
  currentConfig: {
    esUrl: string;
    esIndex: string;
  };
}

export interface MitreApiResponse {
  total: number;
  events: MitreTechnique[];
  page: number;
  size: number;
}


// for Mitre Framework
export interface MitreTechniqueFramework {
  id: string;
  name: string;
  description: string;
  tactics: string[];
  platforms: string[];
  dataSources: string[];
  detection: string;
  eventIds: number[];
}

export interface MitreTacticFramework {
  id: string;
  name: string;
  description: string;
  shortName: string;
}

export interface TechniqueStatsFramework {
  count: number;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'none';
  lastSeen: string | null;
}

export interface FilterStateFramework {
  search: string;
  severity: string;
}



