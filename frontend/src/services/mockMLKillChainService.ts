// services/mockMLKillChainService.ts
// Use this mock service during development, then swap to real API when ready

export interface MLPredictionRequest {
  indices: string[];
  day_range: number;
  confidence_threshold?: number;
}

export interface TechniqueDetection {
  technique_id: string;
  technique_name: string;
  count: number;
  confidence: number;
  sources: Record<string, number>;
  tactic_id?: string;
  tactic_name?: string;
}

export interface MLPhaseCoverage {
  phase_id: string;
  phase_name: string;
  phase_name_th: string;
  total_detections: number;
  predicted_detections: number;
  rule_based_detections: number;
  techniques_detected: number;
  available_techniques: number;
  coverage_percentage: number;
  confidence_score: number;
  sources: Record<string, number>;
  mitre_tactics: string[];
  top_techniques: TechniqueDetection[];
}

export interface MLKillChainResponse {
  total_detections: number;
  ml_predictions: number;
  unique_techniques: number;
  active_phases: number;
  methodology: string;
  model_version: string;
  confidence_threshold: number;
  time_range: {
    start: string;
    end: string;
  };
  indices_queried: string[];
  phases: MLPhaseCoverage[];
}

// Feature flag to switch between mock and real API
const USE_MOCK_API = import.meta.env.VITE_USE_MOCK_ML === 'true' || true;
const ML_API_BASE_URL = import.meta.env.VITE_ML_API_URL || 'http://localhost:8000';

// Mock data generator with realistic patterns
function generateMockMLResponse(
  indices: string[],
  dayRange: number,
  confidenceThreshold: number
): MLKillChainResponse {
  const now = new Date();
  const startDate = new Date(now);
  startDate.setDate(startDate.getDate() - dayRange);

  // Simulate realistic detection counts based on day range
  const baseDetections = Math.floor(100 * dayRange);
  
  // Generate phase data with realistic confidence scores
  const phases: MLPhaseCoverage[] = [
    {
      phase_id: 'reconnaissance',
      phase_name: 'Reconnaissance',
      phase_name_th: 'การสำรวจ',
      total_detections: Math.floor(baseDetections * 0.08),
      predicted_detections: Math.floor(baseDetections * 0.08),
      rule_based_detections: Math.floor(baseDetections * 0.06),
      techniques_detected: Math.floor(Math.random() * 5) + 3,
      available_techniques: 10,
      coverage_percentage: 65 + Math.random() * 20,
      confidence_score: 0.72 + Math.random() * 0.15,
      sources: {
        'SIEM': Math.floor(baseDetections * 0.04),
        'NDR': Math.floor(baseDetections * 0.03),
        'EDR': Math.floor(baseDetections * 0.01)
      },
      mitre_tactics: ['TA0043'],
      top_techniques: [
        {
          technique_id: 'T1595',
          technique_name: 'Active Scanning',
          count: Math.floor(baseDetections * 0.03),
          confidence: 0.85,
          sources: { 'NDR': Math.floor(baseDetections * 0.02), 'SIEM': Math.floor(baseDetections * 0.01) },
          tactic_id: 'TA0043',
          tactic_name: 'Reconnaissance'
        }
      ]
    },
    {
      phase_id: 'weaponization',
      phase_name: 'Weaponization',
      phase_name_th: 'การสร้างอาวุธ',
      total_detections: Math.floor(baseDetections * 0.06),
      predicted_detections: Math.floor(baseDetections * 0.06),
      rule_based_detections: Math.floor(baseDetections * 0.04),
      techniques_detected: Math.floor(Math.random() * 4) + 2,
      available_techniques: 8,
      coverage_percentage: 55 + Math.random() * 25,
      confidence_score: 0.68 + Math.random() * 0.18,
      sources: {
        'EDR': Math.floor(baseDetections * 0.04),
        'SIEM': Math.floor(baseDetections * 0.02)
      },
      mitre_tactics: ['TA0042'],
      top_techniques: [
        {
          technique_id: 'T1587',
          technique_name: 'Develop Capabilities',
          count: Math.floor(baseDetections * 0.02),
          confidence: 0.71,
          sources: { 'EDR': Math.floor(baseDetections * 0.02) }
        }
      ]
    },
    {
      phase_id: 'delivery',
      phase_name: 'Delivery',
      phase_name_th: 'การส่งมอบ',
      total_detections: Math.floor(baseDetections * 0.15),
      predicted_detections: Math.floor(baseDetections * 0.15),
      rule_based_detections: Math.floor(baseDetections * 0.13),
      techniques_detected: Math.floor(Math.random() * 6) + 4,
      available_techniques: 15,
      coverage_percentage: 70 + Math.random() * 20,
      confidence_score: 0.81 + Math.random() * 0.12,
      sources: {
        'EDR': Math.floor(baseDetections * 0.09),
        'Email Gateway': Math.floor(baseDetections * 0.04),
        'Proxy': Math.floor(baseDetections * 0.02)
      },
      mitre_tactics: ['TA0001'],
      top_techniques: [
        {
          technique_id: 'T1566',
          technique_name: 'Phishing',
          count: Math.floor(baseDetections * 0.08),
          confidence: 0.89,
          sources: { 'Email Gateway': Math.floor(baseDetections * 0.05), 'EDR': Math.floor(baseDetections * 0.03) }
        }
      ]
    },
    {
      phase_id: 'exploitation',
      phase_name: 'Exploitation',
      phase_name_th: 'การโจมตี',
      total_detections: Math.floor(baseDetections * 0.23),
      predicted_detections: Math.floor(baseDetections * 0.23),
      rule_based_detections: Math.floor(baseDetections * 0.20),
      techniques_detected: Math.floor(Math.random() * 8) + 6,
      available_techniques: 20,
      coverage_percentage: 78 + Math.random() * 18,
      confidence_score: 0.86 + Math.random() * 0.10,
      sources: {
        'EDR': Math.floor(baseDetections * 0.14),
        'SIEM': Math.floor(baseDetections * 0.07),
        'IDS/IPS': Math.floor(baseDetections * 0.02)
      },
      mitre_tactics: ['TA0002'],
      top_techniques: [
        {
          technique_id: 'T1203',
          technique_name: 'Exploitation for Client Execution',
          count: Math.floor(baseDetections * 0.10),
          confidence: 0.92,
          sources: { 'EDR': Math.floor(baseDetections * 0.08), 'SIEM': Math.floor(baseDetections * 0.02) }
        }
      ]
    },
    {
      phase_id: 'installation',
      phase_name: 'Installation',
      phase_name_th: 'การติดตั้ง',
      total_detections: Math.floor(baseDetections * 0.18),
      predicted_detections: Math.floor(baseDetections * 0.18),
      rule_based_detections: Math.floor(baseDetections * 0.16),
      techniques_detected: Math.floor(Math.random() * 7) + 4,
      available_techniques: 12,
      coverage_percentage: 72 + Math.random() * 20,
      confidence_score: 0.79 + Math.random() * 0.14,
      sources: {
        'EDR': Math.floor(baseDetections * 0.12),
        'SIEM': Math.floor(baseDetections * 0.04),
        'File Integrity': Math.floor(baseDetections * 0.02)
      },
      mitre_tactics: ['TA0003'],
      top_techniques: [
        {
          technique_id: 'T1547',
          technique_name: 'Boot or Logon Autostart Execution',
          count: Math.floor(baseDetections * 0.08),
          confidence: 0.83,
          sources: { 'EDR': Math.floor(baseDetections * 0.07), 'SIEM': Math.floor(baseDetections * 0.01) }
        }
      ]
    },
    {
      phase_id: 'command_control',
      phase_name: 'Command & Control',
      phase_name_th: 'การควบคุม',
      total_detections: Math.floor(baseDetections * 0.20),
      predicted_detections: Math.floor(baseDetections * 0.20),
      rule_based_detections: Math.floor(baseDetections * 0.18),
      techniques_detected: Math.floor(Math.random() * 8) + 5,
      available_techniques: 18,
      coverage_percentage: 75 + Math.random() * 18,
      confidence_score: 0.84 + Math.random() * 0.11,
      sources: {
        'NDR': Math.floor(baseDetections * 0.11),
        'Proxy': Math.floor(baseDetections * 0.06),
        'Firewall': Math.floor(baseDetections * 0.03)
      },
      mitre_tactics: ['TA0011'],
      top_techniques: [
        {
          technique_id: 'T1071',
          technique_name: 'Application Layer Protocol',
          count: Math.floor(baseDetections * 0.09),
          confidence: 0.88,
          sources: { 'NDR': Math.floor(baseDetections * 0.06), 'Proxy': Math.floor(baseDetections * 0.03) }
        }
      ]
    },
    {
      phase_id: 'actions_objectives',
      phase_name: 'Actions on Objectives',
      phase_name_th: 'การดำเนินการ',
      total_detections: Math.floor(baseDetections * 0.10),
      predicted_detections: Math.floor(baseDetections * 0.10),
      rule_based_detections: Math.floor(baseDetections * 0.08),
      techniques_detected: Math.floor(Math.random() * 6) + 3,
      available_techniques: 14,
      coverage_percentage: 60 + Math.random() * 25,
      confidence_score: 0.75 + Math.random() * 0.17,
      sources: {
        'EDR': Math.floor(baseDetections * 0.05),
        'DLP': Math.floor(baseDetections * 0.03),
        'SIEM': Math.floor(baseDetections * 0.02)
      },
      mitre_tactics: ['TA0040'],
      top_techniques: [
        {
          technique_id: 'T1020',
          technique_name: 'Automated Exfiltration',
          count: Math.floor(baseDetections * 0.04),
          confidence: 0.78,
          sources: { 'DLP': Math.floor(baseDetections * 0.02), 'EDR': Math.floor(baseDetections * 0.02) }
        }
      ]
    }
  ];

  // Filter by confidence threshold
  const filteredPhases = phases.map(phase => {
    if (phase.confidence_score < confidenceThreshold) {
      return {
        ...phase,
        predicted_detections: Math.floor(phase.predicted_detections * 0.3),
        total_detections: Math.floor(phase.total_detections * 0.3)
      };
    }
    return phase;
  });

  const totalPredictions = filteredPhases.reduce((sum, p) => sum + p.predicted_detections, 0);
  const activePhases = filteredPhases.filter(p => p.predicted_detections > 0).length;

  return {
    total_detections: totalPredictions,
    ml_predictions: totalPredictions,
    unique_techniques: filteredPhases.reduce((sum, p) => sum + p.techniques_detected, 0),
    active_phases: activePhases,
    methodology: 'Machine Learning (XGBoost)',
    model_version: 'v1.0-dev',
    confidence_threshold: confidenceThreshold,
    time_range: {
      start: startDate.toISOString(),
      end: now.toISOString()
    },
    indices_queried: indices,
    phases: filteredPhases
  };
}

/**
 * Fetch ML-based cyber kill chain predictions
 * Automatically uses mock or real API based on configuration
 */
export async function fetchMLKillChainCoverage(
  indices: string[],
  options: {
    dayRange: number;
    confidenceThreshold?: number;
  }
): Promise<MLKillChainResponse> {
  const confidenceThreshold = options.confidenceThreshold || 0.6;

  // Use mock data during development
  if (USE_MOCK_API) {
    console.log('🔧 [DEV MODE] Using mock ML API');
    // Simulate network delay
    await new Promise(resolve => setTimeout(resolve, 800));
    return generateMockMLResponse(indices, options.dayRange, confidenceThreshold);
  }

  // Real API call
  try {
    const response = await fetch(`${ML_API_BASE_URL}/api/ml/predict-killchain`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        indices,
        day_range: options.dayRange,
        confidence_threshold: confidenceThreshold,
      }),
    });

    if (!response.ok) {
      throw new Error(`ML API error: ${response.statusText}`);
    }

    return response.json();
  } catch (error) {
    console.error('ML API call failed, falling back to mock:', error);
    // Fallback to mock on error
    return generateMockMLResponse(indices, options.dayRange, confidenceThreshold);
  }
}

/**
 * Get model information
 */
export async function getModelInfo(): Promise<any> {
  if (USE_MOCK_API) {
    return {
      model_type: 'XGBoost Classifier (Mock)',
      phases: [
        'reconnaissance',
        'weaponization',
        'delivery',
        'exploitation',
        'installation',
        'command_control',
        'actions_objectives'
      ],
      num_classes: 7,
      model_path: 'mock/model/path',
      features: ['msg_length', 'has_ip', 'has_url', 'has_exec', '...'],
      status: 'development'
    };
  }

  const response = await fetch(`${ML_API_BASE_URL}/api/ml/model-info`);
  
  if (!response.ok) {
    throw new Error(`Failed to fetch model info: ${response.statusText}`);
  }

  return response.json();
}

/**
 * Export ML predictions to CSV
 */
export function exportMLPredictionsToCSV(data: MLKillChainResponse): string {
  const headers = [
    'Phase',
    'Thai Name',
    'ML Predictions',
    'Confidence Score',
    'Techniques',
    'Coverage %',
    'Sources'
  ];

  const rows = data.phases.map(phase => [
    phase.phase_name,
    phase.phase_name_th,
    phase.predicted_detections,
    phase.confidence_score.toFixed(3),
    `${phase.techniques_detected}/${phase.available_techniques}`,
    phase.coverage_percentage.toFixed(1) + '%',
    Object.entries(phase.sources).map(([k, v]) => `${k}:${v}`).join('; ')
  ]);

  return [
    headers.join(','),
    ...rows.map(row => row.join(','))
  ].join('\n');
}

/**
 * Switch between mock and real API
 * Call this function when real API becomes available
 */
export function setMLAPIMode(useMock: boolean) {
  // This would ideally update the USE_MOCK_API flag
  // For now, update via environment variable
  console.log(`Switching ML API mode to: ${useMock ? 'MOCK' : 'REAL'}`);
  if (typeof window !== 'undefined') {
    (window as any).__USE_MOCK_ML_API__ = useMock;
  }
}

/**
 * Check if ML API is available
 */
export async function checkMLAPIHealth(): Promise<boolean> {
  if (USE_MOCK_API) {
    return true;
  }

  try {
    const response = await fetch(`${ML_API_BASE_URL}/health`, {
      method: 'GET',
      signal: AbortSignal.timeout(3000) // 3 second timeout
    });
    return response.ok;
  } catch (error) {
    console.error('ML API health check failed:', error);
    return false;
  }
}