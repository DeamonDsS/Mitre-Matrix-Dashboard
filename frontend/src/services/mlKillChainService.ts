// services/mlKillChainService.ts
import { fetchCyberKillChainCoverage } from "./killChainService";

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
  predicted_detections: number;  // NEW: ML predictions
  rule_based_detections: number; // Legacy
  techniques_detected: number;
  available_techniques: number;
  coverage_percentage: number;
  confidence_score: number;  // NEW: Average ML confidence
  sources: Record<string, number>;
  mitre_tactics: string[];
  top_techniques: TechniqueDetection[];
}

export interface MLKillChainResponse {
  total_detections: number;
  ml_predictions: number;  // NEW: Count of ML predictions
  unique_techniques: number;
  active_phases: number;
  methodology: string;
  model_version: string;  // NEW: Track model version
  confidence_threshold: number;  // NEW: Applied threshold
  time_range: {
    start: string;
    end: string;
  };
  indices_queried: string[];
  phases: MLPhaseCoverage[];
}

export interface ModelInfo {
  model_type: string;
  phases: string[];
  num_classes: number;
  model_path: string;
  features: string[];
}

const ML_API_BASE_URL = import.meta.env.REACT_APP_ML_API_URL || 'http://localhost:8000';

/**
 * Fetch ML-based cyber kill chain predictions
 */
export async function fetchMLKillChainCoverage(
  indices: string[],
  options: {
    dayRange: number;
    confidenceThreshold?: number;
  }
): Promise<MLKillChainResponse> {
  const response = await fetch(`${ML_API_BASE_URL}/api/ml/predict-killchain`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      indices,
      day_range: options.dayRange,
      confidence_threshold: options.confidenceThreshold || 0.6,
    }),
  });

  if (!response.ok) {
    throw new Error(`ML API error: ${response.statusText}`);
  }

  return response.json();
}

/**
 * Get model information
 */
export async function getModelInfo(): Promise<ModelInfo> {
  const response = await fetch(`${ML_API_BASE_URL}/api/ml/model-info`);
  
  if (!response.ok) {
    throw new Error(`Failed to fetch model info: ${response.statusText}`);
  }

  return response.json();
}

/**
 * Compare ML vs Rule-Based predictions
 */
export async function compareMLvsRules(
  indices: string[],
  dayRange: number
): Promise<{
  ml: MLKillChainResponse;
  rules: any; // Your existing rule-based response
  agreement_rate: number;
  phase_differences: Array<{
    phase: string;
    ml_count: number;
    rule_count: number;
    difference: number;
  }>;
}> {
  // Fetch both ML and rule-based predictions
  const [mlResult, ruleResult] = await Promise.all([
    fetchMLKillChainCoverage(indices, { dayRange, confidenceThreshold: 0.6 }),
    fetchCyberKillChainCoverage(indices, { dayRange, search: null }),
    // Your existing fetchCyberKillChainCoverage() call here
  ]);

  // Compare results
  const phaseDiffs = mlResult.phases.map((mlPhase, idx) => {
    const rulePhase = ruleResult.phases[idx];
    return {
      phase: mlPhase.phase_name,
      ml_count: mlPhase.predicted_detections,
      rule_count: rulePhase.total_detections,
      difference: Math.abs(mlPhase.predicted_detections - rulePhase.total_detections),
    };
  });

  const agreementRate = phaseDiffs.reduce((sum, diff) => {
    return sum + (1 - Math.min(diff.difference / Math.max(diff.ml_count, diff.rule_count, 1), 1));
  }, 0) / phaseDiffs.length;

  return {
    ml: mlResult,
    rules: ruleResult,
    agreement_rate: agreementRate * 100,
    phase_differences: phaseDiffs,
  };
}

/**
 * Get confidence distribution
 */
export function getConfidenceDistribution(phases: MLPhaseCoverage[]): {
  high: number;    // > 0.8
  medium: number;  // 0.6 - 0.8
  low: number;     // < 0.6
} {
  return phases.reduce(
    (acc, phase) => {
      if (phase.confidence_score > 0.8) acc.high++;
      else if (phase.confidence_score >= 0.6) acc.medium++;
      else acc.low++;
      return acc;
    },
    { high: 0, medium: 0, low: 0 }
  );
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