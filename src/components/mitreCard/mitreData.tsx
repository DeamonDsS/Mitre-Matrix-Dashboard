// mitreData.tsx - Enhanced with Multi-Index Support
import type { MitreTacticFramework as MitreTactic, MitreTechniqueFramework as MitreTechnique } from '../../types/mitre';

const TACTIC_ORDER = [
  'reconnaissance',       
  'resource-development',
  'initial-access',
  'execution',
  'persistence',
  'privilege-escalation',
  'defense-evasion',
  'credential-access',
  'discovery',
  'lateral-movement',
  'collection',
  'command-and-control',
  'exfiltration',
  'impact'
];

// ===================================
// Windows Event ID Mappings
// ===================================

const TECHNIQUE_SPECIFIC_EVENT_MAP: Record<string, number[]> = {
  // Initial Access
  'T1078': [4624, 4625],                    // Valid Accounts
  'T1133': [4624, 4648],                    // External Remote Services
  'T1190': [],                              // Exploit Public-Facing Application
  'T1566': [],                              // Phishing
  
  // Execution
  'T1059': [4688],                          // Command and Scripting Interpreter
  'T1059.001': [4104, 4103],                // PowerShell
  'T1059.003': [4688],                      // Windows Command Shell
  'T1047': [4688, 5857, 5858, 5859, 5860, 5861], // WMI
  'T1053': [4698, 4699, 4700, 4701, 106],   // Scheduled Task/Job
  'T1106': [4688],                          // Native API
  'T1129': [7],                             // Shared Modules
  'T1203': [],                              // Exploitation for Client Execution
  'T1204': [4688],                          // User Execution
  'T1559': [],                              // Inter-Process Communication
  'T1569': [4697, 7045],                    // System Services
  
  // Persistence
  'T1098': [4720, 4722, 4738],              // Account Manipulation
  'T1136': [4720],                          // Create Account
  'T1197': [],                              // BITS Jobs
  'T1505': [7045, 4697],                    // Server Software Component
  'T1543': [7045, 4697],                    // Create or Modify System Process
  'T1547': [4657, 13],                      // Boot or Logon Autostart Execution
  'T1574': [7045],                          // Hijack Execution Flow
  
  // Privilege Escalation
  'T1068': [],                              // Exploitation for Privilege Escalation
  'T1134': [4672, 4673, 4674],              // Access Token Manipulation
  'T1484': [5136, 5137, 5138, 5139, 5141],  // Domain Policy Modification
  'T1548': [4672],                          // Abuse Elevation Control Mechanism
  'T1055': [8, 10],                         // Process Injection
  
  // Defense Evasion
  'T1027': [],                              // Obfuscated Files or Information
  'T1070': [1102, 1100, 104],               // Indicator Removal on Host
  'T1112': [4657, 12, 13],                  // Modify Registry
  'T1140': [],                              // Deobfuscate/Decode Files or Information
  'T1202': [],                              // Indirect Command Execution
  'T1218': [4688],                          // System Binary Proxy Execution
  'T1222': [4670],                          // File and Directory Permissions Modification
  'T1480': [],                              // Execution Guardrails
  'T1562': [4719, 4688],                    // Impair Defenses
  'T1564': [4663],                          // Hide Artifacts
  
  // Credential Access
  'T1003': [4688, 4656, 4663],              // OS Credential Dumping
  'T1110': [4625, 4771, 4776],              // Brute Force
  'T1111': [],                              // Two-Factor Authentication Interception
  'T1187': [4625],                          // Forced Authentication
  'T1212': [],                              // Exploitation for Credential Access
  'T1528': [],                              // Steal Application Access Token
  'T1539': [],                              // Steal Web Session Cookie
  'T1552': [4663],                          // Unsecured Credentials
  'T1555': [],                              // Credentials from Password Stores
  'T1556': [4657],                          // Modify Authentication Process
  
  // Discovery
  'T1007': [4688],                          // System Service Discovery
  'T1012': [4663],                          // Query Registry
  'T1016': [4688],                          // System Network Configuration Discovery
  'T1018': [4688],                          // Remote System Discovery
  'T1033': [4688, 4624],                    // System Owner/User Discovery
  'T1046': [5156],                          // Network Service Scanning
  'T1049': [4688],                          // System Network Connections Discovery
  'T1057': [4688],                          // Process Discovery
  'T1069': [4688, 4799],                    // Permission Groups Discovery
  'T1082': [4688],                          // System Information Discovery
  'T1083': [4663],                          // File and Directory Discovery
  'T1087': [4688, 4798, 4799],              // Account Discovery
  'T1124': [4688],                          // System Time Discovery
  'T1135': [5140, 5145],                    // Network Share Discovery
  'T1201': [],                              // Password Policy Discovery
  'T1217': [],                              // Browser Bookmark Discovery
  'T1518': [4688],                          // Software Discovery
  'T1580': [],                              // Cloud Infrastructure Discovery
  
  // Lateral Movement
  'T1021': [4624, 4648, 4672],              // Remote Services
  'T1021.001': [4624, 4648],                // Remote Desktop Protocol
  'T1021.002': [4624, 4648],                // SMB/Windows Admin Shares
  'T1021.003': [4624, 4648],                // Distributed Component Object Model
  'T1021.006': [4624, 4648],                // Windows Remote Management
  'T1080': [],                              // Taint Shared Content
  'T1091': [4663],                          // Replication Through Removable Media
  'T1534': [4624],                          // Internal Spearphishing
  'T1550': [4624, 4648, 4672],              // Use Alternate Authentication Material
  
  // Collection
  'T1005': [4663],                          // Data from Local System
  'T1025': [4663],                          // Data from Removable Media
  'T1039': [5140, 5145],                    // Data from Network Shared Drive
  'T1074': [4663],                          // Data Staged
  'T1114': [],                              // Email Collection
  'T1115': [],                              // Clipboard Data
  'T1119': [],                              // Automated Collection
  'T1123': [],                              // Audio Capture
  'T1125': [],                              // Video Capture
  'T1185': [],                              // Man in the Browser
  'T1213': [],                              // Data from Information Repositories
  'T1560': [4688],                          // Archive Collected Data
  
  // Command and Control
  'T1071': [5156, 3],                       // Application Layer Protocol
  'T1090': [5156],                          // Proxy
  'T1095': [5156],                          // Non-Application Layer Protocol
  'T1102': [5156],                          // Web Service
  'T1104': [],                              // Multi-Stage Channels
  'T1105': [5156],                          // Ingress Tool Transfer
  'T1132': [],                              // Data Encoding
  'T1205': [],                              // Traffic Signaling
  'T1219': [4688],                          // Remote Access Software
  'T1568': [],                              // Dynamic Resolution
  'T1571': [5156],                          // Non-Standard Port
  'T1572': [],                              // Protocol Tunneling
  'T1573': [],                              // Encrypted Channel
  
  // Exfiltration
  'T1020': [],                              // Automated Exfiltration
  'T1030': [],                              // Data Transfer Size Limits
  'T1041': [5156],                          // Exfiltration Over C2 Channel
  'T1048': [5156],                          // Exfiltration Over Alternative Protocol
  'T1052': [4663],                          // Exfiltration Over Physical Medium
  'T1567': [5156],                          // Exfiltration Over Web Service
  
  // Impact
  'T1485': [4663, 4660],                    // Data Destruction
  'T1486': [4663],                          // Data Encrypted for Impact
  'T1489': [7036, 7040],                    // Service Stop
  'T1490': [4688],                          // Inhibit System Recovery
  'T1491': [],                              // Defacement
  'T1495': [6],                             // Firmware Corruption
  'T1496': [4688],                          // Resource Hijacking
  'T1498': [],                              // Network Denial of Service
  'T1499': [],                              // Endpoint Denial of Service
  'T1529': [6008, 1074],                    // System Shutdown/Reboot
  'T1531': [4725, 4726],                    // Account Access Removal
  'T1561': [4688],                          // Disk Wipe
};

const DATA_SOURCE_EVENT_MAP: Record<string, number[]> = {
  'Process: Process Creation': [4688],
  'Command: Command Execution': [4688, 4104, 800],
  'Service: Service Creation': [7045, 4697],
  'Windows Registry': [4657, 12, 13],
  'User Account': [4720, 4722, 4738, 4624, 4625, 4648],
  'Logon Session': [4624, 4648, 4672],
  'Scheduled Job': [4698, 4699, 4700, 4701, 106],
  'File': [4663, 4656, 2, 11, 23],
  'Network Traffic': [5156, 3],
  'Network Share': [5140, 5145],
  'Active Directory': [4662, 4661, 5136],
  'Windows Event Logs': [1102, 1100, 104],
  'Driver': [6, 4697],
  'Module': [7],
  'Process: Process Termination': [4689],
  'Process: OS API Execution': [10]
};

// ===================================
// Helper Functions
// ===================================

/**
 * Get parent technique ID from sub-technique
 * Example: T1059.001 -> T1059
 */
function getParentTechniqueId(techniqueId: string): string | null {
  const match = techniqueId.match(/^(T\d+)\./);
  return match ? match[1] : null;
}

/**
 * Get event IDs for a specific technique
 * Priority: Specific mapping > Parent mapping > Data source mapping
 */
export function getEventIdsForTechnique(techniqueId: string, dataSources: string[]): number[] {
  // 1. Check technique-specific mapping
  if (TECHNIQUE_SPECIFIC_EVENT_MAP[techniqueId]) {
    return TECHNIQUE_SPECIFIC_EVENT_MAP[techniqueId];
  }
  
  // 2. Check parent technique mapping (for sub-techniques)
  const parentId = getParentTechniqueId(techniqueId);
  if (parentId && TECHNIQUE_SPECIFIC_EVENT_MAP[parentId]) {
    console.log(`ℹ️ Using parent technique mapping: ${techniqueId} -> ${parentId}`);
    return TECHNIQUE_SPECIFIC_EVENT_MAP[parentId];
  }
  
  // 3. Fallback to data source mapping
  return mapDataSourcesToEventIds(dataSources);
}

export function mapDataSourcesToEventIds(dataSources: string[]): number[] {
  const eventIds = new Set<number>();
  dataSources.forEach(ds => {
    Object.entries(DATA_SOURCE_EVENT_MAP).forEach(([key, ids]) => {
      if (ds.includes(key) || key.includes(ds)) {
        ids.forEach(id => eventIds.add(id));
      }
    });
  });
  return Array.from(eventIds);
}

/**
 * Check if technique is detectable
 * Some techniques have no Windows event IDs but are still valid
 */
export function isTechniqueDetectable(techniqueId: string, dataSources: string[]): boolean {
  const eventIds = getEventIdsForTechnique(techniqueId, dataSources);
  return eventIds.length > 0;
}

/**
 * Get detection coverage statistics
 */
export function getDetectionCoverage(techniques: MitreTechnique[]): {
  total: number;
  detectable: number;
  undetectable: number;
  percentage: number;
} {
  const total = techniques.length;
  const detectable = techniques.filter(t => t.eventIds.length > 0).length;
  const undetectable = total - detectable;
  const percentage = total > 0 ? Math.round((detectable / total) * 100) : 0;
  
  return { total, detectable, undetectable, percentage };
}

// ===================================
// Main Data Loading
// ===================================

export async function loadMitreData(): Promise<{
  tactics: MitreTactic[];
  techniques: MitreTechnique[];
}> {
  const response = await fetch('/data/enterprise-attack.json');
  const data = await response.json();

  const tactics = data.objects
    .filter((obj: any) => obj.type === 'x-mitre-tactic')
    .map((tactic: any) => ({
      id: tactic.external_references?.find((ref: any) => ref.source_name === 'mitre-attack')?.external_id || '',
      name: tactic.name,
      description: tactic.description,
      shortName: tactic.x_mitre_shortname || tactic.name
    }))
    .sort((a: MitreTactic, b: MitreTactic) =>
      TACTIC_ORDER.indexOf(a.shortName) - TACTIC_ORDER.indexOf(b.shortName)
    );

  const techniques = data.objects
    .filter((obj: any) => {
      const isWindowsTechnique = obj.x_mitre_platforms?.some((p: string) => 
        p.toLowerCase().includes('windows')
      );
      
      const isReconOrResourceDev = obj.kill_chain_phases?.some((phase: any) => 
        phase.phase_name === 'reconnaissance' || 
        phase.phase_name === 'resource-development'
      );
      
      return obj.type === 'attack-pattern' &&
        !obj.revoked &&
        !obj.x_mitre_deprecated &&
        (isWindowsTechnique || isReconOrResourceDev);
    })
    .map((tech: any) => {
      const externalId = tech.external_references?.find(
        (ref: any) => ref.source_name === 'mitre-attack'
      )?.external_id || '';

      const tactics = tech.kill_chain_phases?.map(
        (phase: any) => phase.phase_name
      ) || [];

      const dataSources = tech.x_mitre_data_sources || [];
      
      // Get event IDs with fallback to parent technique
      const eventIds = getEventIdsForTechnique(externalId, dataSources);

      return {
        id: externalId,
        name: tech.name,
        description: tech.description,
        tactics,
        platforms: tech.x_mitre_platforms || [],
        dataSources,
        detection: tech.x_mitre_detection || '',
        eventIds
      };
    })
    .filter((tech: MitreTechnique) => tech.id.startsWith('T'));

  // Log detection coverage statistics
  const coverage = getDetectionCoverage(techniques);
  console.log(`📊 Detection Coverage: ${coverage.detectable}/${coverage.total} (${coverage.percentage}%)`);
  console.log(`   ✅ Detectable: ${coverage.detectable}`);
  console.log(`   ❌ Undetectable: ${coverage.undetectable}`);

  return { tactics, techniques };
}

// ===================================
// Severity & Display Helpers
// ===================================

export function getSeverityColor(severity: string): string {
  switch (severity) {
    case 'critical': return 'bg-red-500';
    case 'high': return 'bg-orange-500';
    case 'medium': return 'bg-yellow-500';
    case 'low': return 'bg-blue-500';
    default: return 'bg-gray-300';
  }
}

export function getSeverityText(severity: string): string {
  return severity === 'none' ? 'Not Detected' : severity.toUpperCase();
}

export function getSeverityBadgeColor(severity: string): string {
  switch (severity) {
    case 'critical': return 'bg-red-600 text-white';
    case 'high': return 'bg-orange-600 text-white';
    case 'medium': return 'bg-yellow-600 text-white';
    case 'low': return 'bg-blue-600 text-white';
    default: return 'bg-gray-600 text-white';
  }
}

// ===================================
// Export for Testing/Debugging
// ===================================

export const __testing__ = {
  TECHNIQUE_SPECIFIC_EVENT_MAP,
  DATA_SOURCE_EVENT_MAP,
  getParentTechniqueId,
  getEventIdsForTechnique,
  isTechniqueDetectable,
  getDetectionCoverage
};