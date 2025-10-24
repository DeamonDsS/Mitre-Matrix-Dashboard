import type { MitreTechnique, MitreApiResponse, MitreStats } from '../types/mitre';

// Backend API URL
const BACKEND_API_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:8000';

export async function fetchMitreTechniques(
  esIndex: string,
  filters: {
    search?: string;
    tactic?: string;
    severity?: string;
  },
  pagination: { // 2. เพิ่ม parameter สำหรับ pagination
    page: number;
    size: number;
  }
): Promise<MitreApiResponse> { // 3. เปลี่ยน return type
  try {
    const url = `${BACKEND_API_URL}/api/search?index=${encodeURIComponent(esIndex)}`;
    
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        search: filters.search || null,
        tactic: filters.tactic || 'all',
        severity: filters.severity || 'all',
        size: pagination.size, // 4. ส่ง size และ page ไปใน body
        page: pagination.page,
      }),
    });

    if (!response.ok) {
      throw new Error(`Backend API error: ${response.status}`);
    }

    const data: MitreApiResponse = await response.json();
    return data;

  } catch (error) {
    console.error('Error fetching from Backend API:', error);
    throw error;
  }
}

export async function fetchStats(
  esIndex: string,
  filters: {
    search?: string;
    tactic?: string;
    severity?: string;
  }
): Promise<MitreStats> {
  try {
    const url = `${BACKEND_API_URL}/api/stats?index=${encodeURIComponent(esIndex)}`;
    
    const response = await fetch(url, {
      method: 'POST', // เปลี่ยนเป็น POST
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        search: filters.search || null,
        tactic: filters.tactic || 'all',
        severity: filters.severity || 'all',
      }),
    });

    if (!response.ok) {
      throw new Error(`Backend API error for stats: ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    console.error('Error fetching stats from Backend API:', error);
    // คืนค่า default เพื่อไม่ให้ UI พัง
    return { total: 0, critical: 0, high: 0, medium: 0, low: 0, tactics: 0 };
  }
}

// Mock data function
export function getMockData(): MitreTechnique[] {
  return [
    {
      id: 'mock-1',
      technique_id: 'Event-4624',
      technique_name: 'Account Logon Success',
      tactic: 'Initial Access',
      description: 'Demo event: Successful user logon to the system',
      severity: 'low',
      timestamp: new Date().toISOString(),
      platform: ['Windows'],
      event_code: '4624',
      host_name: 'DEMO-HOST',
      user_name: 'demo_user',
      process_name: '',
      log_level: 'info',
      channel: 'Security',
    },
    {
      id: 'mock-2',
      technique_id: 'Event-4625',
      technique_name: 'Account Logon Failed',
      tactic: 'Initial Access',
      description: 'Demo event: Failed logon attempt detected',
      severity: 'medium',
      timestamp: new Date().toISOString(),
      platform: ['Windows'],
      event_code: '4625',
      host_name: 'DEMO-HOST',
      user_name: 'attacker',
      process_name: '',
      log_level: 'warning',
      channel: 'Security',
    },
    {
      id: 'mock-3',
      technique_id: 'Event-4672',
      technique_name: 'Special Privileges Assigned',
      tactic: 'Privilege Escalation',
      description: 'Demo event: Special privileges assigned to new logon',
      severity: 'high',
      timestamp: new Date().toISOString(),
      platform: ['Windows'],
      event_code: '4672',
      host_name: 'DEMO-HOST',
      user_name: 'admin',
      process_name: '',
      log_level: 'info',
      channel: 'Security',
    },
    {
      id: 'mock-4',
      technique_id: 'Event-1102',
      technique_name: 'Audit Log Cleared',
      tactic: 'Defense Evasion',
      description: 'Demo event: Security audit log was cleared',
      severity: 'critical',
      timestamp: new Date().toISOString(),
      platform: ['Windows'],
      event_code: '1102',
      host_name: 'DEMO-HOST',
      user_name: 'system',
      process_name: '',
      log_level: 'critical',
      channel: 'Security',
    },
  ];
}