import axios from 'axios'
import type {
  ScanRequest,
  ScanResponse,
  FindingItem,
  EvidenceItem,
  AgentLogItem,
  TaskInfo,
  HealthStatus,
} from './types'

const http = axios.create({
  baseURL: '/api',
  timeout: 120000,
})

http.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

http.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('access_token')
      window.location.reload()
    }
    return Promise.reject(error)
  }
)

export const getHealth = () => http.get<HealthStatus>('/health')
export const submitScan = (data: ScanRequest) => http.post<ScanResponse>('/scan', data)
export const submitAsyncScan = (data: ScanRequest) => http.post<{ task_id: string }>('/scan/async', data)
export const getTaskStatus = (taskId: string) => http.get<TaskInfo>(`/tasks/${taskId}`)
export const getFindings = (scanId?: string) => http.get<FindingItem[]>('/findings', { params: scanId ? { scan_id: scanId } : {} })
export const getEvidence = (scanId?: string) => http.get<EvidenceItem[]>('/evidence', { params: scanId ? { scan_id: scanId } : {} })
export const getAgentLogs = (scanId?: string) => http.get<AgentLogItem[]>('/agents/logs', { params: scanId ? { scan_id: scanId } : {} })
export const getReportJson = (scanId?: string) => http.get('/report/json', { params: scanId ? { scan_id: scanId } : {} })
export const getReportMarkdown = (scanId?: string) => http.get('/report/markdown', { params: scanId ? { scan_id: scanId } : {} }, { responseType: 'text' } as any)
export const getReportHtml = (scanId?: string) => http.get('/report/html', { params: scanId ? { scan_id: scanId } : {} }, { responseType: 'text' } as any)
export const getScanHistory = () => http.get('/scans')
export const login = (username: string, password: string) => http.post('/auth/login', { username, password })
export const getAuthStatus = () => http.get('/auth/status')

export default http

export const runCompetitionDemo = (data: import('./types').DemoRunRequest) => http.post<import('./types').DemoRunResponse>('/demo/run', data)
export const resetCompetitionDemo = () => http.post('/demo/reset')
export const getCompetitionDemoState = () => http.get('/demo/state')
export const getRoutingDecisions = () => http.get<import('./types').RoutingDecision[]>('/routing/decisions')
export const getRepairCases = (params?: { cwe?: string; outcome?: string; limit?: number }) => http.get<import('./types').RepairCase[]>('/cases', { params })
export const getCaseEvents = (limit = 200) => http.get<import('./types').CaseEvent[]>('/cases/events', { params: { limit } })
export const getCaseRetrievals = (limit = 200) => http.get<import('./types').CaseEvent[]>('/cases/retrievals', { params: { limit } })
export const getModelHealth = () => http.get('/models/health')
