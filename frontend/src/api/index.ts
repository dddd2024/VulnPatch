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

// 请求拦截器
http.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// 响应拦截器
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

// 健康检查
export const getHealth = () => http.get<HealthStatus>('/health')

// 扫描
export const submitScan = (data: ScanRequest) => http.post<ScanResponse>('/scan', data)

// 异步扫描
export const submitAsyncScan = (data: ScanRequest) => http.post<{ task_id: string }>('/scan/async', data)

// 任务状态
export const getTaskStatus = (taskId: string) => http.get<TaskInfo>(`/tasks/${taskId}`)

// 获取发现
export const getFindings = (scanId?: string) =>
  http.get<FindingItem[]>('/findings', { params: scanId ? { scan_id: scanId } : {} })

// 获取证据
export const getEvidence = (scanId?: string) =>
  http.get<EvidenceItem[]>('/evidence', { params: scanId ? { scan_id: scanId } : {} })

// 获取 Agent 日志
export const getAgentLogs = (scanId?: string) =>
  http.get<AgentLogItem[]>('/agents/logs', { params: scanId ? { scan_id: scanId } : {} })

// 获取报告
export const getReportJson = (scanId?: string) =>
  http.get('/report/json', { params: scanId ? { scan_id: scanId } : {} })

export const getReportMarkdown = (scanId?: string) =>
  http.get('/report/markdown', { params: scanId ? { scan_id: scanId } : {} }, { responseType: 'text' } as any)

export const getReportHtml = (scanId?: string) =>
  http.get('/report/html', { params: scanId ? { scan_id: scanId } : {} }, { responseType: 'text' } as any)

// 获取扫描历史
export const getScanHistory = () => http.get('/scans')

// 认证
export const login = (username: string, password: string) =>
  http.post('/auth/login', { username, password })

export const getAuthStatus = () => http.get('/auth/status')

export default http

// 比赛展示 / 自主调度 / 案例进化
export const runCompetitionDemo = (data: import('./types').DemoRunRequest) =>
  http.post<import('./types').DemoRunResponse>('/demo/run', data)

export const resetCompetitionDemo = () => http.post('/demo/reset')
export const getCompetitionDemoState = () => http.get('/demo/state')
export const getRoutingDecisions = () => http.get<import('./types').RoutingDecision[]>('/routing/decisions')
export const getRepairCases = (params?: { cwe?: string; outcome?: string; limit?: number }) =>
  http.get<import('./types').RepairCase[]>('/cases', { params })
export const getCaseEvents = (limit = 200) =>
  http.get<import('./types').CaseEvent[]>('/cases/events', { params: { limit } })
export const getCaseRetrievals = (limit = 200) =>
  http.get<import('./types').CaseEvent[]>('/cases/retrievals', { params: { limit } })
export const getModelHealth = () => http.get('/models/health')
