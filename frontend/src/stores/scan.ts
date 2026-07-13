import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import * as api from '@/api'
import type {
  ScanResponse,
  FindingItem,
  EvidenceItem,
  AgentLogItem,
  TaskInfo,
} from '@/api/types'

export const useScanStore = defineStore('scan', () => {
  // 状态
  const currentScan = ref<ScanResponse | null>(null)
  const findings = ref<FindingItem[]>([])
  const evidence = ref<EvidenceItem[]>([])
  const agentLogs = ref<AgentLogItem[]>([])
  const currentTask = ref<TaskInfo | null>(null)
  const loading = ref(false)
  const scanning = ref(false)
  const error = ref<string | null>(null)

  // 计算属性
  const summary = computed(() => currentScan.value?.summary)
  const riskScore = computed(() => summary.value?.risk_score ?? 0)
  const totalFindings = computed(() => findings.value.length)

  const findingsBySeverity = computed(() => {
    const map: Record<string, number> = { ERROR: 0, WARN: 0, INFO: 0, UNKNOWN: 0 }
    findings.value.forEach((f) => {
      const sev = f.severity?.toUpperCase() || 'UNKNOWN'
      map[sev] = (map[sev] || 0) + 1
    })
    return map
  })

  const findingsByVerdict = computed(() => {
    const map: Record<string, number> = { confirmed: 0, suspicious: 0, rejected: 0, pending: 0 }
    findings.value.forEach((f) => {
      const v = f.verdict || 'pending'
      map[v] = (map[v] || 0) + 1
    })
    return map
  })

  // 方法
  async function submitScan(request: api.ScanRequest) {
    scanning.value = true
    error.value = null
    try {
      const { data } = await api.submitScan(request)
      currentScan.value = data
      findings.value = data.findings
      evidence.value = data.evidence
      agentLogs.value = data.agent_logs
      return data
    } catch (e: any) {
      error.value = e.response?.data?.detail || e.message || '扫描失败'
      throw e
    } finally {
      scanning.value = false
    }
  }

  async function submitAsyncScan(request: api.ScanRequest) {
    scanning.value = true
    error.value = null
    try {
      const { data } = await api.submitAsyncScan(request)
      // 开始轮询任务状态
      pollTaskStatus(data.task_id)
      return data
    } catch (e: any) {
      error.value = e.response?.data?.detail || e.message || '提交扫描失败'
      scanning.value = false
      throw e
    }
  }

  async function pollTaskStatus(taskId: string) {
    const poll = async () => {
      try {
        const { data } = await api.getTaskStatus(taskId)
        currentTask.value = data

        if (data.state === 'COMPLETED' && data.result) {
          currentScan.value = data.result
          findings.value = data.result.findings
          evidence.value = data.result.evidence
          agentLogs.value = data.result.agent_logs
          scanning.value = false
          return
        }

        if (data.state === 'FAILED' || data.state === 'CANCELLED') {
          error.value = data.error || '扫描失败'
          scanning.value = false
          return
        }

        // 继续轮询
        setTimeout(poll, 2000)
      } catch {
        scanning.value = false
        error.value = '获取任务状态失败'
      }
    }
    poll()
  }

  async function fetchFindings(scanId?: string) {
    loading.value = true
    try {
      const { data } = await api.getFindings(scanId)
      findings.value = data
    } finally {
      loading.value = false
    }
  }

  async function fetchEvidence(scanId?: string) {
    loading.value = true
    try {
      const { data } = await api.getEvidence(scanId)
      evidence.value = data
    } finally {
      loading.value = false
    }
  }

  async function fetchAgentLogs(scanId?: string) {
    loading.value = true
    try {
      const { data } = await api.getAgentLogs(scanId)
      agentLogs.value = data
    } finally {
      loading.value = false
    }
  }

  function clear() {
    currentScan.value = null
    findings.value = []
    evidence.value = []
    agentLogs.value = []
    currentTask.value = null
    error.value = null
  }

  return {
    currentScan,
    findings,
    evidence,
    agentLogs,
    currentTask,
    loading,
    scanning,
    error,
    summary,
    riskScore,
    totalFindings,
    findingsBySeverity,
    findingsByVerdict,
    submitScan,
    submitAsyncScan,
    fetchFindings,
    fetchEvidence,
    fetchAgentLogs,
    clear,
  }
})
