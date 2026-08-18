<template>
  <div class="findings-page">
    <el-card shadow="hover">
      <template #header>
        <div style="display: flex; justify-content: space-between; align-items: center">
          <span>漏洞发现列表</span>
          <div style="display: flex; gap: 8px">
            <el-select v-model="filterSeverity" placeholder="筛选等级" clearable size="small" style="width: 120px">
              <el-option label="ERROR" value="ERROR" />
              <el-option label="WARN" value="WARN" />
              <el-option label="INFO" value="INFO" />
            </el-select>
            <el-select v-model="filterVerdict" placeholder="筛选裁决" clearable size="small" style="width: 120px">
              <el-option label="已确认" value="confirmed" />
              <el-option label="可疑" value="suspicious" />
              <el-option label="已排除" value="rejected" />
              <el-option label="待定" value="pending" />
            </el-select>
            <el-button size="small" @click="scanStore.fetchFindings()">刷新</el-button>
          </div>
        </div>
      </template>

      <el-table :data="filteredFindings" stripe style="width: 100%" v-loading="scanStore.loading">
        <el-table-column type="expand">
          <template #default="{ row }">
            <div style="padding: 12px 24px">
              <el-descriptions :column="2" border size="small">
                <el-descriptions-item label="规则 ID">{{ row.rule_id }}</el-descriptions-item>
                <el-descriptions-item label="CWE">{{ row.cwe || '-' }}</el-descriptions-item>
                <el-descriptions-item label="检测引擎">{{ row.engine }}</el-descriptions-item>
                <el-descriptions-item label="置信度">{{ row.confidence }}</el-descriptions-item>
                <el-descriptions-item label="风险评分">{{ row.risk_score ?? '-' }}</el-descriptions-item>
                <el-descriptions-item label="裁决">{{ verdictLabel(row.verdict) }}</el-descriptions-item>
                <el-descriptions-item label="描述" :span="2">{{ row.message }}</el-descriptions-item>
              </el-descriptions>
              <div v-if="row.snippet" style="margin-top: 12px">
                <strong>代码片段:</strong>
                <pre class="code-snippet"><code>{{ row.snippet }}</code></pre>
              </div>
            </div>
          </template>
        </el-table-column>
        <el-table-column prop="type" label="漏洞类型" width="180" />
        <el-table-column prop="severity" label="等级" width="100">
          <template #default="{ row }">
            <el-tag :type="severityTagType(row.severity)" size="small">{{ row.severity }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="confidence" label="置信度" width="90" />
        <el-table-column prop="file_path" label="文件路径" min-width="180" show-overflow-tooltip />
        <el-table-column prop="start_line" label="起始行" width="80" />
        <el-table-column prop="verdict" label="裁决" width="100">
          <template #default="{ row }">
            <el-tag :type="verdictTagType(row.verdict)" size="small">{{ verdictLabel(row.verdict) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="110" fixed="right">
          <template #default="{ row }">
            <el-button type="primary" link :loading="repairingId === row.id" @click="generateRepair(row)">生成修复</el-button>
          </template>
        </el-table-column>
      </el-table>

      <el-empty v-if="filteredFindings.length === 0 && !scanStore.loading" description="暂无漏洞数据" />
    </el-card>

    <el-drawer v-model="repairDrawer" title="漏洞修复与验证" size="62%">
      <template v-if="repairResult">
        <el-alert
          :title="repairResult.verification.passed ? '修复已通过确定性验证' : '候选修复未通过全部验证'"
          :type="repairResult.verification.passed ? 'success' : 'warning'"
          :closable="false"
          show-icon
          style="margin-bottom: 16px"
        />

        <el-descriptions :column="2" border size="small">
          <el-descriptions-item label="选择模型">
            {{ repairResult.routing_decision.selected_provider }} / {{ repairResult.routing_decision.selected_model || '-' }}
          </el-descriptions-item>
          <el-descriptions-item label="修复策略">{{ repairResult.patch.strategy }}</el-descriptions-item>
          <el-descriptions-item label="路由理由" :span="2">
            <el-tag v-for="reason in repairResult.routing_decision.reason_codes" :key="reason" size="small" style="margin: 2px">{{ reason }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="使用历史案例">
            {{ repairResult.patch.historical_cases_used.join(', ') || '无' }}
          </el-descriptions-item>
          <el-descriptions-item label="规避历史案例">
            {{ repairResult.patch.historical_cases_avoided.join(', ') || '无' }}
          </el-descriptions-item>
          <el-descriptions-item label="新案例结果">
            <el-tag :type="repairResult.evolved_case.outcome === 'POSITIVE' ? 'success' : 'danger'">
              {{ repairResult.evolved_case.outcome }} / trust {{ repairResult.evolved_case.trust_score }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="Patch ID">{{ repairResult.patch.patch_id }}</el-descriptions-item>
        </el-descriptions>

        <h4>Patch Diff</h4>
        <pre class="code-snippet diff"><code>{{ repairResult.patch.diff || '无代码差异' }}</code></pre>

        <h4>确定性验证</h4>
        <el-table :data="repairResult.verification.checks" size="small" border>
          <el-table-column prop="name" label="检查" width="150" />
          <el-table-column prop="status" label="状态" width="100">
            <template #default="{ row }">
              <el-tag :type="checkTagType(row.status)" size="small">{{ row.status }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="details" label="证据" min-width="320" />
        </el-table>
      </template>
    </el-drawer>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { useScanStore } from '@/stores/scan'
import { repairFinding } from '@/api'
import type { FindingItem, RepairResponse } from '@/api/types'

const scanStore = useScanStore()
const filterSeverity = ref('')
const filterVerdict = ref('')
const repairDrawer = ref(false)
const repairResult = ref<RepairResponse | null>(null)
const repairingId = ref('')
type TagType = 'primary' | 'success' | 'info' | 'warning' | 'danger'

const filteredFindings = computed(() => {
  let list = scanStore.findings
  if (filterSeverity.value) list = list.filter(f => f.severity?.toUpperCase() === filterSeverity.value)
  if (filterVerdict.value) list = list.filter(f => f.verdict === filterVerdict.value)
  return list
})

function severityTagType(severity: string): TagType {
  return ({ ERROR: 'danger', WARN: 'warning', INFO: 'info', UNKNOWN: 'info' } as Record<string, TagType>)[severity?.toUpperCase()] || 'info'
}
function verdictTagType(verdict: string): TagType {
  return ({ confirmed: 'danger', suspicious: 'warning', rejected: 'success', pending: 'info' } as Record<string, TagType>)[verdict] || 'info'
}
function checkTagType(status: string): TagType {
  return ({ pass: 'success', fail: 'danger', skipped: 'info' } as Record<string, TagType>)[status] || 'info'
}
function verdictLabel(verdict: string) {
  return ({ confirmed: '已确认', suspicious: '可疑', rejected: '已排除', pending: '待定' } as Record<string, string>)[verdict] || verdict || '待定'
}

async function generateRepair(row: FindingItem) {
  const scanId = scanStore.currentScan?.scan_id
  if (!scanId) {
    ElMessage.warning('请先在安全扫描页面完成一次扫描，再生成修复')
    return
  }
  repairingId.value = row.id
  try {
    const { data } = await repairFinding({ scan_id: scanId, finding_id: row.id, sensitivity: 'public', repair_variant: 'auto' })
    repairResult.value = data
    repairDrawer.value = true
  } catch (e: any) {
    ElMessage.error(e.response?.data?.detail || e.message || '生成修复失败')
  } finally {
    repairingId.value = ''
  }
}

onMounted(() => {
  if (scanStore.findings.length === 0) scanStore.fetchFindings()
})
</script>

<style lang="scss" scoped>
.code-snippet {
  background: #1e1e1e;
  color: #d4d4d4;
  padding: 12px 16px;
  border-radius: 6px;
  overflow-x: auto;
  font-size: 13px;
  line-height: 1.5;
  margin-top: 8px;
  white-space: pre-wrap;
}
.diff { max-height: 360px; }
h4 { margin: 18px 0 8px; }
</style>
