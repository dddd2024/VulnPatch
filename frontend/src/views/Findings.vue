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
                <el-descriptions-item label="风险评分">{{ row.risk_score }}</el-descriptions-item>
                <el-descriptions-item label="裁决">{{ verdictLabel(row.verdict) }}</el-descriptions-item>
                <el-descriptions-item label="描述" :span="2">{{ row.message }}</el-descriptions-item>
              </el-descriptions>
              <div v-if="row.snippet" style="margin-top: 12px">
                <strong>代码片段:</strong>
                <pre class="code-snippet"><code>{{ row.snippet }}</code></pre>
              </div>
              <div v-if="row.call_chain && row.call_chain.length" style="margin-top: 12px">
                <strong>调用链:</strong>
                <el-tag v-for="(item, idx) in row.call_chain" :key="idx" size="small" style="margin: 2px">{{ item }}</el-tag>
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
        <el-table-column prop="file_path" label="文件路径" min-width="200" show-overflow-tooltip />
        <el-table-column prop="start_line" label="起始行" width="80" />
        <el-table-column prop="end_line" label="结束行" width="80" />
        <el-table-column prop="verdict" label="裁决" width="100">
          <template #default="{ row }">
            <el-tag :type="verdictTagType(row.verdict)" size="small">{{ verdictLabel(row.verdict) }}</el-tag>
          </template>
        </el-table-column>
      </el-table>

      <el-empty v-if="filteredFindings.length === 0 && !scanStore.loading" description="暂无漏洞数据" />
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useScanStore } from '@/stores/scan'

const scanStore = useScanStore()
const filterSeverity = ref('')
const filterVerdict = ref('')

const filteredFindings = computed(() => {
  let list = scanStore.findings
  if (filterSeverity.value) {
    list = list.filter(f => f.severity?.toUpperCase() === filterSeverity.value)
  }
  if (filterVerdict.value) {
    list = list.filter(f => f.verdict === filterVerdict.value)
  }
  return list
})

function severityTagType(severity: string) {
  const map: Record<string, string> = { ERROR: 'danger', WARN: 'warning', INFO: '', UNKNOWN: 'info' }
  return map[severity?.toUpperCase()] || 'info'
}

function verdictTagType(verdict: string) {
  const map: Record<string, string> = { confirmed: 'danger', suspicious: 'warning', rejected: 'success', pending: 'info' }
  return map[verdict] || 'info'
}

function verdictLabel(verdict: string) {
  const map: Record<string, string> = { confirmed: '已确认', suspicious: '可疑', rejected: '已排除', pending: '待定' }
  return map[verdict] || verdict
}

onMounted(() => {
  if (scanStore.findings.length === 0) {
    scanStore.fetchFindings()
  }
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
}
</style>
