<template>
  <div class="agents-page">
    <el-card shadow="hover">
      <template #header>
        <div style="display: flex; justify-content: space-between; align-items: center">
          <span>Agent 执行日志</span>
          <el-button size="small" @click="scanStore.fetchAgentLogs()">刷新</el-button>
        </div>
      </template>

      <el-table :data="scanStore.agentLogs" stripe style="width: 100%" v-loading="scanStore.loading">
        <el-table-column type="expand">
          <template #default="{ row }">
            <div style="padding: 12px 24px">
              <el-descriptions :column="2" border size="small">
                <el-descriptions-item label="Agent">{{ row.agent_name }}</el-descriptions-item>
                <el-descriptions-item label="阶段">{{ row.stage }}</el-descriptions-item>
                <el-descriptions-item label="时间">{{ row.timestamp }}</el-descriptions-item>
                <el-descriptions-item label="Scan ID">{{ row.scan_id }}</el-descriptions-item>
                <el-descriptions-item label="输入引用" :span="2">
                  <el-tag v-for="ref in row.input_refs" :key="ref" size="small" style="margin: 2px">{{ ref }}</el-tag>
                  <span v-if="!row.input_refs.length">-</span>
                </el-descriptions-item>
                <el-descriptions-item label="输出引用" :span="2">
                  <el-tag v-for="ref in row.output_refs" :key="ref" size="small" type="success" style="margin: 2px">{{ ref }}</el-tag>
                  <span v-if="!row.output_refs.length">-</span>
                </el-descriptions-item>
              </el-descriptions>
              <div v-if="row.metadata && Object.keys(row.metadata).length" style="margin-top: 12px">
                <strong>元数据</strong>
                <pre class="code-snippet"><code>{{ JSON.stringify(row.metadata, null, 2) }}</code></pre>
              </div>
            </div>
          </template>
        </el-table-column>
        <el-table-column prop="agent_name" label="Agent" width="160">
          <template #default="{ row }">
            <el-tag :type="agentTagType(row.agent_name)" effect="plain">{{ row.agent_name }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="stage" label="阶段" width="120">
          <template #default="{ row }">
            <el-tag size="small" type="info">{{ row.stage }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="message" label="消息" min-width="300" show-overflow-tooltip />
        <el-table-column prop="timestamp" label="时间" width="180">
          <template #default="{ row }">
            {{ formatTime(row.timestamp) }}
          </template>
        </el-table-column>
      </el-table>

      <el-empty v-if="scanStore.agentLogs.length === 0 && !scanStore.loading" description="暂无 Agent 日志，请先进行安全扫描" />
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { onMounted } from 'vue'
import { useScanStore } from '@/stores/scan'

const scanStore = useScanStore()

function agentTagType(name: string) {
  const map: Record<string, string> = {
    ReconAgent: '', AnalysisAgent: 'warning', JudgeAgent: 'danger', VerificationAgent: 'success',
  }
  return map[name] || 'info'
}

function formatTime(ts: string) {
  try {
    return new Date(ts).toLocaleString('zh-CN')
  } catch {
    return ts
  }
}

onMounted(() => {
  if (scanStore.agentLogs.length === 0) {
    scanStore.fetchAgentLogs()
  }
})
</script>

<style lang="scss" scoped>
.code-snippet {
  background: #1e1e1e;
  color: #d4d4d4;
  padding: 10px 14px;
  border-radius: 6px;
  overflow-x: auto;
  font-size: 12px;
  line-height: 1.5;
  margin-top: 4px;
}
</style>
