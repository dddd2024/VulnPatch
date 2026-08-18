<template>
  <div class="agents-page">
    <el-card shadow="hover" class="routing-card">
      <template #header><div class="header-flex"><strong>自主多模型调度决策</strong><el-button size="small" @click="loadRouting">刷新决策</el-button></div></template>
      <el-table :data="decisions" stripe size="small">
        <el-table-column prop="created_at" label="时间" width="180"><template #default="{ row }">{{ formatTime(row.created_at) }}</template></el-table-column>
        <el-table-column label="任务" min-width="150"><template #default="{ row }">{{ row.context.cwe || '-' }} / {{ row.context.complexity }}</template></el-table-column>
        <el-table-column label="敏感级别" width="120"><template #default="{ row }">{{ row.context.sensitivity }}</template></el-table-column>
        <el-table-column label="选择" width="130"><template #default="{ row }"><el-tag type="success">{{ row.selected_provider }}</el-tag></template></el-table-column>
        <el-table-column label="执行路径" min-width="180"><template #default="{ row }">{{ row.execution_path.join(' → ') || row.fallback_chain.join(' → ') }}</template></el-table-column>
        <el-table-column type="expand"><template #default="{ row }"><div class="decision-detail"><el-table :data="row.candidates" size="small"><el-table-column prop="provider" label="Provider"/><el-table-column prop="score" label="Score"/><el-table-column prop="health" label="Health"/><el-table-column label="Allowed"><template #default="scope">{{ scope.row.allowed }}</template></el-table-column><el-table-column label="Available"><template #default="scope">{{ scope.row.available }}</template></el-table-column><el-table-column label="Reasons"><template #default="scope">{{ scope.row.reasons.join(', ') || '-' }}</template></el-table-column></el-table></div></template></el-table-column>
      </el-table>
      <el-empty v-if="!decisions.length" description="暂无 RoutingDecision，请先从“比赛展示”运行一个闭环"/>
    </el-card>
    <el-card shadow="hover"><template #header><div class="header-flex"><strong>Agent 执行日志</strong><el-button size="small" @click="scanStore.fetchAgentLogs()">刷新</el-button></div></template>
      <el-table :data="scanStore.agentLogs" stripe style="width:100%" v-loading="scanStore.loading"><el-table-column type="expand"><template #default="{ row }"><div style="padding:12px 24px"><el-descriptions :column="2" border size="small"><el-descriptions-item label="Agent">{{ row.agent_name }}</el-descriptions-item><el-descriptions-item label="阶段">{{ row.stage }}</el-descriptions-item><el-descriptions-item label="时间">{{ row.timestamp }}</el-descriptions-item><el-descriptions-item label="Scan ID">{{ row.scan_id }}</el-descriptions-item></el-descriptions><pre v-if="row.metadata && Object.keys(row.metadata).length" class="code-snippet">{{ JSON.stringify(row.metadata, null, 2) }}</pre></div></template></el-table-column><el-table-column prop="agent_name" label="Agent" width="160"><template #default="{ row }"><el-tag effect="plain">{{ row.agent_name }}</el-tag></template></el-table-column><el-table-column prop="stage" label="阶段" width="120"><template #default="{ row }"><el-tag size="small" type="info">{{ row.stage }}</el-tag></template></el-table-column><el-table-column prop="message" label="消息" min-width="300" show-overflow-tooltip/><el-table-column prop="timestamp" label="时间" width="180"><template #default="{ row }">{{ formatTime(row.timestamp) }}</template></el-table-column></el-table>
      <el-empty v-if="scanStore.agentLogs.length === 0 && !scanStore.loading" description="暂无 Agent 日志，请先进行安全扫描"/>
    </el-card>
  </div>
</template>
<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { getRoutingDecisions } from '@/api'
import type { RoutingDecision } from '@/api/types'
import { useScanStore } from '@/stores/scan'
const scanStore = useScanStore(); const decisions = ref<RoutingDecision[]>([])
async function loadRouting(){try{decisions.value=(await getRoutingDecisions()).data}catch{decisions.value=[]}}
function formatTime(ts:string){try{return new Date(ts).toLocaleString('zh-CN')}catch{return ts}}
onMounted(()=>{loadRouting();if(scanStore.agentLogs.length===0)scanStore.fetchAgentLogs()})
</script>
<style lang="scss" scoped>
.agents-page{display:flex;flex-direction:column;gap:16px}.header-flex{display:flex;justify-content:space-between;align-items:center}.decision-detail{padding:12px 24px}.code-snippet{background:#1e1e1e;color:#d4d4d4;padding:10px 14px;border-radius:6px;overflow-x:auto;font-size:12px;line-height:1.5}
</style>
