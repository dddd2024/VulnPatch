<template>
  <div class="evidence-page">
    <el-card shadow="hover">
      <template #header>
        <div style="display: flex; justify-content: space-between; align-items: center">
          <span>证据链</span>
          <el-button size="small" @click="scanStore.fetchEvidence()">刷新</el-button>
        </div>
      </template>

      <el-timeline v-if="scanStore.evidence.length > 0">
        <el-timeline-item
          v-for="item in scanStore.evidence"
          :key="item.id"
          :timestamp="item.finding?.type || '未知'"
          placement="top"
          :type="evidenceColor(item)"
        >
          <el-card shadow="never">
            <h4 style="margin: 0 0 8px">{{ item.finding?.type || '未知漏洞' }}</h4>
            <el-descriptions :column="2" border size="small">
              <el-descriptions-item label="文件">{{ item.finding?.file_path || '-' }}</el-descriptions-item>
              <el-descriptions-item label="行号">{{ item.finding?.start_line || '-' }}</el-descriptions-item>
            </el-descriptions>

            <!-- 代码片段 -->
            <div v-if="item.snippets && item.snippets.length" style="margin-top: 12px">
              <strong>代码片段</strong>
              <pre
                v-for="(s, idx) in item.snippets"
                :key="idx"
                class="code-snippet"
              ><code>{{ typeof s === 'string' ? s : JSON.stringify(s, null, 2) }}</code></pre>
            </div>

            <!-- 调用链 -->
            <div v-if="item.call_chain && item.call_chain.length" style="margin-top: 12px">
              <strong>调用链</strong>
              <div style="margin-top: 4px">
                <el-steps :active="item.call_chain.length" finish-status="process" simple>
                  <el-step
                    v-for="(step, idx) in item.call_chain"
                    :key="idx"
                    :title="typeof step === 'string' ? step : step.name || JSON.stringify(step)"
                  />
                </el-steps>
              </div>
            </div>

            <!-- Agent 假设 -->
            <div v-if="item.agent_hypotheses && item.agent_hypotheses.length" style="margin-top: 12px">
              <strong>Agent 分析假设</strong>
              <el-collapse style="margin-top: 4px">
                <el-collapse-item
                  v-for="h in item.agent_hypotheses"
                  :key="h.id"
                  :title="`${h.agent_name} - ${h.vulnerability_type || '未知类型'}`"
                >
                  <p>{{ h.hypothesis }}</p>
                  <p style="color: #909399; font-size: 13px">{{ h.reasoning_summary }}</p>
                  <el-tag size="small">置信度: {{ h.confidence }}</el-tag>
                </el-collapse-item>
              </el-collapse>
            </div>

            <!-- Judge 裁决 -->
            <div v-if="item.judge_decision" style="margin-top: 12px">
              <strong>Judge 裁决</strong>
              <el-descriptions :column="3" border size="small" style="margin-top: 4px">
                <el-descriptions-item label="裁决">
                  <el-tag :type="verdictTagType(item.judge_decision.verdict)">
                    {{ verdictLabel(item.judge_decision.verdict) }}
                  </el-tag>
                </el-descriptions-item>
                <el-descriptions-item label="风险评分">{{ item.judge_decision.risk_score }}</el-descriptions-item>
                <el-descriptions-item label="置信度">{{ item.judge_decision.confidence }}</el-descriptions-item>
              </el-descriptions>
              <p style="margin-top: 4px; color: #606266">{{ item.judge_decision.reason }}</p>
            </div>

            <!-- CWE 信息 -->
            <div v-if="item.cwe_info && Object.keys(item.cwe_info).length" style="margin-top: 12px">
              <strong>CWE 信息</strong>
              <pre class="code-snippet"><code>{{ JSON.stringify(item.cwe_info, null, 2) }}</code></pre>
            </div>
          </el-card>
        </el-timeline-item>
      </el-timeline>

      <el-empty v-else description="暂无证据链数据，请先进行安全扫描" />
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { onMounted } from 'vue'
import { useScanStore } from '@/stores/scan'
import type { EvidenceItem } from '@/api/types'

const scanStore = useScanStore()

function evidenceColor(item: EvidenceItem) {
  if (item.judge_decision?.verdict === 'confirmed') return 'danger'
  if (item.judge_decision?.verdict === 'suspicious') return 'warning'
  if (item.judge_decision?.verdict === 'rejected') return 'success'
  return 'primary'
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
  if (scanStore.evidence.length === 0) {
    scanStore.fetchEvidence()
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
