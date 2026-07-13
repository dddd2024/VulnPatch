<template>
  <div class="scan-page">
    <el-row :gutter="16">
      <!-- 扫描表单 -->
      <el-col :span="10">
        <el-card shadow="hover">
          <template #header>
            <div style="display: flex; align-items: center; gap: 8px">
              <el-icon><Search /></el-icon>
              <span>安全扫描</span>
            </div>
          </template>

          <el-form :model="scanForm" label-width="100px" label-position="top">
            <el-form-item label="输入类型">
              <el-radio-group v-model="scanForm.input_type">
                <el-radio-button value="code">代码片段</el-radio-button>
                <el-radio-button value="path">本地路径</el-radio-button>
                <el-radio-button value="github">GitHub 仓库</el-radio-button>
              </el-radio-group>
            </el-form-item>

            <el-form-item v-if="scanForm.input_type === 'code'" label="代码内容">
              <el-input
                v-model="scanForm.code"
                type="textarea"
                :rows="12"
                placeholder="粘贴需要扫描的代码..."
                style="font-family: 'Courier New', monospace"
              />
            </el-form-item>

            <el-form-item v-if="scanForm.input_type === 'path'" label="仓库路径">
              <el-input v-model="scanForm.repo_path" placeholder="/path/to/project" />
            </el-form-item>

            <el-form-item v-if="scanForm.input_type === 'github'" label="GitHub URL">
              <el-input v-model="scanForm.repo_url" placeholder="https://github.com/owner/repo" />
            </el-form-item>

            <el-form-item label="编程语言">
              <el-select v-model="scanForm.language" placeholder="自动检测" clearable>
                <el-option label="自动检测" value="auto" />
                <el-option label="Python" value="python" />
                <el-option label="JavaScript" value="javascript" />
                <el-option label="Java" value="java" />
                <el-option label="C/C++" value="c_cpp" />
                <el-option label="TypeScript" value="typescript" />
                <el-option label="Go" value="go" />
              </el-select>
            </el-form-item>

            <el-form-item>
              <el-button
                type="primary"
                size="large"
                :loading="scanStore.scanning"
                @click="handleScan"
                style="width: 100%"
              >
                <el-icon v-if="!scanStore.scanning"><Search /></el-icon>
                {{ scanStore.scanning ? '扫描中...' : '开始扫描' }}
              </el-button>
            </el-form-item>
          </el-form>
        </el-card>

        <!-- 扫描进度 -->
        <el-card v-if="scanStore.currentTask" shadow="hover" style="margin-top: 16px">
          <template #header>
            <span>扫描进度</span>
          </template>
          <el-progress
            :percentage="scanStore.currentTask.progress"
            :status="taskStatus"
            :stroke-width="12"
          />
          <p style="margin-top: 8px; color: #909399">{{ scanStore.currentTask.message }}</p>
        </el-card>
      </el-col>

      <!-- 扫描结果 -->
      <el-col :span="14">
        <el-card shadow="hover">
          <template #header>
            <div style="display: flex; justify-content: space-between; align-items: center">
              <span>扫描结果</span>
              <el-tag v-if="scanStore.currentScan" type="info" size="small">
                Scan ID: {{ scanStore.currentScan.scan_id }}
              </el-tag>
            </div>
          </template>

          <div v-if="scanStore.error" style="margin-bottom: 16px">
            <el-alert :title="scanStore.error" type="error" show-icon :closable="false" />
          </div>

          <!-- 摘要 -->
          <div v-if="scanStore.summary" class="scan-summary">
            <el-descriptions :column="3" border size="small">
              <el-descriptions-item label="代码单元">{{ scanStore.summary.total_code_units }}</el-descriptions-item>
              <el-descriptions-item label="漏洞数量">{{ scanStore.summary.total_findings }}</el-descriptions-item>
              <el-descriptions-item label="证据包">{{ scanStore.summary.total_evidence_bundles }}</el-descriptions-item>
              <el-descriptions-item label="风险评分">
                <el-tag :type="scanStore.riskScore >= 70 ? 'danger' : scanStore.riskScore >= 40 ? 'warning' : 'success'">
                  {{ scanStore.riskScore.toFixed(1) }}
                </el-tag>
              </el-descriptions-item>
              <el-descriptions-item label="编程语言">
                <el-tag v-for="lang in scanStore.summary.languages" :key="lang" size="small" style="margin-right: 4px">{{ lang }}</el-tag>
              </el-descriptions-item>
              <el-descriptions-item label="扫描文件">{{ scanStore.summary.scanned_files.length }}</el-descriptions-item>
            </el-descriptions>
          </div>

          <!-- 发现列表 -->
          <el-table
            v-if="scanStore.findings.length > 0"
            :data="scanStore.findings"
            stripe
            style="width: 100%; margin-top: 16px"
            @row-click="(row: any) => selectedFinding = row"
          >
            <el-table-column prop="type" label="类型" width="160" />
            <el-table-column prop="severity" label="等级" width="90">
              <template #default="{ row }">
                <el-tag :type="severityTagType(row.severity)" size="small">{{ row.severity }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="file_path" label="文件" show-overflow-tooltip />
            <el-table-column prop="verdict" label="裁决" width="90">
              <template #default="{ row }">
                <el-tag :type="verdictTagType(row.verdict)" size="small">{{ verdictLabel(row.verdict) }}</el-tag>
              </template>
            </el-table-column>
          </el-table>

          <el-empty v-if="!scanStore.scanning && !scanStore.summary" description="请提交代码进行安全扫描" />
        </el-card>

        <!-- 代码详情 -->
        <el-card v-if="selectedFinding" shadow="hover" style="margin-top: 16px">
          <template #header>
            <div style="display: flex; justify-content: space-between; align-items: center">
              <span>{{ selectedFinding.type }} - {{ selectedFinding.file_path }}:{{ selectedFinding.start_line }}</span>
              <el-button text @click="selectedFinding = null">关闭</el-button>
            </div>
          </template>
          <el-descriptions :column="2" border size="small">
            <el-descriptions-item label="规则 ID">{{ selectedFinding.rule_id }}</el-descriptions-item>
            <el-descriptions-item label="CWE">{{ selectedFinding.cwe || '-' }}</el-descriptions-item>
            <el-descriptions-item label="检测引擎">{{ selectedFinding.engine }}</el-descriptions-item>
            <el-descriptions-item label="置信度">{{ selectedFinding.confidence }}</el-descriptions-item>
            <el-descriptions-item label="描述" :span="2">{{ selectedFinding.message }}</el-descriptions-item>
          </el-descriptions>
          <div v-if="selectedFinding.snippet" style="margin-top: 12px">
            <h4>代码片段</h4>
            <pre class="code-snippet"><code>{{ selectedFinding.snippet }}</code></pre>
          </div>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { ElMessage } from 'element-plus'
import { useScanStore } from '@/stores/scan'
import type { FindingItem } from '@/api/types'

const scanStore = useScanStore()
const selectedFinding = ref<FindingItem | null>(null)

const scanForm = ref({
  input_type: 'code' as 'code' | 'path' | 'github',
  code: '',
  repo_path: '',
  repo_url: '',
  language: 'auto',
})

const taskStatus = computed(() => {
  const s = scanStore.currentTask?.state
  if (s === 'COMPLETED') return 'success'
  if (s === 'FAILED') return 'exception'
  return undefined
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

async function handleScan() {
  if (scanForm.value.input_type === 'code' && !scanForm.value.code.trim()) {
    ElMessage.warning('请输入代码内容')
    return
  }
  if (scanForm.value.input_type === 'path' && !scanForm.value.repo_path.trim()) {
    ElMessage.warning('请输入仓库路径')
    return
  }
  if (scanForm.value.input_type === 'github' && !scanForm.value.repo_url.trim()) {
    ElMessage.warning('请输入 GitHub URL')
    return
  }

  try {
    await scanStore.submitScan({
      input_type: scanForm.value.input_type,
      code: scanForm.value.code || undefined,
      repo_path: scanForm.value.repo_path || undefined,
      repo_url: scanForm.value.repo_url || undefined,
      language: scanForm.value.language || undefined,
    })
    ElMessage.success('扫描完成')
  } catch {
    // error is handled in store
  }
}
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
}
</style>
