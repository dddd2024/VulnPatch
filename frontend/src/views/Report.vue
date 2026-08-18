<template>
  <div class="report-page">
    <el-card shadow="hover">
      <template #header>
        <div style="display: flex; justify-content: space-between; align-items: center">
          <span>审计报告</span>
          <div style="display: flex; gap: 8px">
            <el-radio-group v-model="reportFormat" size="small">
              <el-radio-button value="json">JSON</el-radio-button>
              <el-radio-button value="markdown">Markdown</el-radio-button>
              <el-radio-button value="html">HTML</el-radio-button>
            </el-radio-group>
            <el-button size="small" type="primary" @click="fetchReport">生成报告</el-button>
          </div>
        </div>
      </template>

      <!-- JSON 报告 -->
      <div v-if="reportFormat === 'json' && reportData">
        <el-descriptions title="审计摘要" :column="3" border style="margin-bottom: 16px">
          <el-descriptions-item label="代码单元">{{ reportData.summary?.total_code_units ?? '-' }}</el-descriptions-item>
          <el-descriptions-item label="漏洞总数">{{ reportData.summary?.total_findings ?? '-' }}</el-descriptions-item>
          <el-descriptions-item label="证据包数">{{ reportData.summary?.total_evidence_bundles ?? '-' }}</el-descriptions-item>
          <el-descriptions-item label="风险评分">
            <el-tag :type="riskTagType(reportData.summary?.risk_score ?? 0)">
              {{ (reportData.summary?.risk_score ?? 0).toFixed(1) }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="编程语言">
            <el-tag v-for="lang in (reportData.summary?.languages || [])" :key="lang" size="small" style="margin-right: 4px">{{ lang }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="扫描文件数">{{ reportData.summary?.scanned_files?.length ?? 0 }}</el-descriptions-item>
        </el-descriptions>

        <h3>漏洞详情</h3>
        <el-table :data="reportData.findings || []" stripe style="width: 100%">
          <el-table-column prop="type" label="类型" width="180" />
          <el-table-column prop="severity" label="等级" width="100">
            <template #default="{ row }">
              <el-tag :type="severityTagType(row.severity)" size="small">{{ row.severity }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="file_path" label="文件" min-width="200" show-overflow-tooltip />
          <el-table-column prop="start_line" label="行" width="60" />
          <el-table-column prop="message" label="描述" min-width="200" show-overflow-tooltip />
        </el-table>

        <el-collapse style="margin-top: 16px">
          <el-collapse-item title="原始 JSON 数据">
            <pre class="code-snippet"><code>{{ JSON.stringify(reportData, null, 2) }}</code></pre>
          </el-collapse-item>
        </el-collapse>
      </div>

      <!-- Markdown 报告 -->
      <div v-if="reportFormat === 'markdown' && reportText" class="markdown-body" v-html="renderedMarkdown" />

      <!-- HTML 报告 -->
      <div v-if="reportFormat === 'html' && reportText" v-html="reportText" class="html-report" />

      <el-empty v-if="!reportData && !reportText && !loading" description="请点击「生成报告」查看审计报告" />
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { marked } from 'marked'
import * as api from '@/api'

const reportFormat = ref<'json' | 'markdown' | 'html'>('json')
const reportData = ref<any>(null)
const reportText = ref<string>('')
const loading = ref(false)

const renderedMarkdown = computed(() => {
  if (!reportText.value) return ''
  return marked(reportText.value)
})

function severityTagType(severity: string) {
  const map: Record<string, string> = { ERROR: 'danger', WARN: 'warning', INFO: '', UNKNOWN: 'info' }
  return map[severity?.toUpperCase()] || 'info'
}

function riskTagType(score: number) {
  if (score >= 70) return 'danger'
  if (score >= 40) return 'warning'
  return 'success'
}

async function fetchReport() {
  loading.value = true
  try {
    if (reportFormat.value === 'json') {
      const { data } = await api.getReportJson()
      reportData.value = data
      reportText.value = ''
    } else if (reportFormat.value === 'markdown') {
      const { data } = await api.getReportMarkdown()
      reportText.value = data as any
      reportData.value = null
    } else {
      const { data } = await api.getReportHtml()
      reportText.value = data as any
      reportData.value = null
    }
  } catch (e: any) {
    reportData.value = null
    reportText.value = ''
  } finally {
    loading.value = false
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
  font-size: 12px;
  line-height: 1.5;
  max-height: 500px;
}

.markdown-body {
  padding: 16px;
  background: #fff;
  border-radius: 6px;
  line-height: 1.7;

  :deep(h1), :deep(h2), :deep(h3) {
    margin-top: 1em;
    border-bottom: 1px solid #eee;
    padding-bottom: 0.3em;
  }

  :deep(table) {
    border-collapse: collapse;
    width: 100%;
    th, td {
      border: 1px solid #ddd;
      padding: 8px 12px;
      text-align: left;
    }
    th { background: #f5f5f5; }
  }

  :deep(code) {
    background: #f4f4f4;
    padding: 2px 6px;
    border-radius: 3px;
    font-size: 90%;
  }

  :deep(pre) {
    background: #1e1e1e;
    color: #d4d4d4;
    padding: 12px 16px;
    border-radius: 6px;
    overflow-x: auto;
    code {
      background: none;
      padding: 0;
      color: inherit;
    }
  }
}

.html-report {
  border: 1px solid #eee;
  border-radius: 6px;
  padding: 20px;
}
</style>
