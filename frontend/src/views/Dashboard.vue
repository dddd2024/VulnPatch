<template>
  <div class="dashboard">
    <!-- 顶部统计卡片 -->
    <el-row :gutter="16" class="stat-row">
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-content">
            <div class="stat-icon" style="background: linear-gradient(135deg, #409eff, #6c5ce7)">
              <el-icon :size="28"><Search /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-value">{{ scanStore.totalFindings }}</div>
              <div class="stat-label">漏洞发现</div>
            </div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-content">
            <div class="stat-icon" style="background: linear-gradient(135deg, #f56c6c, #e91e63)">
              <el-icon :size="28"><Warning /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-value">{{ scanStore.findingsBySeverity.ERROR }}</div>
              <div class="stat-label">高危漏洞</div>
            </div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-content">
            <div class="stat-icon" style="background: linear-gradient(135deg, #e6a23c, #ff9800)">
              <el-icon :size="28"><CircleCheck /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-value">{{ scanStore.findingsByVerdict.confirmed }}</div>
              <div class="stat-label">已确认</div>
            </div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-content">
            <div class="stat-icon" style="background: linear-gradient(135deg, #67c23a, #4caf50)">
              <el-icon :size="28"><TrendCharts /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-value">{{ scanStore.riskScore.toFixed(1) }}</div>
              <div class="stat-label">风险评分</div>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 图表区域 -->
    <el-row :gutter="16" style="margin-top: 16px">
      <el-col :span="12">
        <el-card shadow="hover">
          <template #header>
            <span>漏洞严重等级分布</span>
          </template>
          <div ref="severityChartRef" style="height: 300px"></div>
        </el-card>
      </el-col>
      <el-col :span="12">
        <el-card shadow="hover">
          <template #header>
            <span>裁决结果分布</span>
          </template>
          <div ref="verdictChartRef" style="height: 300px"></div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 最近发现列表 -->
    <el-card shadow="hover" style="margin-top: 16px">
      <template #header>
        <div style="display: flex; justify-content: space-between; align-items: center">
          <span>最近漏洞发现</span>
          <el-button type="primary" text @click="$router.push('/scan')">开始扫描</el-button>
        </div>
      </template>
      <el-table :data="recentFindings" stripe style="width: 100%">
        <el-table-column prop="type" label="类型" width="180" />
        <el-table-column prop="severity" label="严重等级" width="120">
          <template #default="{ row }">
            <el-tag :type="severityTagType(row.severity)" size="small">{{ row.severity }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="file_path" label="文件路径" min-width="200" show-overflow-tooltip />
        <el-table-column prop="start_line" label="行号" width="80" />
        <el-table-column prop="verdict" label="裁决" width="100">
          <template #default="{ row }">
            <el-tag :type="verdictTagType(row.verdict)" size="small">{{ verdictLabel(row.verdict) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="risk_score" label="风险分" width="100">
          <template #default="{ row }">
            <el-progress :percentage="row.risk_score" :color="riskColor(row.risk_score)" :stroke-width="6" :show-text="true" />
          </template>
        </el-table-column>
      </el-table>
      <el-empty v-if="recentFindings.length === 0" description="暂无漏洞数据，请先进行安全扫描" />
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import * as echarts from 'echarts'
import { useScanStore } from '@/stores/scan'

const scanStore = useScanStore()
const severityChartRef = ref<HTMLElement>()
const verdictChartRef = ref<HTMLElement>()
let severityChart: echarts.ECharts | null = null
let verdictChart: echarts.ECharts | null = null

const recentFindings = computed(() => scanStore.findings.slice(0, 10))

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

function riskColor(score: number) {
  if (score >= 70) return '#f56c6c'
  if (score >= 40) return '#e6a23c'
  return '#67c23a'
}

function renderCharts() {
  if (!severityChartRef.value || !verdictChartRef.value) return

  // 严重等级饼图
  if (!severityChart) severityChart = echarts.init(severityChartRef.value)
  severityChart.setOption({
    tooltip: { trigger: 'item' },
    legend: { bottom: 0 },
    series: [{
      type: 'pie',
      radius: ['40%', '70%'],
      avoidLabelOverlap: false,
      itemStyle: { borderRadius: 8, borderColor: '#fff', borderWidth: 2 },
      label: { show: false },
      emphasis: { label: { show: true, fontSize: 14, fontWeight: 'bold' } },
      data: [
        { value: scanStore.findingsBySeverity.ERROR, name: '高危 (ERROR)', itemStyle: { color: '#f56c6c' } },
        { value: scanStore.findingsBySeverity.WARN, name: '中危 (WARN)', itemStyle: { color: '#e6a23c' } },
        { value: scanStore.findingsBySeverity.INFO, name: '低危 (INFO)', itemStyle: { color: '#409eff' } },
        { value: scanStore.findingsBySeverity.UNKNOWN, name: '未知', itemStyle: { color: '#909399' } },
      ],
    }],
  })

  // 裁决结果饼图
  if (!verdictChart) verdictChart = echarts.init(verdictChartRef.value)
  verdictChart.setOption({
    tooltip: { trigger: 'item' },
    legend: { bottom: 0 },
    series: [{
      type: 'pie',
      radius: ['40%', '70%'],
      avoidLabelOverlap: false,
      itemStyle: { borderRadius: 8, borderColor: '#fff', borderWidth: 2 },
      label: { show: false },
      emphasis: { label: { show: true, fontSize: 14, fontWeight: 'bold' } },
      data: [
        { value: scanStore.findingsByVerdict.confirmed, name: '已确认', itemStyle: { color: '#f56c6c' } },
        { value: scanStore.findingsByVerdict.suspicious, name: '可疑', itemStyle: { color: '#e6a23c' } },
        { value: scanStore.findingsByVerdict.rejected, name: '已排除', itemStyle: { color: '#67c23a' } },
        { value: scanStore.findingsByVerdict.pending, name: '待定', itemStyle: { color: '#909399' } },
      ],
    }],
  })
}

watch(() => [scanStore.findingsBySeverity, scanStore.findingsByVerdict], renderCharts, { deep: true })

onMounted(() => {
  renderCharts()
  window.addEventListener('resize', () => {
    severityChart?.resize()
    verdictChart?.resize()
  })
})
</script>

<style lang="scss" scoped>
.dashboard {
  .stat-card {
    .stat-content {
      display: flex;
      align-items: center;
      gap: 16px;

      .stat-icon {
        width: 56px;
        height: 56px;
        border-radius: 12px;
        display: flex;
        align-items: center;
        justify-content: center;
        color: #fff;
        flex-shrink: 0;
      }

      .stat-info {
        .stat-value {
          font-size: 28px;
          font-weight: 700;
          color: #303133;
          line-height: 1.2;
        }
        .stat-label {
          font-size: 13px;
          color: #909399;
          margin-top: 4px;
        }
      }
    }
  }
}
</style>
