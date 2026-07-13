<template>
  <div class="knowledge-page">
    <el-row :gutter="16">
      <el-col :span="24">
        <el-card shadow="hover">
          <template #header>
            <div style="display: flex; justify-content: space-between; align-items: center">
              <span>漏洞知识库</span>
              <el-tag type="info">自进化案例库</el-tag>
            </div>
          </template>

          <el-alert
            title="知识库说明"
            type="info"
            :closable="false"
            show-icon
            style="margin-bottom: 16px"
          >
            VulnPatch 知识库基于漏洞案例自进化机制，通过多模型调度持续积累和更新漏洞模式。
            每次扫描的确认漏洞将自动反馈至知识库，提升后续检测准确率。
          </el-alert>

          <!-- CWE 知识卡片 -->
          <h3>常见 CWE 漏洞类型</h3>
          <el-row :gutter="12" style="margin-top: 12px">
            <el-col :span="8" v-for="cwe in cweList" :key="cwe.id" style="margin-bottom: 12px">
              <el-card shadow="hover" class="cwe-card">
                <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px">
                  <el-tag :type="cwe.level === 'high' ? 'danger' : cwe.level === 'medium' ? 'warning' : 'info'" size="small">
                    {{ cwe.level === 'high' ? '高危' : cwe.level === 'medium' ? '中危' : '低危' }}
                  </el-tag>
                  <strong>{{ cwe.id }}</strong>
                </div>
                <h4 style="margin: 0 0 4px">{{ cwe.name }}</h4>
                <p style="margin: 0; color: #909399; font-size: 13px">{{ cwe.description }}</p>
              </el-card>
            </el-col>
          </el-row>

          <!-- 多模型调度说明 -->
          <h3 style="margin-top: 24px">多模型调度策略</h3>
          <el-table :data="modelList" stripe style="width: 100%; margin-top: 12px">
            <el-table-column prop="name" label="模型" width="180" />
            <el-table-column prop="role" label="角色" width="140" />
            <el-table-column prop="description" label="描述" min-width="300" />
            <el-table-column prop="status" label="状态" width="100">
              <template #default="{ row }">
                <el-tag :type="row.status === 'active' ? 'success' : 'info'" size="small">
                  {{ row.status === 'active' ? '可用' : '未配置' }}
                </el-tag>
              </template>
            </el-table-column>
          </el-table>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script setup lang="ts">
const cweList = [
  { id: 'CWE-89', name: 'SQL 注入', description: '通过构造恶意 SQL 语句执行非授权数据库操作', level: 'high' },
  { id: 'CWE-78', name: '操作系统命令注入', description: '通过构造恶意系统命令执行非授权操作系统指令', level: 'high' },
  { id: 'CWE-79', name: '跨站脚本 (XSS)', description: '在网页中注入恶意脚本，影响其他用户', level: 'medium' },
  { id: 'CWE-22', name: '路径遍历', description: '利用路径序列访问受限目录外的文件', level: 'high' },
  { id: 'CWE-787', name: '越界写入', description: '向缓冲区边界外写入数据，可能导致代码执行', level: 'high' },
  { id: 'CWE-125', name: '越界读取', description: '从缓冲区边界外读取数据，可能导致信息泄露', level: 'medium' },
  { id: 'CWE-352', name: '跨站请求伪造 (CSRF)', description: '诱导用户在已认证的 Web 应用中执行非预期操作', level: 'medium' },
  { id: 'CWE-434', name: '危险类型文件上传', description: '允许上传危险类型的文件，可能导致远程代码执行', level: 'high' },
  { id: 'CWE-502', name: '不安全的反序列化', description: '反序列化不可信数据，可能导致远程代码执行', level: 'high' },
]

const modelList = [
  { name: 'DeepSeek', role: '深度分析', description: '用于深度代码分析和漏洞假设生成', status: 'active' },
  { name: 'OpenAI GPT', role: '推理验证', description: '用于漏洞推理验证和证据链构建', status: 'active' },
  { name: '本地规则引擎', role: '模式匹配', description: '基于静态规则的快速模式匹配检测', status: 'active' },
  { name: 'Semgrep', role: '外部扫描', description: '集成 Semgrep 进行语义化代码扫描', status: 'active' },
]
</script>

<style lang="scss" scoped>
.cwe-card {
  height: 100%;
  transition: transform 0.2s;

  &:hover {
    transform: translateY(-2px);
  }
}
</style>
