<template>
  <el-container class="main-layout">
    <el-aside :width="isCollapsed ? '64px' : '220px'" class="sidebar">
      <div class="logo-section" @click="isCollapsed = !isCollapsed">
        <div class="logo-icon"><el-icon :size="28"><Monitor /></el-icon></div>
        <transition name="fade"><div v-if="!isCollapsed" class="logo-text"><h1 class="logo-title">VulnPatch</h1><p class="logo-subtitle">自主多模型调度与案例库<br>自进化的漏洞修复辅助系统</p></div></transition>
      </div>
      <el-menu :default-active="currentRoute" :collapse="isCollapsed" :collapse-transition="true" background-color="#16213e" text-color="#b4b6ba" active-text-color="#409eff" router class="sidebar-menu">
        <el-menu-item index="/competition"><el-icon><Trophy /></el-icon><template #title>比赛展示</template></el-menu-item>
        <el-menu-item index="/dashboard"><el-icon><DataBoard /></el-icon><template #title>仪表盘</template></el-menu-item>
        <el-menu-item index="/scan"><el-icon><Search /></el-icon><template #title>安全扫描</template></el-menu-item>
        <el-menu-item index="/findings"><el-icon><Warning /></el-icon><template #title>漏洞发现</template></el-menu-item>
        <el-menu-item index="/evidence"><el-icon><Link /></el-icon><template #title>证据链</template></el-menu-item>
        <el-menu-item index="/agents"><el-icon><Cpu /></el-icon><template #title>Agent 日志</template></el-menu-item>
        <el-menu-item index="/report"><el-icon><Document /></el-icon><template #title>审计报告</template></el-menu-item>
        <el-menu-item index="/knowledge"><el-icon><Collection /></el-icon><template #title>知识库</template></el-menu-item>
      </el-menu>
    </el-aside>
    <el-container>
      <el-header class="main-header"><div class="header-left"><el-breadcrumb separator="/"><el-breadcrumb-item :to="{ path: '/dashboard' }">首页</el-breadcrumb-item><el-breadcrumb-item>{{ currentTitle }}</el-breadcrumb-item></el-breadcrumb></div><div class="header-right"><el-tag v-if="scanStore.scanning" type="warning" effect="dark" round><el-icon class="is-loading"><Loading /></el-icon>扫描中...</el-tag><el-badge :value="scanStore.totalFindings" :hidden="scanStore.totalFindings === 0" :max="99"><el-button :icon="Bell" circle size="small" /></el-badge></div></el-header>
      <el-main class="main-content"><router-view /></el-main>
    </el-container>
  </el-container>
</template>
<script setup lang="ts">
import { ref, computed } from 'vue'
import { useRoute } from 'vue-router'
import { Bell } from '@element-plus/icons-vue'
import { useScanStore } from '@/stores/scan'
const route = useRoute(); const scanStore = useScanStore(); const isCollapsed = ref(false)
const currentRoute = computed(() => route.path); const currentTitle = computed(() => (route.meta.title as string) || '')
</script>
<style lang="scss" scoped>
.main-layout { height: 100vh; }
.sidebar { background: #16213e; transition: width 0.3s ease; overflow: hidden; .logo-section { display:flex; align-items:center; padding:16px 12px; cursor:pointer; border-bottom:1px solid rgba(255,255,255,.08); min-height:80px; .logo-icon { flex-shrink:0; width:40px; height:40px; display:flex; align-items:center; justify-content:center; background:linear-gradient(135deg,#409eff 0%,#6c5ce7 100%); border-radius:10px; color:#fff; } .logo-text { margin-left:12px; overflow:hidden; .logo-title { font-size:18px; font-weight:700; color:#fff; margin:0; line-height:1.2; } .logo-subtitle { font-size:10px; color:rgba(255,255,255,.55); margin:4px 0 0; line-height:1.4; } } } .sidebar-menu { border-right:none; &.el-menu--collapse { :deep(.el-menu-item) { padding:0 20px !important; justify-content:center; } } :deep(.el-menu-item) { height:48px; line-height:48px; margin:4px 8px; border-radius:8px; &.is-active { background:rgba(64,158,255,.15) !important; } &:hover { background:rgba(255,255,255,.06) !important; } } } }
.main-header { display:flex; align-items:center; justify-content:space-between; background:#fff; border-bottom:1px solid #ebeef5; padding:0 20px; height:56px; .header-right { display:flex; align-items:center; gap:12px; } }
.main-content { background:#f0f2f5; overflow-y:auto; padding:20px; }
.fade-enter-active,.fade-leave-active { transition:opacity .3s ease; } .fade-enter-from,.fade-leave-to { opacity:0; }
</style>
