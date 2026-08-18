import { createRouter, createWebHistory } from 'vue-router'
import type { RouteRecordRaw } from 'vue-router'

const routes: RouteRecordRaw[] = [
  {
    path: '/',
    component: () => import('@/layouts/MainLayout.vue'),
    redirect: '/dashboard',
    children: [
      {
        path: 'competition',
        name: 'CompetitionDemo',
        component: () => import('@/views/CompetitionDemo.vue'),
        meta: { title: '比赛展示', icon: 'Trophy' },
      },
      {
        path: 'dashboard',
        name: 'Dashboard',
        component: () => import('@/views/Dashboard.vue'),
        meta: { title: '仪表盘', icon: 'DataBoard' },
      },
      {
        path: 'scan',
        name: 'Scan',
        component: () => import('@/views/Scan.vue'),
        meta: { title: '安全扫描', icon: 'Search' },
      },
      {
        path: 'findings',
        name: 'Findings',
        component: () => import('@/views/Findings.vue'),
        meta: { title: '漏洞发现', icon: 'Warning' },
      },
      {
        path: 'evidence',
        name: 'Evidence',
        component: () => import('@/views/Evidence.vue'),
        meta: { title: '证据链', icon: 'Link' },
      },
      {
        path: 'agents',
        name: 'Agents',
        component: () => import('@/views/Agents.vue'),
        meta: { title: 'Agent 日志', icon: 'Cpu' },
      },
      {
        path: 'report',
        name: 'Report',
        component: () => import('@/views/Report.vue'),
        meta: { title: '审计报告', icon: 'Document' },
      },
      {
        path: 'knowledge',
        name: 'Knowledge',
        component: () => import('@/views/Knowledge.vue'),
        meta: { title: '知识库', icon: 'Collection' },
      },
    ],
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

export default router
