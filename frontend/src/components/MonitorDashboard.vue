<template>
  <div class="panel">
    <h2>📡 实时监控</h2>
    <div class="control-bar">
      <button @click="handleStart" :disabled="running" class="btn-start">🚀 开始监控</button>
      <button @click="handleStop" :disabled="!running" class="btn-stop">⏹ 停止监控</button>
    </div>
    
    <div class="status-grid">
      <div v-for="c in containerStatus" :key="c.id" class="status-card" :class="c.status">
        <div class="status-icon">{{ statusIcon(c.status) }}</div>
        <div class="status-name">{{ c.name }}</div>
        <div class="status-detail">{{ c.detail }}</div>
      </div>
    </div>
    
    <div class="actions">
      <button @click="viewReports">📄 查看报告</button>
      <button @click="downloadTxt">⬇ 下载TXT</button>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { startMonitor as apiStart, stopMonitor as apiStop, getStatus, getReports } from '../api/ablock.js'

const running = ref(false)
const containerStatus = ref([
  { id: 'c1', name: 'web-app', status: 'normal', detail: 'CPU:15% 内存:128M' },
  { id: 'c2', name: 'api-gateway', status: 'warning', detail: 'CPU偏离65%' },
  { id: 'c3', name: 'redis', status: 'killed', detail: '已斩杀' },
])

let pollTimer = null

function statusIcon(status) {
  return { normal: '🟢', warning: '🟡', killed: '🔴' }[status] || '⚪'
}

async function handleStart() {
  await apiStart({})
  running.value = true
  pollTimer = setInterval(pollStatus, 2000)
}

async function handleStop() {
  await apiStop()
  running.value = false
  clearInterval(pollTimer)
}

async function pollStatus() {
  const status = await getStatus()
  containerStatus.value = status.data?.containers || []
}

function viewReports() {
  window.open('/api/reports', '_blank')
}

function downloadTxt() {
  window.open('/api/reports/download', '_blank')
}

onMounted(() => {})
onUnmounted(() => {
  clearInterval(pollTimer)
})
</script>

<style scoped>
.panel {
  background: #16213e;
  border-radius: 12px;
  padding: 20px;
  margin: 15px 0;
}
.control-bar {
  display: flex;
  gap: 15px;
  margin-bottom: 20px;
}
.btn-start {
  background: #2ecc71;
  color: #1a1a2e;
}
.btn-stop {
  background: #e94560;
}
button {
  padding: 12px 30px;
  border: none;
  border-radius: 8px;
  font-size: 16px;
  cursor: pointer;
  font-weight: bold;
}
button:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
.status-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  gap: 15px;
  margin: 20px 0;
}
.status-card {
  background: #0f3460;
  border-radius: 10px;
  padding: 15px;
  text-align: center;
  border-left: 4px solid #2ecc71;
}
.status-card.warning {
  border-left-color: #f4a261;
}
.status-card.killed {
  border-left-color: #e94560;
}
.status-icon {
  font-size: 32px;
  margin-bottom: 8px;
}
.status-name {
  font-size: 18px;
  font-weight: bold;
}
.status-detail {
  color: #aaa;
  font-size: 14px;
  margin-top: 5px;
}
.actions {
  display: flex;
  gap: 15px;
}
.actions button {
  background: #533483;
  font-size: 14px;
  padding: 10px 20px;
}
</style>
