<template>
  <div class="panel">
    <h2>📊 基线采集</h2>
    <div class="baseline-mode">
      <label><input type="radio" v-model="baselineMode" value="quick"> 快速采集 (5秒)</label>
      <label><input type="radio" v-model="baselineMode" value="standard"> 指定标准容器</label>
      <label><input type="radio" v-model="baselineMode" value="custom"> 自定义</label>
    </div>
    
    <div v-if="baselineMode === 'quick'" class="info">
      点击"开始监控"后自动采集5秒作为基线
    </div>
    
    <div v-if="baselineMode === 'standard'">
      <select v-model="standardContainer">
        <option v-for="c in containers" :key="c.id" :value="c.id">{{ c.name }}</option>
      </select>
    </div>
    
    <div v-if="baselineMode === 'custom'" class="custom-form">
      <label>CPU限制: <input type="number" v-model="custom.cpu" placeholder="%"></label>
      <label>内存限制: <input type="number" v-model="custom.memory" placeholder="MB"></label>
      <label>网络连接: <input type="number" v-model="custom.network" placeholder="/秒"></label>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'

const baselineMode = ref('quick')
const standardContainer = ref('')
const custom = ref({ cpu: '', memory: '', network: '' })
const containers = ref([
  { id: 'c1a2b3d4', name: 'web-app' },
  { id: 'e5f6g7h8', name: 'api-gateway' }
])
</script>

<style scoped>
.panel {
  background: #16213e;
  border-radius: 12px;
  padding: 20px;
  margin: 15px 0;
}
.baseline-mode label {
  display: block;
  margin: 8px 0;
  cursor: pointer;
}
.custom-form label {
  display: block;
  margin: 10px 0;
}
input[type="number"] {
  width: 100px;
  padding: 5px;
  border-radius: 4px;
  border: 1px solid #e94560;
  background: #0f3460;
  color: white;
}
.info {
  color: #aaa;
  padding: 10px;
  background: #0f3460;
  border-radius: 6px;
}
</style>
