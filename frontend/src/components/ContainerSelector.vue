<template>
  <div class="panel">
    <h2>📦 选择容器</h2>
    <div class="mode-select">
      <label><input type="radio" v-model="mode" value="single"> 单容器</label>
      <label><input type="radio" v-model="mode" value="multi"> 多容器</label>
      <label><input type="radio" v-model="mode" value="all"> 全容器</label>
    </div>
    
    <select v-if="mode === 'single'" v-model="selectedContainer">
      <option value="">请选择容器</option>
      <option v-for="c in containers" :key="c.id" :value="c.id">
        {{ c.id }} - {{ c.name }}
      </option>
    </select>
    
    <div v-if="mode === 'multi'" class="checkbox-list">
      <label v-for="c in containers" :key="c.id">
        <input type="checkbox" :value="c.id" v-model="selectedContainers">
        {{ c.id }} - {{ c.name }}
      </label>
    </div>
    
    <button @click="refreshContainers">🔄 刷新列表</button>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { getContainers } from '../api/ablock.js'

const mode = ref('single')
const selectedContainer = ref('')
const selectedContainers = ref([])
const containers = ref([])

async function refreshContainers() {
  containers.value = await getContainers()
}

onMounted(refreshContainers)
</script>

<style scoped>
.panel {
  background: #16213e;
  border-radius: 12px;
  padding: 20px;
  margin: 15px 0;
}
.mode-select label {
  margin-right: 20px;
  cursor: pointer;
}
select, button {
  margin-top: 10px;
  padding: 10px 20px;
  border-radius: 6px;
  border: none;
  background: #e94560;
  color: white;
  cursor: pointer;
}
.checkbox-list {
  max-height: 200px;
  overflow-y: auto;
  margin: 10px 0;
}
.checkbox-list label {
  display: block;
  padding: 5px;
}
</style>
