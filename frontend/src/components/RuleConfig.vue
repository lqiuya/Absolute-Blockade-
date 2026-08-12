<template>
  <div class="panel">
    <h2>⚔️ 规则配置</h2>
    <div class="strict-level">
      <label>严格等级:</label>
      <label><input type="radio" v-model="strictLevel" value="strict"> 严格 (20%)</label>
      <label><input type="radio" v-model="strictLevel" value="normal"> 标准 (50%)</label>
      <label><input type="radio" v-model="strictLevel" value="loose"> 宽松 (100%)</label>
    </div>
    
    <div class="rules-list">
      <div v-for="rule in rules" :key="rule.id" class="rule-item">
        <label class="switch">
          <input type="checkbox" v-model="rule.enabled">
          <span class="slider"></span>
        </label>
        <span class="rule-name">{{ rule.name }}</span>
        <span class="rule-action" :class="rule.action">{{ rule.action }}</span>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'

const strictLevel = ref('normal')
const rules = ref([
  { id: 'R001', name: 'mount /proc', enabled: true, action: '斩杀' },
  { id: 'R002', name: 'mount /sys', enabled: true, action: '斩杀' },
  { id: 'R003', name: 'open /proc/1/ns/mnt', enabled: true, action: '斩杀' },
  { id: 'R004', name: 'open /proc/1/root', enabled: true, action: '斩杀' },
  { id: 'R005', name: 'write /etc/crontab', enabled: true, action: '斩杀' },
  { id: 'R006', name: 'mknod /dev/sda', enabled: true, action: '斩杀' },
  { id: 'R007', name: 'ptrace attach', enabled: true, action: '斩杀' },
  { id: 'R008', name: '特权容器启动', enabled: true, action: '警告' },
])
</script>

<style scoped>
.panel {
  background: #16213e;
  border-radius: 12px;
  padding: 20px;
  margin: 15px 0;
}
.strict-level label {
  margin-right: 15px;
}
.rules-list {
  margin-top: 15px;
}
.rule-item {
  display: flex;
  align-items: center;
  padding: 10px;
  border-bottom: 1px solid #0f3460;
}
.rule-name {
  flex: 1;
  margin-left: 15px;
}
.rule-action {
  padding: 4px 12px;
  border-radius: 4px;
  font-size: 12px;
}
.rule-action.斩杀 {
  background: #e94560;
  color: white;
}
.rule-action.警告 {
  background: #f4a261;
  color: #1a1a2e;
}
.switch {
  position: relative;
  display: inline-block;
  width: 40px;
  height: 20px;
}
.switch input { opacity: 0; width: 0; height: 0; }
.slider {
  position: absolute;
  cursor: pointer;
  top: 0; left: 0; right: 0; bottom: 0;
  background: #555;
  border-radius: 20px;
  transition: .3s;
}
.slider:before {
  position: absolute;
  content: "";
  height: 14px;
  width: 14px;
  left: 3px;
  bottom: 3px;
  background: white;
  border-radius: 50%;
  transition: .3s;
}
input:checked + .slider { background: #e94560; }
input:checked + .slider:before { transform: translateX(20px); }
</style>
