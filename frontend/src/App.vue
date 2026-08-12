<template>
  <div class="ablock-app">
    <h1>🛡️ ablock 容器安全代理</h1>
    <ContainerSelector />
    <BaselineConfig />
    <RuleConfig />
    <MonitorDashboard />
  </div>
</template>

<script setup>
import ContainerSelector from './components/ContainerSelector.vue'
import BaselineConfig from './components/BaselineConfig.vue'
import RuleConfig from './components/RuleConfig.vue'
import MonitorDashboard from './components/MonitorDashboard.vue'
</script>

<style>
.ablock-app {
  max-width: 900px;
  margin: 0 auto;
  padding: 20px;
  font-family: system-ui, sans-serif;
  background: #1a1a2e;
  color: #eee;
  min-height: 100vh;
}
h1 { text-align: center; color: #e94560; }
</style>
