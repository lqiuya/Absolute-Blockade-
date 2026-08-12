const API_BASE = '/api'

export async function getContainers() {
  const res = await fetch(`${API_BASE}/containers`)
  return res.json()
}

export async function quickBaseline(id) {
  const res = await fetch(`${API_BASE}/baseline/quick`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ container_id: id })
  })
  return res.json()
}

export async function getContainerLimits(id) {
  const res = await fetch(`${API_BASE}/container/${id}/limits`)
  return res.json()
}

export async function startMonitor(cfg) {
  const res = await fetch(`${API_BASE}/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(cfg)
  })
  return res.json()
}

export async function stopMonitor() {
  const res = await fetch(`${API_BASE}/stop`, { method: 'POST' })
  return res.json()
}

export async function getStatus() {
  const res = await fetch(`${API_BASE}/status`)
  return res.json()
}

export async function getReports() {
  const res = await fetch(`${API_BASE}/reports`)
  return res.json()
}

export async function getReportContent(name) {
  const res = await fetch(`${API_BASE}/reports/${encodeURIComponent(name)}`)
  return res.text()
}
