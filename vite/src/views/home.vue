<template>
  <!-- 炫彩动态背景底图 -->
  <div class="glass-wrapper">
    <!-- 背景流光装饰球 -->
    <div class="glow-sphere sphere-1"></div>
    <div class="glow-sphere sphere-2"></div>
    <div class="glow-sphere sphere-3"></div>

    <div class="glass-container">
      <!-- 头部标题 -->
      <header class="header-section">
        <div class="title-badge">
          <el-icon><Lock /></el-icon>
          <span>SSL / TLS Certificates Manager</span>
        </div>
        <h1 class="main-title">内网 PKI 证书生成中心</h1>
        <p class="sub-title">一键签发企业级 CA 根证书、服务端及客户端证书包</p>
      </header>

      <el-form :model="form" label-position="top" class="cert-form">
        <div class="grid-layout">
          <!-- 左侧：参数配置区域 -->
          <div class="left-col space-y-6">

            <!-- 1. 输出文件选择 -->
            <div class="glass-card">
              <div class="card-header">
                <el-icon><Files /></el-icon>
                <span>1. 选择需生成的证书文件</span>
              </div>
              <div class="checkbox-grid">
                <div
                    v-for="(item, key) in targetList"
                    :key="key"
                    class="glass-checkbox-item"
                    :class="{ active: form.targets[key] }"
                    @click="form.targets[key] = !form.targets[key]"
                >
                  <el-checkbox v-model="form.targets[key]" @click.stop />
                  <div class="checkbox-info">
                    <span class="file-name">{{ item.label }}</span>
                    <span class="file-ext">{{ item.ext }}</span>
                  </div>
                  <el-icon class="file-icon"><Document /></el-icon>
                </div>
              </div>
            </div>

            <!-- 2. 主体 DN 配置 -->
            <div class="glass-card">
              <div class="card-header">
                <el-icon><User /></el-icon>
                <span>2. 证书主体信息 (DN)</span>
              </div>
              <el-row :gutter="16">
                <el-col :span="12">
                  <el-form-item label="国家 (C)">
                    <el-input v-model="form.ca.country" placeholder="CN" class="glass-input" />
                  </el-form-item>
                </el-col>
                <el-col :span="12">
                  <el-form-item label="省份/州 (ST)">
                    <el-input v-model="form.ca.province" placeholder="Beijing" class="glass-input" />
                  </el-form-item>
                </el-col>
                <el-col :span="12">
                  <el-form-item label="组织机构 (O)">
                    <el-input v-model="form.ca.organization" placeholder="Dev Team" class="glass-input" />
                  </el-form-item>
                </el-col>
                <el-col :span="12">
                  <el-form-item label="部门 (OU)">
                    <el-input v-model="form.ca.organizationalUnit" placeholder="Security" class="glass-input" />
                  </el-form-item>
                </el-col>
                <el-col :span="16">
                  <el-form-item label="通用名称 (Common Name / CN)">
                    <el-input v-model="form.ca.commonName" placeholder="Internal Root CA" class="glass-input" />
                  </el-form-item>
                </el-col>
                <el-col :span="8">
                  <el-form-item label="有效期 (年)">
                    <el-input-number v-model="form.ca.validityYears" :min="1" :max="30" class="glass-input-number" />
                  </el-form-item>
                </el-col>
              </el-row>
            </div>

            <!-- 3. SAN (域名 & IP) -->
            <div class="glass-card">
              <div class="card-header">
                <el-icon><Connection /></el-icon>
                <span>3. 绑定域名与 IP (SAN)</span>
              </div>

              <!-- 域名列表 -->
              <div class="san-section">
                <div class="san-header">
                  <label>DNS 域名</label>
                  <el-button type="primary" link size="small" @click="addDomain" :icon="Plus">添加域名</el-button>
                </div>
                <div v-for="(domain, idx) in form.domains" :key="'domain-' + idx" class="san-row">
                  <el-input v-model="form.domains[idx]" placeholder="e.g. *.test.local 或 localhost" class="glass-input" />
                  <el-button type="danger" circle plain size="small" @click="removeDomain(idx)" :icon="Delete" />
                </div>
              </div>

              <!-- IP 列表 -->
              <div class="san-section mt-4">
                <div class="san-header">
                  <label>IP 地址</label>
                  <el-button type="primary" link size="small" @click="addIp" :icon="Plus">添加 IP</el-button>
                </div>
                <div v-for="(ip, idx) in form.ips" :key="'ip-' + idx" class="san-row">
                  <el-input v-model="form.ips[idx]" placeholder="e.g. 127.0.0.1 或 192.168.1.100" class="glass-input" />
                  <el-button type="danger" circle plain size="small" @click="removeIp(idx)" :icon="Delete" />
                </div>
              </div>
            </div>

          </div>

          <!-- 右侧：实时预览与提交动作 -->
          <div class="right-col">
            <div class="glass-card preview-card sticky-top">
              <div class="card-header">
                <el-icon><Cpu /></el-icon>
                <span>生成文件预览</span>
              </div>

              <div class="file-tree-preview">
                <div class="zip-box">
                  <el-icon class="zip-icon"><FolderOpened /></el-icon>
                  <span>certificates.zip</span>
                </div>
                <div class="tree-lines">
                  <template v-for="(item, key) in targetList" :key="key">
                    <div v-if="form.targets[key]" class="tree-item">
                      <span class="line">└─</span>
                      <el-icon class="item-icon"><Document /></el-icon>
                      <span class="item-name">{{ item.ext }}</span>
                      <el-tag size="small" type="info" effect="plain" class="item-tag">{{ item.label }}</el-tag>
                    </div>
                  </template>
                </div>
              </div>

              <div class="action-box">
                <el-button
                    type="primary"
                    size="large"
                    class="glass-submit-btn"
                    :loading="loading"
                    @click="handleGenerate"
                >
                  <template #icon>
                    <el-icon><Download /></el-icon>
                  </template>
                  {{ loading ? '打包签发中...' : '生成并下载证书包 (.zip)' }}
                </el-button>
                <p class="tip-text">证书私钥全流程内存生成，无需担心密钥泄露</p>
              </div>
            </div>
          </div>
        </div>
      </el-form>
    </div>
  </div>
</template>

<script setup>
import { reactive, ref } from 'vue'
import axios from 'axios'
import { ElMessage } from 'element-plus'
import {
  Lock, Files, User, Connection, Cpu, Document,
  FolderOpened, Download, Plus, Delete
} from '@element-plus/icons-vue'

const loading = ref(false)

// 证书文件清单映射
const targetList = {
  caCert: { label: 'CA 根证书', ext: 'ca.pem' },
  caKey: { label: 'CA 私钥', ext: 'ca.key' },
  serverCert: { label: '服务端证书', ext: 'server.pem' },
  serverKey: { label: '服务端私钥', ext: 'server.key' },
  clientCert: { label: '客户端证书', ext: 'client.pem' },
  clientKey: { label: '客户端私钥', ext: 'client.key' },
}

const form = reactive({
  targets: {
    caCert: true,
    caKey: true,
    serverCert: true,
    serverKey: true,
    clientCert: false,
    clientKey: false
  },
  ca: {
    country: 'CN',
    province: 'Beijing',
    organization: 'DevOps Org',
    organizationalUnit: 'Infrastructure',
    commonName: 'Internal Cluster Root CA',
    validityYears: 5
  },
  domains: ['localhost', '*.test.local'],
  ips: ['127.0.0.1']
})

const addDomain = () => form.domains.push('')
const removeDomain = (idx) => form.domains.splice(idx, 1)

const addIp = () => form.ips.push('')
const removeIp = (idx) => form.ips.splice(idx, 1)

// 提交后端并触发 ZIP 下载
const handleGenerate = async () => {
  const selectedCount = Object.values(form.targets).filter(Boolean).length
  if (selectedCount === 0) {
    ElMessage.warning('请至少勾选选择一种需要导出的证书文件！')
    return
  }

  const payload = {
    targets: form.targets,
    ca: form.ca,
    domains: form.domains.filter(d => d.trim() !== ''),
    ips: form.ips.filter(i => i.trim() !== '')
  }

  loading.value = true
  try {
    const response = await axios({
      url: '/generate', // 配合 Vite proxy 或完整 URL
      method: 'POST',
      data: payload,
      responseType: 'blob' // 必须指定二进制流
    })

    // 创建隐藏 a 标签触发文件下载
    const blob = new Blob([response.data], { type: 'application/zip' })
    const link = document.createElement('a')
    link.href = URL.createObjectURL(blob)
    link.download = `certificates_${Date.now()}.zip`
    link.click()
    URL.revokeObjectURL(link.href)

    ElMessage.success('证书套件生成成功，已开始下载！')
  } catch (err) {
    console.error(err)
    ElMessage.error('证书生成失败，请检查后端服务是否畅通')
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
/* 1. 整体渐变底图 */
.glass-wrapper {
  position: relative;
  min-height: 100vh;
  padding: 40px 20px;
  background: #0f172a;
  background-image:
      radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.15) 0px, transparent 50%),
      radial-gradient(at 100% 100%, rgba(168, 85, 247, 0.15) 0px, transparent 50%);
  color: #f8fafc;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  overflow: hidden;
}

/* 背景流光炫光球 */
.glow-sphere {
  position: absolute;
  border-radius: 50%;
  filter: blur(90px);
  z-index: 0;
  pointer-events: none;
}
.sphere-1 {
  width: 400px;
  height: 400px;
  background: rgba(79, 70, 229, 0.25);
  top: -100px;
  left: -100px;
}
.sphere-2 {
  width: 350px;
  height: 350px;
  background: rgba(236, 72, 153, 0.2);
  bottom: -50px;
  right: -50px;
}
.sphere-3 {
  width: 300px;
  height: 300px;
  background: rgba(6, 182, 212, 0.15);
  top: 40%;
  left: 50%;
  transform: translate(-50%, -50%);
}

/* 2. 容器与头部 */
.glass-container {
  position: relative;
  z-index: 1;
  max-width: 1100px;
  margin: 0 auto;
}
.header-section {
  text-align: center;
  margin-bottom: 32px;
}
.title-badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 6px 16px;
  border-radius: 20px;
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid rgba(255, 255, 255, 0.1);
  color: #818cf8;
  font-size: 13px;
  font-weight: 500;
  margin-bottom: 12px;
}
.main-title {
  font-size: 32px;
  font-weight: 800;
  letter-spacing: -0.5px;
  background: linear-gradient(135deg, #ffffff 0%, #cbd5e1 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  margin: 0 0 8px 0;
}
.sub-title {
  color: #94a3b8;
  font-size: 14px;
  margin: 0;
}

/* 3. 网格布局与毛玻璃卡片 */
.grid-layout {
  display: grid;
  grid-template-columns: 1fr 340px;
  gap: 24px;
}
@media (max-width: 868px) {
  .grid-layout { grid-template-columns: 1fr; }
}

.glass-card {
  background: rgba(30, 41, 59, 0.45);
  backdrop-filter: blur(16px);
  -webkit-backdrop-filter: blur(16px);
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 16px;
  padding: 20px;
  box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
  margin-bottom: 20px;
}

.card-header {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 15px;
  font-weight: 600;
  color: #e2e8f0;
  margin-bottom: 16px;
  padding-bottom: 10px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.05);
}

/* 4. 文件选择格子 */
.checkbox-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 12px;
}
.glass-checkbox-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 14px;
  background: rgba(15, 23, 42, 0.4);
  border: 1px solid rgba(255, 255, 255, 0.05);
  border-radius: 10px;
  cursor: pointer;
  transition: all 0.2s ease;
}
.glass-checkbox-item:hover {
  border-color: rgba(99, 102, 241, 0.4);
  background: rgba(30, 41, 59, 0.6);
}
.glass-checkbox-item.active {
  background: rgba(79, 70, 229, 0.15);
  border-color: rgba(129, 140, 248, 0.5);
}
.checkbox-info {
  display: flex;
  flex-direction: column;
  flex: 1;
}
.file-name {
  font-size: 13px;
  color: #f1f5f9;
  font-weight: 500;
}
.file-ext {
  font-size: 11px;
  color: #64748b;
  font-family: monospace;
}
.file-icon {
  color: #475569;
}

/* 5. SAN 添加区 */
.san-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
  font-size: 13px;
  color: #94a3b8;
}
.san-row {
  display: flex;
  gap: 8px;
  margin-bottom: 8px;
}

/* 6. 右侧预览与提交 */
.preview-card {
  height: calc(100% - 40px);
  display: flex;
  flex-direction: column;
  justify-content: space-between;
}
.sticky-top {
  position: sticky;
  top: 20px;
}
.file-tree-preview {
  background: rgba(15, 23, 42, 0.6);
  border-radius: 12px;
  padding: 16px;
  border: 1px solid rgba(255, 255, 255, 0.05);
  margin-bottom: 20px;
}
.zip-box {
  display: flex;
  align-items: center;
  gap: 8px;
  font-weight: 600;
  color: #cbd5e1;
  font-size: 14px;
  margin-bottom: 12px;
}
.zip-icon { color: #f59e0b; font-size: 18px; }
.tree-lines {
  padding-left: 8px;
}
.tree-item {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  font-family: monospace;
  color: #94a3b8;
  margin-bottom: 8px;
}
.tree-item .line { color: #475569; }
.tree-item .item-name { color: #38bdf8; }
.tree-item .item-tag { margin-left: auto; font-size: 10px; }

.glass-submit-btn {
  width: 100%;
  height: 48px;
  border-radius: 12px;
  background: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%) !important;
  border: none !important;
  box-shadow: 0 8px 20px rgba(79, 70, 229, 0.4);
  font-weight: 600;
  letter-spacing: 0.5px;
  transition: all 0.2s ease;
}
.glass-submit-btn:hover {
  transform: translateY(-1px);
  box-shadow: 0 12px 24px rgba(79, 70, 229, 0.6);
}
.tip-text {
  text-align: center;
  font-size: 11px;
  color: #64748b;
  margin-top: 10px;
}
.mt-4 { margin-top: 16px; }
.space-y-6 > * + * { margin-top: 24px; }
</style>

<!-- Element Plus 主题深色化覆写 -->
<style>
.glass-wrapper .el-form-item__label {
  color: #94a3b8 !important;
  font-size: 12px !important;
  margin-bottom: 4px !important;
}
.glass-input .el-input__wrapper,
.glass-input-number .el-input__wrapper {
  background-color: rgba(15, 23, 42, 0.6) !important;
  box-shadow: 0 0 0 1px rgba(255, 255, 255, 0.1) inset !important;
  border-radius: 8px !important;
}
.glass-input .el-input__wrapper.is-focus,
.glass-input-number .el-input__wrapper.is-focus {
  box-shadow: 0 0 0 1px #818cf8 inset !important;
}
.glass-input .el-input__inner,
.glass-input-number .el-input__inner {
  color: #f1f5f9 !important;
}
.glass-wrapper .el-checkbox__inner {
  background-color: rgba(15, 23, 42, 0.8) !important;
  border-color: rgba(255, 255, 255, 0.2) !important;
}
.glass-wrapper .el-checkbox__input.is-checked .el-checkbox__inner {
  background-color: #6366f1 !important;
  border-color: #6366f1 !important;
}
</style>