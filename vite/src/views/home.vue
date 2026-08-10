<template>
  <div class="cute-wrapper">
    <!-- 飘浮的萌系背景气泡装饰 -->
    <div class="bubble bubble-1"></div>
    <div class="bubble bubble-2"></div>

    <div class="cute-container">
      <header class="header-section">
        <div class="title-badge">
          <span class="badge-icon">🔐</span>
          <span>ENTERPRISE PKI SYSTEM</span>
        </div>
        <h1 class="main-title">内网证书签发与管理平台 ☁️</h1>
        <p class="subtitle">安全、快捷、一键生成标准 SSL/TLS 证书套件 ✨</p>
      </header>

      <el-form :model="form" label-position="top" class="custom-form">
        <div class="grid-layout">
          <!-- 左侧配置面板 -->
          <div class="left-col">

            <!-- 1. CA 来源选择 -->
            <div class="cute-card">
              <div class="card-header">
                <div class="header-icon-box">📁</div>
                <span>1. 选择 CA 根证书来源</span>
              </div>

              <el-radio-group v-model="form.caMode" class="cute-radio-group">
                <el-radio-button value="preset">使用内部预设 CA</el-radio-button>
                <el-radio-button value="custom">自动生成全新自签名 CA</el-radio-button>
              </el-radio-group>

              <!-- 选内置 CA 时展示下拉 -->
              <div v-if="form.caMode === 'preset'" class="mt-4">
                <el-form-item label="选择内置 CA 套件">
                  <el-select
                      v-model="form.presetId"
                      placeholder="请选择内部 CA"
                      class="cute-select w-full"
                      popper-class="cute-select-popper"
                      :teleported="true"
                  >
                    <el-option
                        v-for="item in presetCAList"
                        :key="item.id"
                        :label="item.name"
                        :value="item.id"
                    />
                  </el-select>
                </el-form-item>
              </div>
            </div>

            <!-- 2. 密钥强度与算法选择 -->
            <div class="cute-card">
              <div class="card-header">
                <div class="header-icon-box">🔑</div>
                <span>2. 密钥算法与强度配置</span>
              </div>

              <el-row :gutter="16">
                <el-col :span="12">
                  <el-form-item label="加密算法类型">
                    <el-select
                        v-model="form.keySpec.type"
                        class="cute-select"
                        popper-class="cute-select-popper"
                        :teleported="true"
                        @change="handleAlgChange"
                    >
                      <el-option label="RSA (通用兼容)" value="RSA" />
                      <el-option label="ECDSA (椭圆曲线/高性能)" value="ECDSA" />
                    </el-select>
                  </el-form-item>
                </el-col>
                <el-col :span="12">
                  <el-form-item :label="form.keySpec.type === 'RSA' ? '密钥长度 (Bits)' : '椭圆曲线 (Curve)'">
                    <el-select
                        v-model="form.keySpec.size"
                        class="cute-select"
                        popper-class="cute-select-popper"
                        :teleported="true"
                    >
                      <template v-if="form.keySpec.type === 'RSA'">
                        <el-option label="2048 bit (标准强度)" :value="2048" />
                        <el-option label="3072 bit (高强度)" :value="3072" />
                        <el-option label="4096 bit (极高强度)" :value="4096" />
                      </template>
                      <template v-else>
                        <el-option label="P-256 (secp256r1)" :value="256" />
                        <el-option label="P-384 (secp384r1)" :value="384" />
                        <el-option label="P-521 (secp521r1)" :value="521" />
                      </template>
                    </el-select>
                  </el-form-item>
                </el-col>
              </el-row>
            </div>

            <!-- 3. 输出文件勾选 -->
            <div class="cute-card">
              <div class="card-header">
                <div class="header-icon-box">📦</div>
                <span>3. 导出文件内容</span>
              </div>
              <div class="checkbox-grid">
                <label
                    v-for="(item, key) in targetList"
                    :key="key"
                    class="cute-checkbox-item"
                    :class="{ active: form.targets[key] }"
                >
                  <el-checkbox v-model="form.targets[key]" />
                  <div class="checkbox-info">
                    <span class="file-name">{{ item.label }}</span>
                    <span class="file-ext">{{ item.ext }}</span>
                  </div>
                </label>
              </div>
            </div>

            <!-- 4. 主体 DN 配置 -->
            <div class="cute-card" v-if="form.caMode === 'custom'">
              <div class="card-header">
                <div class="header-icon-box">👤</div>
                <span>4. CA 主体信息 (DN)</span>
              </div>
              <el-row :gutter="16">
                <el-col :span="12">
                  <el-form-item label="国家 (C)">
                    <el-input v-model="form.ca.country" placeholder="CN" class="cute-input" />
                  </el-form-item>
                </el-col>
                <el-col :span="12">
                  <el-form-item label="组织 (O)">
                    <el-input v-model="form.ca.organization" placeholder="Dev Team" class="cute-input" />
                  </el-form-item>
                </el-col>
                <el-col :span="16">
                  <el-form-item label="通用名称 (CN)">
                    <el-input v-model="form.ca.commonName" placeholder="My Root CA" class="cute-input" />
                  </el-form-item>
                </el-col>
                <el-col :span="8">
                  <el-form-item label="有效期 (年)">
                    <el-input-number v-model="form.ca.validityYears" :min="1" :max="30" class="cute-input-number" />
                  </el-form-item>
                </el-col>
              </el-row>
            </div>

            <!-- 5. SAN (域名与 IP) -->
            <div class="cute-card">
              <div class="card-header justify-between">
                <div class="flex items-center gap-2">
                  <div class="header-icon-box">🌐</div>
                  <span>5. 绑定域名与 IP (SAN)</span>
                </div>
                <el-button class="cute-add-btn" size="small" @click="form.domains.push('')" :icon="Plus">
                  加一个
                </el-button>
              </div>
              <div class="san-section">
                <div v-for="(domain, idx) in form.domains" :key="'domain-' + idx" class="san-row">
                  <el-input v-model="form.domains[idx]" placeholder="例如: *.domain.com 或 localhost" class="cute-input" />
                  <el-button class="cute-del-btn" circle size="small" @click="form.domains.splice(idx, 1)" :icon="Delete" />
                </div>
              </div>
            </div>

          </div>

          <!-- 右侧预览与提交 -->
          <div class="right-col">
            <div class="cute-card preview-card">
              <div class="card-header">
                <div class="header-icon-box">🔮</div>
                <span>生成清单</span>
              </div>

              <div class="summary-list">
                <div class="summary-item">
                  <span class="label">CA 模式</span>
                  <span class="tag-badge">{{ form.caMode === 'preset' ? '内置预设' : '全新自签' }}</span>
                </div>
                <div class="summary-item">
                  <span class="label">密钥算法</span>
                  <span class="val">{{ form.keySpec.type }}</span>
                </div>
                <div class="summary-item">
                  <span class="label">算法强度</span>
                  <span class="val highlight">{{ form.keySpec.size }} {{ form.keySpec.type === 'RSA' ? 'Bits' : 'Curve' }}</span>
                </div>
                <div class="summary-item">
                  <span class="label">包含文件</span>
                  <span class="val">{{ Object.values(form.targets).filter(Boolean).length }} 个</span>
                </div>
              </div>

              <div class="action-box">
                <el-button
                    type="primary"
                    size="large"
                    class="cute-submit-btn"
                    :loading="loading"
                    @click="handleGenerate"
                >
                  <template #icon><Download /></template>
                  {{ loading ? '打包中...' : '生成打包文件包 (.zip)' }}
                </el-button>
              </div>
            </div>
          </div>
        </div>
      </el-form>
    </div>
  </div>
</template>

<script setup>
import { reactive, ref, onMounted } from 'vue'
import axios from 'axios'
import { ElMessage } from 'element-plus'
import { Download, Plus, Delete } from '@element-plus/icons-vue'

const loading = ref(false)
const presetCAList = ref([
  { id: '1', name: 'chrelyonly专用证书' },
  { id: '2', name: '访客通用证书' }
])

const targetList = {
  caCert: { label: 'CA 根证书', ext: 'ca.pem' },
  caKey: { label: 'CA 私钥', ext: 'ca.key' },
  serverCert: { label: '服务端证书', ext: 'server.pem' },
  serverKey: { label: '服务端私钥', ext: 'server.key' },
}

const form = reactive({
  caMode: 'preset',
  presetId: '1',
  keySpec: {
    type: 'RSA',
    size: 2048
  },
  targets: {
    caCert: true,
    caKey: false,
    serverCert: true,
    serverKey: true,
  },
  ca: {
    country: 'chrelyonly',
    province: 'chrelyonly',
    organization: 'chrelyonly',
    organizationalUnit: 'chrelyonly',
    commonName: 'chrelyonly',
    validityYears: 100
  },
  domains: ['localhost', '*.cluster.local'],
  ips: ['127.0.0.1']
})

const handleAlgChange = (val) => {
  if (val === 'RSA') {
    form.keySpec.size = 2048
  } else {
    form.keySpec.size = 256
  }
}


const handleGenerate = async () => {
  loading.value = true
  try {
    const res = await axios({
      url: '/generate',
      method: 'POST',
      data: form,
      responseType: 'blob'
    })

    const blob = new Blob([res.data], { type: 'application/zip' })
    const link = document.createElement('a')
    link.href = URL.createObjectURL(blob)
    link.download = `certs_${form.keySpec.type.toLowerCase()}_${Date.now()}.zip`
    link.click()
    URL.revokeObjectURL(link.href)

    ElMessage.success('证书打包已成功！🎉')
  } catch (err) {
    ElMessage.error('生成失败，请稍后再试哦')
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
/* 治愈马卡龙背景 */
.cute-wrapper {
  position: relative;
  min-height: 100vh;
  padding: 40px 20px;
  background-color: #f6f8fd;
  background-image:
      radial-gradient(at 10% 10%, #fce7f3 0px, transparent 50%),
      radial-gradient(at 90% 90%, #e0f2fe 0px, transparent 50%);
  color: #475569;
  font-family: -apple-system, BlinkMacSystemFont, "PingFang SC", "Segoe UI", sans-serif;
  overflow: hidden;
}

/* 装饰背景泡泡 */
.bubble {
  position: absolute;
  border-radius: 50%;
  filter: blur(40px);
  z-index: 0;
  pointer-events: none;
}
.bubble-1 {
  width: 250px;
  height: 250px;
  background: rgba(244, 114, 182, 0.15);
  top: -50px;
  left: 10%;
}
.bubble-2 {
  width: 300px;
  height: 300px;
  background: rgba(56, 189, 248, 0.15);
  bottom: -80px;
  right: 10%;
}

.cute-container {
  position: relative;
  z-index: 1;
  max-width: 1020px;
  margin: 0 auto;
}

.header-section {
  text-align: center;
  margin-bottom: 30px;
}

.title-badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 6px 14px;
  border-radius: 30px;
  background: #ffffff;
  border: 1px dashed #f472b6;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.05em;
  color: #db2777;
  margin-bottom: 12px;
  box-shadow: 0 4px 10px rgba(244, 114, 182, 0.1);
}

.main-title {
  font-size: 26px;
  font-weight: 800;
  color: #1e293b;
  margin: 0 0 6px 0;
}

.subtitle {
  font-size: 13px;
  color: #64748b;
  margin: 0;
}

.grid-layout {
  display: grid;
  grid-template-columns: 1fr 290px;
  gap: 18px;
}

@media (max-width: 868px) {
  .grid-layout {
    grid-template-columns: 1fr;
  }
}

/* 卡片风格 */
.cute-card {
  background: rgba(255, 255, 255, 0.85);
  backdrop-filter: blur(12px);
  border: 2px solid #ffffff;
  box-shadow: 0 8px 20px rgba(148, 163, 184, 0.08);
  border-radius: 18px;
  padding: 20px;
  margin-bottom: 16px;
}

.card-header {
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 15px;
  font-weight: 700;
  color: #334155;
  margin-bottom: 16px;
}

.card-header.justify-between {
  justify-content: space-between;
}

.header-icon-box {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 32px;
  height: 32px;
  border-radius: 12px;
  background: #fbcfe8;
  font-size: 16px;
}

/* 复选框样式 */
.checkbox-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 10px;
}

.cute-checkbox-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 14px;
  background: #f8fafc;
  border: 1.5px solid #f1f5f9;
  border-radius: 14px;
  cursor: pointer;
  user-select: none;
  transition: all 0.2s cubic-bezier(0.34, 1.56, 0.64, 1);
}

.cute-checkbox-item:hover {
  transform: translateY(-2px);
  border-color: #f472b6;
}

.cute-checkbox-item.active {
  background: #fdf2f8;
  border-color: #f472b6;
}

.checkbox-info {
  display: flex;
  flex-direction: column;
}

.file-name {
  font-size: 13px;
  font-weight: 600;
  color: #334155;
}

.file-ext {
  font-size: 11px;
  color: #94a3b8;
  font-family: monospace;
}

.san-section {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.san-row {
  display: flex;
  align-items: center;
  gap: 10px;
}

.preview-card {
  position: sticky;
  top: 20px;
}

.summary-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
  margin-bottom: 20px;
}

.summary-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 13px;
  padding-bottom: 8px;
  border-bottom: 1px dashed #e2e8f0;
}

.summary-item .label {
  color: #64748b;
}

.summary-item .val {
  color: #1e293b;
  font-weight: 600;
}

.summary-item .highlight {
  color: #db2777;
  font-family: monospace;
  font-weight: 700;
}

.tag-badge {
  background: #fce7f3;
  color: #db2777;
  padding: 2px 10px;
  border-radius: 20px;
  font-size: 11px;
  font-weight: 700;
}

/* 主提交按钮 */
.cute-submit-btn {
  width: 100%;
  height: 46px;
  border-radius: 23px !important;
  font-weight: 700 !important;
  background: linear-gradient(135deg, #f472b6 0%, #ec4899 100%) !important;
  border: none !important;
  box-shadow: 0 6px 16px rgba(244, 114, 182, 0.4) !important;
  transition: all 0.2s cubic-bezier(0.34, 1.56, 0.64, 1) !important;
}

.cute-submit-btn:hover {
  transform: scale(1.02);
  box-shadow: 0 8px 20px rgba(244, 114, 182, 0.5) !important;
}

.cute-add-btn {
  background: #fce7f3 !important;
  border: none !important;
  color: #db2777 !important;
  border-radius: 20px !important;
  font-weight: 600 !important;
}

.cute-del-btn {
  background: #fff1f2 !important;
  border: 1px solid #fecdd3 !important;
  color: #f43f5e !important;
}

.w-full { width: 100%; }
.mt-4 { margin-top: 16px; }
.flex { display: flex; }
.items-center { align-items: center; }
.gap-2 { gap: 8px; }
</style>

<!-- Element Plus 萌系全面重写 -->
<style>
/* Label 表单标签 */
.custom-form .el-form-item__label {
  color: #475569 !important;
  font-size: 13px !important;
  font-weight: 600 !important;
  margin-bottom: 4px !important;
}

/* 输入框圆角与高亮 */
.custom-form .cute-input .el-input__wrapper,
.custom-form .cute-input-number .el-input__wrapper {
  background-color: #f8fafc !important;
  box-shadow: 0 0 0 1.5px #e2e8f0 inset !important;
  border-radius: 12px !important;
  transition: all 0.2s ease;
}

.custom-form .cute-input .el-input__wrapper.is-focus,
.custom-form .cute-input-number .el-input__wrapper.is-focus {
  background-color: #ffffff !important;
  box-shadow: 0 0 0 2px #f472b6 inset !important;
}

.custom-form .cute-input .el-input__inner,
.custom-form .cute-input-number .el-input__inner {
  color: #1e293b !important;
  font-weight: 500;
}

/* 下拉选择器 */
.custom-form .cute-select .el-select__wrapper {
  background-color: #f8fafc !important;
  box-shadow: 0 0 0 1.5px #e2e8f0 inset !important;
  border-radius: 12px !important;
}

.custom-form .cute-select .el-select__selected-item {
  color: #1e293b !important;
  font-weight: 500;
}

/* 下拉菜单 Popper 浮层层级修复 */
.el-popper.cute-select-popper {
  z-index: 9999 !important;
  background: #ffffff !important;
  border: 2px solid #fce7f3 !important;
  border-radius: 14px !important;
  box-shadow: 0 10px 25px rgba(244, 114, 182, 0.15) !important;
  padding: 6px !important;
}

.cute-select-popper .el-select-dropdown__item {
  color: #475569 !important;
  border-radius: 8px !important;
  margin: 2px 0 !important;
}

.cute-select-popper .el-select-dropdown__item.hover,
.cute-select-popper .el-select-dropdown__item:hover {
  background: #fdf2f8 !important;
  color: #db2777 !important;
}

.cute-select-popper .el-select-dropdown__item.is-selected {
  background: #fce7f3 !important;
  color: #db2777 !important;
  font-weight: 700;
}

/* 单选 Radio 切换按键组 */
.custom-form .cute-radio-group {
  display: flex;
  width: 100%;
}

.custom-form .cute-radio-group .el-radio-button {
  flex: 1;
}

.custom-form .cute-radio-group .el-radio-button__inner {
  width: 100%;
  background: #f8fafc !important;
  border: 1.5px solid #e2e8f0 !important;
  color: #64748b !important;
  padding: 9px 15px !important;
  font-weight: 600;
}

.custom-form .cute-radio-group .el-radio-button:first-child .el-radio-button__inner {
  border-radius: 12px 0 0 12px !important;
}

.custom-form .cute-radio-group .el-radio-button:last-child .el-radio-button__inner {
  border-radius: 0 12px 12px 0 !important;
}

.custom-form .cute-radio-group .el-radio-button__original-radio:checked + .el-radio-button__inner {
  background: #fce7f3 !important;
  border-color: #f472b6 !important;
  color: #db2777 !important;
  box-shadow: -1px 0 0 0 #f472b6 !important;
}

/* 复选框粉色点缀 */
.cute-checkbox-item .el-checkbox__inner {
  background-color: #ffffff !important;
  border-color: #cbd5e1 !important;
  border-radius: 6px !important;
}

.cute-checkbox-item .el-checkbox__input.is-checked .el-checkbox__inner {
  background-color: #f472b6 !important;
  border-color: #f472b6 !important;
}
</style>