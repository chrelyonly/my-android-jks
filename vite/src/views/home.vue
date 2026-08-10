<template>
  <div class="cute-wrapper">
    <!-- 飘浮的萌系背景气泡装饰 -->
    <div class="bubble bubble-1"></div>
    <div class="bubble bubble-2"></div>

    <div class="cute-container">
      <header class="header-section">
        <div class="title-badge">
          <span class="badge-icon">🤖</span>
          <span>ANDROID APK SIGNING SYSTEM</span>
        </div>
        <h1 class="main-title">APK 签名证书生成平台 ☁️</h1>
        <p class="subtitle">快捷、安全、一键生成标准 JKS 密钥库及指纹信息套件 ✨</p>
      </header>

      <el-form :model="form" label-position="top" class="custom-form">
        <div class="grid-layout">
          <!-- 左侧配置面板 -->
          <div class="left-col">

            <!-- 1. Keystore 基础配置 -->
            <div class="cute-card">
              <div class="card-header">
                <div class="header-icon-box">🔑</div>
                <span>1. Keystore 密钥参数配置</span>
              </div>

              <el-row :gutter="16">
                <el-col :span="12">
                  <el-form-item label="生成文件名">
                    <el-input v-model="form.keystore.fileName" placeholder="release-key.jks" class="cute-input" />
                  </el-form-item>
                </el-col>
                <el-col :span="12">
                  <el-form-item label="Key Alias (别名)">
                    <el-input v-model="form.keystore.keyAlias" placeholder="chrelyonly" class="cute-input" />
                  </el-form-item>
                </el-col>
                <el-col :span="12">
                  <el-form-item label="Keystore 存储库密码">
                    <el-input v-model="form.keystore.password" type="password" show-password placeholder="输入密码" class="cute-input" />
                  </el-form-item>
                </el-col>
                <el-col :span="12">
                  <el-form-item label="Key 私钥密码">
                    <el-input v-model="form.keystore.keyPass" type="password" show-password placeholder="输入密码" class="cute-input" />
                  </el-form-item>
                </el-col>
              </el-row>
            </div>

            <!-- 2. CA 证书主体 (DN) 信息 -->
            <div class="cute-card">
              <div class="card-header justify-between">
                <div class="flex items-center gap-2">
                  <div class="header-icon-box">📜</div>
                  <span>2. 证书主体 (Subject) 信息</span>
                </div>
                <el-button class="cute-add-btn" size="small" @click="resetDefaults">
                  恢复默认
                </el-button>
              </div>

              <el-row :gutter="16">
                <el-col :span="12">
                  <el-form-item label="常用名称 (Common Name)">
                    <el-input v-model="form.ca.commonName" placeholder="chrelyonly" class="cute-input" />
                  </el-form-item>
                </el-col>
                <el-col :span="12">
                  <el-form-item label="组织 (Organization)">
                    <el-input v-model="form.ca.organization" placeholder="chrelyonly" class="cute-input" />
                  </el-form-item>
                </el-col>
                <el-col :span="12">
                  <el-form-item label="部门 (Organizational Unit)">
                    <el-input v-model="form.ca.organizationalUnit" placeholder="chrelyonly" class="cute-input" />
                  </el-form-item>
                </el-col>
                <el-col :span="12">
                  <el-form-item label="省/州 (Province)">
                    <el-input v-model="form.ca.province" placeholder="Yunnan" class="cute-input" />
                  </el-form-item>
                </el-col>
                <el-col :span="12">
                  <el-form-item label="国家代码 (Country)">
                    <el-input v-model="form.ca.country" placeholder="CN" maxlength="2" class="cute-input uppercase" />
                  </el-form-item>
                </el-col>
                <el-col :span="12">
                  <el-form-item label="证书有效期 (年)">
                    <el-input-number v-model="form.ca.validityYears" :min="1" :max="100" class="cute-input-number" />
                  </el-form-item>
                </el-col>
              </el-row>
            </div>

            <!-- 3. 打包导出包含内容说明 -->
            <div class="cute-card">
              <div class="card-header">
                <div class="header-icon-box">📦</div>
                <span>3. 打包导出清单说明</span>
              </div>
              <div class="checkbox-grid">
                <div class="cute-checkbox-item active">
                  <div class="checkbox-info">
                    <span class="file-name">JKS 密钥库文件</span>
                    <span class="file-ext">{{ form.keystore.fileName || 'release-key.jks' }}</span>
                  </div>
                </div>
                <div class="cute-checkbox-item active">
                  <div class="checkbox-info">
                    <span class="file-name">签名指纹说明文档</span>
                    <span class="file-ext">cert-info.txt (含 MD5/SHA1)</span>
                  </div>
                </div>
              </div>
            </div>

          </div>

          <!-- 右侧预览与提交 -->
          <div class="right-col">
            <div class="cute-card preview-card">
              <div class="card-header">
                <div class="header-icon-box">🔮</div>
                <span>生成概要</span>
              </div>

              <div class="summary-list">
                <div class="summary-item">
                  <span class="label">密钥类型</span>
                  <span class="tag-badge">RSA 2048 Bit</span>
                </div>
                <div class="summary-item">
                  <span class="label">Key Alias</span>
                  <span class="val highlight">{{ form.keystore.keyAlias || '未设置' }}</span>
                </div>
                <div class="summary-item">
                  <span class="label">证书有效期</span>
                  <span class="val">{{ form.ca.validityYears }} 年</span>
                </div>
                <div class="summary-item">
                  <span class="label">国家/主体</span>
                  <span class="val">{{ form.ca.country }} / {{ form.ca.commonName }}</span>
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
                  {{ loading ? '打包中...' : '生成并下载签名包 (.zip)' }}
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
import { reactive, ref } from 'vue'
import axios from 'axios'
import { ElMessage } from 'element-plus'
import { Download } from '@element-plus/icons-vue'

const loading = ref(false)

const defaultForm = {
  keystore: {
    fileName: 'release-key.jks',
    password: 'chrelyonly',
    keyAlias: 'chrelyonly',
    keyPass: 'chrelyonly'
  },
  ca: {
    country: 'CN',
    province: 'Yunnan',
    organization: 'chrelyonly',
    organizationalUnit: 'chrelyonly',
    commonName: 'chrelyonly',
    validityYears: 30
  }
}

const form = reactive(JSON.parse(JSON.stringify(defaultForm)))

const resetDefaults = () => {
  Object.assign(form, JSON.parse(JSON.stringify(defaultForm)))
  ElMessage.info('已恢复默认配置 💕')
}

const handleGenerate = async () => {
  loading.value = true
  try {
    const res = await axios({
      url: '/generate-apk-cert',
      method: 'POST',
      data: form,
      responseType: 'blob'
    })

    // 解析 Header 获取文件名，若无则使用默认文件名
    let fileName = 'apk-keystore.zip'
    const disposition = res.headers['content-disposition']
    if (disposition && disposition.includes('filename=')) {
      const match = disposition.match(/filename="?([^";]+)"?/)
      if (match && match[1]) {
        fileName = match[1]
      }
    }

    const blob = new Blob([res.data], { type: 'application/zip' })
    const link = document.createElement('a')
    link.href = URL.createObjectURL(blob)
    link.download = fileName
    link.click()
    URL.revokeObjectURL(link.href)

    ElMessage.success('APK 签名证书与指纹文件打包成功！🎉')
  } catch (err) {
    ElMessage.error('生成失败，请检查网络或后端配置哦 😿')
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

/* 展示框样式 */
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
  user-select: none;
  transition: all 0.2s cubic-bezier(0.34, 1.56, 0.64, 1);
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

.uppercase { text-transform: uppercase; }
.flex { display: flex; }
.items-center { align-items: center; }
.gap-2 { gap: 8px; }
</style>

<!-- Element Plus 萌系样式覆盖 -->
<style>
.custom-form .el-form-item__label {
  color: #475569 !important;
  font-size: 13px !important;
  font-weight: 600 !important;
  margin-bottom: 4px !important;
}

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
</style>