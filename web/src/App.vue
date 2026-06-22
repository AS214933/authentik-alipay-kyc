<template>
  <main class="shell" :class="{ 'admin-shell': isAdminPage }">
    <section class="panel" :class="{ 'admin-panel': isAdminPage }">
      <template v-if="isAdminPage">
        <header class="topbar">
          <div>
            <p class="eyebrow">管理导入</p>
            <h1>手动认证导入</h1>
          </div>
          <button v-if="admin.authenticated" class="icon-button" type="button" title="退出" @click="adminLogout">
            <LogOut :size="18" />
          </button>
        </header>

        <div v-if="admin.loading" class="loading">
          <LoaderCircle class="spin" :size="24" />
        </div>

        <template v-else>
          <div v-if="!admin.enabled" class="empty">
            <ShieldAlert :size="38" />
            <h2>管理导入未启用</h2>
            <p>需要先在服务端开启管理员导入开关。</p>
          </div>

          <form v-else-if="!admin.authenticated" class="form" @submit.prevent="adminLogin">
            <label>
              <span>管理员密码</span>
              <input v-model="adminLoginForm.password" type="password" autocomplete="current-password" required />
            </label>
            <button class="primary" type="submit" :disabled="admin.busy">
              <LoaderCircle v-if="admin.busy" class="spin" :size="18" />
              <LogIn v-else :size="18" />
              登录
            </button>
          </form>

          <template v-else>
            <form class="form" @submit.prevent="adminImport">
              <div class="form-grid">
                <label>
                  <span>用户 ID</span>
                  <input v-model.trim="adminImportForm.user_id" name="user_id" autocomplete="off" required />
                </label>
                <label>
                  <span>认证状态</span>
                  <select v-model="adminImportForm.verified" name="verified">
                    <option :value="true">验证是</option>
                    <option :value="false">验证否</option>
                  </select>
                </label>
              </div>
              <label>
                <span>姓名</span>
                <input v-model.trim="adminImportForm.name" name="name" autocomplete="name" required maxlength="64" />
              </label>
              <label>
                <span>身份证号</span>
                <input
                  v-model.trim="adminImportForm.id_number"
                  name="id_number"
                  autocomplete="off"
                  inputmode="text"
                  required
                  maxlength="18"
                />
              </label>
              <button class="primary" type="submit" :disabled="admin.busy">
                <LoaderCircle v-if="admin.busy" class="spin" :size="18" />
                <Upload v-else :size="18" />
                导入
              </button>
            </form>

            <div v-if="admin.result" class="result-grid admin-result">
              <div>
                <span class="label">用户 ID</span>
                <strong>{{ admin.result.user_id }}</strong>
              </div>
              <div>
                <span class="label">状态</span>
                <strong>{{ admin.result.verified ? '验证是' : '验证否' }}</strong>
              </div>
              <div>
                <span class="label">姓名</span>
                <strong>{{ admin.result.name_masked }}</strong>
              </div>
              <div>
                <span class="label">证件后四位</span>
                <strong>{{ admin.result.id_last4 }}</strong>
              </div>
            </div>
          </template>

          <p v-if="admin.error" class="error">{{ admin.error }}</p>
          <p v-if="admin.success" class="success">{{ admin.success }}</p>
        </template>
      </template>

      <template v-else>
        <header class="topbar">
          <div>
            <p class="eyebrow">Authentik 用户中心</p>
            <h1>实名认证</h1>
          </div>
          <button v-if="state.authenticated" class="icon-button" type="button" title="退出" @click="logout">
            <LogOut :size="18" />
          </button>
        </header>

        <div v-if="state.loading" class="loading">
          <LoaderCircle class="spin" :size="24" />
        </div>

        <template v-else>
          <div v-if="!state.authenticated" class="empty">
            <ShieldCheck :size="38" />
            <h2>需要登录</h2>
            <p>请先通过 Authentik 登录后继续实名认证。</p>
            <button class="primary" type="button" @click="login">
              <LogIn :size="18" />
              登录
            </button>
          </div>

          <template v-else>
            <div class="account-row">
              <div>
                <span class="label">当前用户</span>
                <strong>{{ state.user.username || state.user.display_name || state.user.id }}</strong>
              </div>
              <span class="status" :class="{ verified: state.verified }">
                <CircleCheck v-if="state.verified" :size="16" />
                <Clock3 v-else :size="16" />
                {{ state.verified ? '已认证' : '未认证' }}
              </span>
            </div>

            <div v-if="state.verified && state.kyc" class="result-grid">
              <div>
                <span class="label">姓名</span>
                <strong>{{ state.kyc.name_masked }}</strong>
              </div>
              <div>
                <span class="label">证件后四位</span>
                <strong>{{ state.kyc.id_last4 }}</strong>
              </div>
              <div>
                <span class="label">渠道</span>
                <strong>{{ state.kyc.channel }}</strong>
              </div>
              <div>
                <span class="label">认证时间</span>
                <strong>{{ formatDate(state.kyc.verified_at) }}</strong>
              </div>
            </div>

            <div v-else-if="state.qrCode" class="qr-panel">
              <div v-if="state.appLaunchUrl && state.mobile" class="mobile-launch">
                <button class="primary" type="button" @click="openAlipay">
                  <ExternalLink :size="18" />
                  打开支付宝
                </button>
              </div>
              <div class="qr-frame">
                <img :src="state.qrCode" alt="支付宝实名认证二维码" />
              </div>
              <div class="qr-actions">
                <button class="primary" type="button" :disabled="state.confirming" @click="confirmKyc(state.pendingState)">
                  <LoaderCircle v-if="state.confirming" class="spin" :size="18" />
                  <CircleCheck v-else :size="18" />
                  我已完成，检查结果
                </button>
                <button class="secondary" type="button" :disabled="state.confirming" @click="resetKyc">
                  重新填写
                </button>
              </div>
            </div>

            <form v-else class="form" @submit.prevent="startKyc">
              <label>
                <span>姓名</span>
                <input v-model.trim="form.name" name="name" autocomplete="name" required maxlength="64" />
              </label>
              <label>
                <span>身份证号</span>
                <input
                  v-model.trim="form.id_number"
                  name="id_number"
                  autocomplete="off"
                  inputmode="text"
                  required
                  maxlength="18"
                />
              </label>
              <button class="primary" type="submit" :disabled="state.busy">
                <LoaderCircle v-if="state.busy" class="spin" :size="18" />
                <ShieldCheck v-else :size="18" />
                开始认证
              </button>
            </form>

            <div v-if="callbackState" class="callback">
              <LoaderCircle v-if="state.confirming" class="spin" :size="18" />
              <CircleCheck v-else-if="state.verified" :size="18" />
              <AlertTriangle v-else :size="18" />
              <span>{{ callbackMessage }}</span>
            </div>
          </template>

          <p v-if="state.error" class="error">{{ state.error }}</p>
        </template>
      </template>
    </section>
  </main>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import {
  AlertTriangle,
  CircleCheck,
  Clock3,
  ExternalLink,
  LoaderCircle,
  LogIn,
  LogOut,
  ShieldAlert,
  ShieldCheck,
  Upload
} from '@lucide/vue'
import QRCode from 'qrcode'

const isAdminPage = window.location.pathname === '/admin' || window.location.pathname.startsWith('/admin/')

const state = reactive({
  loading: true,
  busy: false,
  confirming: false,
  authenticated: false,
  verified: false,
  user: {},
  kyc: null,
  qrCode: '',
  appLaunchUrl: '',
  mobile: isMobileBrowser(),
  pendingState: '',
  error: ''
})

const form = reactive({
  name: '',
  id_number: ''
})

const admin = reactive({
  loading: true,
  busy: false,
  enabled: false,
  authenticated: false,
  result: null,
  error: '',
  success: ''
})

const adminLoginForm = reactive({
  password: ''
})

const adminImportForm = reactive({
  user_id: '',
  name: '',
  id_number: '',
  verified: true
})

const callbackState = ref(new URLSearchParams(window.location.search).get('state') || '')
const callbackMessage = computed(() => {
  if (state.confirming) return '正在确认支付宝认证结果'
  if (state.verified) return '认证已完成并写回 Authentik'
  return '等待认证结果'
})

onMounted(async () => {
  if (isAdminPage) {
    await loadAdminStatus()
    return
  }
  await loadMe()
  if (state.authenticated && callbackState.value && !state.verified) {
    await confirmKyc(callbackState.value)
  }
})

async function request(path, options = {}) {
  const response = await fetch(path, {
    credentials: 'same-origin',
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {})
    },
    ...options
  })
  const text = await response.text()
  const body = text ? JSON.parse(text) : {}
  if (!response.ok) {
    const err = new Error(body.error || `请求失败: ${response.status}`)
    err.body = body
    err.status = response.status
    throw err
  }
  return body
}

async function loadMe() {
  state.loading = true
  state.error = ''
  try {
    const data = await request('/api/me')
    state.authenticated = true
    state.user = data.user || {}
    state.verified = Boolean(data.verified)
    state.kyc = data.kyc || null
  } catch (err) {
    if (err.status === 401) {
      state.authenticated = false
      state.loginUrl = err.body?.login_url || '/auth/login'
    } else {
      state.error = err.message
    }
  } finally {
    state.loading = false
  }
}

async function loadAdminStatus() {
  admin.loading = true
  admin.error = ''
  try {
    const data = await request('/api/admin/status')
    admin.enabled = Boolean(data.enabled)
    admin.authenticated = Boolean(data.authenticated)
  } catch (err) {
    admin.error = err.message
  } finally {
    admin.loading = false
  }
}

async function adminLogin() {
  admin.busy = true
  admin.error = ''
  admin.success = ''
  try {
    await request('/api/admin/login', {
      method: 'POST',
      body: JSON.stringify({ password: adminLoginForm.password })
    })
    admin.authenticated = true
    adminLoginForm.password = ''
  } catch (err) {
    admin.error = err.status === 401 ? '管理员密码不正确' : err.message
  } finally {
    admin.busy = false
  }
}

async function adminLogout() {
  await request('/api/admin/logout', { method: 'POST', body: '{}' })
  admin.authenticated = false
  admin.result = null
}

async function adminImport() {
  admin.busy = true
  admin.error = ''
  admin.success = ''
  admin.result = null
  try {
    const data = await request('/api/admin/import', {
      method: 'POST',
      body: JSON.stringify({
        user_id: adminImportForm.user_id,
        name: adminImportForm.name,
        id_number: adminImportForm.id_number,
        verified: adminImportForm.verified
      })
    })
    admin.result = data.kyc ? { ...data.kyc, user_id: data.user_id } : null
    admin.success = '已写入本地加密记录并回传 Authentik'
  } catch (err) {
    if (err.status === 401) {
      admin.authenticated = false
      admin.error = '管理员登录已失效，请重新登录'
    } else {
      admin.error = err.message
    }
  } finally {
    admin.busy = false
  }
}

function login() {
  window.location.href = state.loginUrl || '/auth/login'
}

async function logout() {
  await request('/auth/logout', { method: 'POST', body: '{}' })
  window.location.href = '/'
}

async function startKyc() {
  state.busy = true
  state.error = ''
  try {
    const data = await request('/api/kyc/start', {
      method: 'POST',
      body: JSON.stringify({ name: form.name, id_number: form.id_number })
    })
    state.pendingState = data.state || ''
    state.appLaunchUrl = data.alipay_app_url || ''
    const qrUrl = data.certify_url || data.redirect_url
    state.qrCode = await QRCode.toDataURL(qrUrl, {
      errorCorrectionLevel: 'M',
      margin: 1,
      scale: 8
    })
    openAlipayOnMobile()
  } catch (err) {
    state.error = err.message
  } finally {
    state.busy = false
  }
}

async function confirmKyc(stateValue) {
  state.confirming = true
  state.error = ''
  try {
    const data = await request('/api/kyc/confirm', {
      method: 'POST',
      body: JSON.stringify({ state: stateValue })
    })
    state.verified = true
    state.kyc = data.kyc
    state.qrCode = ''
    state.appLaunchUrl = ''
    state.pendingState = ''
    window.history.replaceState({}, '', '/')
  } catch (err) {
    if (err.status === 409) {
      state.error = '支付宝还没有返回认证通过结果，请完成扫脸后再检查。'
    } else if (err.status === 410) {
      resetKyc()
      state.error = '本次认证已超时，请重新开始认证。'
    } else {
      state.error = err.message
    }
  } finally {
    state.confirming = false
  }
}

function resetKyc() {
  state.qrCode = ''
  state.appLaunchUrl = ''
  state.pendingState = ''
  state.error = ''
}

function openAlipay() {
  if (state.appLaunchUrl) {
    window.location.href = state.appLaunchUrl
  }
}

function openAlipayOnMobile() {
  if (state.appLaunchUrl && state.mobile) {
    window.setTimeout(openAlipay, 120)
  }
}

function isMobileBrowser() {
  return /Android|iPhone|iPad|iPod|Mobile/i.test(window.navigator.userAgent)
}

function formatDate(value) {
  if (!value) return ''
  return new Intl.DateTimeFormat('zh-CN', {
    dateStyle: 'medium',
    timeStyle: 'short'
  }).format(new Date(value))
}
</script>
