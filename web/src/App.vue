<template>
  <main class="shell">
    <section class="panel">
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
    </section>
  </main>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { AlertTriangle, CircleCheck, Clock3, LoaderCircle, LogIn, LogOut, ShieldCheck } from '@lucide/vue'
import QRCode from 'qrcode'

const state = reactive({
  loading: true,
  busy: false,
  confirming: false,
  authenticated: false,
  verified: false,
  user: {},
  kyc: null,
  qrCode: '',
  pendingState: '',
  error: ''
})

const form = reactive({
  name: '',
  id_number: ''
})

const callbackState = ref(new URLSearchParams(window.location.search).get('state') || '')
const callbackMessage = computed(() => {
  if (state.confirming) return '正在确认支付宝认证结果'
  if (state.verified) return '认证已完成并写回 Authentik'
  return '等待认证结果'
})

onMounted(async () => {
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
    state.qrCode = await QRCode.toDataURL(data.certify_url || data.redirect_url, {
      errorCorrectionLevel: 'M',
      margin: 1,
      scale: 8
    })
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
  state.pendingState = ''
  state.error = ''
}

function formatDate(value) {
  if (!value) return ''
  return new Intl.DateTimeFormat('zh-CN', {
    dateStyle: 'medium',
    timeStyle: 'short'
  }).format(new Date(value))
}
</script>
