/* =========================================================
   网络环境自检工具
   检测项：时区、系统/浏览器语言、IP 归属地、DNS 解析器、
          WebRTC 真实 IP 泄露、代理特征、输入解析
   ========================================================= */

// ---------- 常量 ----------
const CHINA_TIMEZONES = new Set([
  "Asia/Shanghai", "Asia/Chongqing", "Asia/Harbin",
  "Asia/Urumqi", "Asia/Kashgar", "PRC",
  "Asia/Hong_Kong", "Asia/Macau", "Asia/Taipei",
  "Etc/GMT-8",
]);

const CHINA_LANG_PREFIXES = ["zh-cn", "zh-sg", "zh-hans", "zh"];
const HK_TW_LANG_PREFIXES = ["zh-tw", "zh-hk", "zh-mo", "zh-hant"];

const RISK = { SAFE: 0, WARN: 1, DANGER: 2 };
const RISK_TEXT = ["安全", "注意", "高风险"];
const RISK_CLASS = ["badge-safe", "badge-warn", "badge-danger"];

// 各检测项权重（满分 100）
const WEIGHTS = {
  timezone: 20,
  language: 20,
  ip: 25,
  dns: 15,
  webrtc: 10,
  proxy: 10,
};

// ---------- DOM ----------
const btnStart = document.getElementById("btnStart");
const scoreNum = document.getElementById("scoreNum");
const scoreCircle = document.getElementById("scoreCircle");
const scoreTitle = document.getElementById("scoreTitle");
const scoreDesc = document.getElementById("scoreDesc");

const btnParse = document.getElementById("btnParse");
const btnClear = document.getElementById("btnClear");
const inputArea = document.getElementById("inputArea");
const parserResult = document.getElementById("parserResult");
const parserCount = document.getElementById("parserCount");

// 全局检测结果
const results = {
  timezone: null,
  language: null,
  ip: null,
  dns: null,
  webrtc: null,
  proxy: null,
};

// ---------- 工具函数 ----------
function setBadge(id, risk, text) {
  const el = document.querySelector(`#${id} .check-badge`);
  el.className = "check-badge " + RISK_CLASS[risk];
  el.textContent = text || RISK_TEXT[risk];
}

function setDetail(id, html) {
  document.getElementById("detail-" + id).innerHTML = html;
}

function logIpRisk(countryCode) {
  if (!countryCode) return RISK.WARN;
  const code = countryCode.toUpperCase();
  if (code === "CN") return RISK.DANGER;
  if (["HK", "MO", "TW"].includes(code)) return RISK.WARN;
  return RISK.SAFE;
}

// ---------- 1. 时区检测 ----------
function checkTimezone() {
  const tz = Intl.DateTimeFormat().resolvedOptions().timeZone || "未知";
  const offset = -new Date().getTimezoneOffset() / 60; // UTC 偏移小时
  const isCnTz = CHINA_TIMEZONES.has(tz);
  const isUtc8 = offset === 8;

  let risk = RISK.SAFE;
  let detail = `时区：<code>${tz}</code>，UTC 偏移：<code>+${offset}:00</code>`;
  if (isCnTz) {
    risk = RISK.DANGER;
    detail += "<br/>⚠️ 该时区为大中华区常用时区";
  } else if (isUtc8) {
    risk = RISK.WARN;
    detail += "<br/>⚠️ UTC+8 与中国大陆时区一致";
  } else {
    detail += "<br/>✅ 时区不属于大中华区";
  }

  results.timezone = { risk, weight: WEIGHTS.timezone };
  setBadge("check-timezone", risk);
  setDetail("timezone", detail);
}

// ---------- 2. 语言检测 ----------
function checkLanguage() {
  const langs = Array.from(navigator.languages || []);
  if (navigator.language && !langs.includes(navigator.language)) {
    langs.unshift(navigator.language);
  }
  const sysLang = navigator.userLanguage || navigator.systemLanguage || "";
  if (sysLang && !langs.includes(sysLang)) langs.push(sysLang);

  const display = langs.length ? langs.join(", ") : "未知";

  let risk = RISK.SAFE;
  let detail = `浏览器语言：<code>${display}</code>`;

  const primary = (langs[0] || "").toLowerCase();
  if (CHINA_LANG_PREFIXES.some((p) => primary.startsWith(p))) {
    risk = RISK.DANGER;
    detail += "<br/>⚠️ 首选语言为简体中文";
  } else if (HK_TW_LANG_PREFIXES.some((p) => primary.startsWith(p))) {
    risk = RISK.WARN;
    detail += "<br/>⚠️ 首选语言为繁体中文";
  } else if (langs.some((l) => l.toLowerCase().startsWith("zh"))) {
    risk = RISK.WARN;
    detail += "<br/>⚠️ 语言列表中包含中文";
  } else {
    detail += "<br/>✅ 未检测到中文语言";
  }

  results.language = { risk, weight: WEIGHTS.language };
  setBadge("check-language", risk);
  setDetail("language", detail);
}

// ---------- 3. IP 归属地检测 ----------
async function checkIP() {
  setDetail("ip", "正在查询 IP 归属地…");
  try {
    const res = await fetch("https://ipwho.is/", { cache: "no-store" });
    const data = await res.json();

    if (!data.success) {
      setBadge("check-ip", RISK.WARN, "查询失败");
      setDetail("ip", `IP 查询失败：${data.message || "未知错误"}`);
      results.ip = { risk: RISK.WARN, weight: WEIGHTS.ip };
      return;
    }

    const ip = data.ip;
    const country = data.country;
    const countryCode = data.country_code;
    const city = data.city;
    const isp = data.connection?.isp || data.isp || "未知";
    const risk = logIpRisk(countryCode);

    let detail = `IP：<code>${ip}</code><br/>国家/地区：<code>${country}</code>（${countryCode}）<br/>城市：<code>${city}</code><br/>运营商：<code>${isp}</code>`;
    if (risk === RISK.DANGER) detail += "<br/>⚠️ IP 归属地为中国大陆";
    else if (risk === RISK.WARN) detail += "<br/>⚠️ IP 归属地为港澳台地区";
    else detail += "<br/>✅ IP 不在大中华区";

    results.ip = { risk, weight: WEIGHTS.ip, ip };
    setBadge("check-ip", risk);
    setDetail("ip", detail);
  } catch (err) {
    setBadge("check-ip", RISK.WARN, "查询失败");
    setDetail("ip", "IP 查询失败（可能被网络拦截）：" + err.message);
    results.ip = { risk: RISK.WARN, weight: WEIGHTS.ip };
  }
}

// ---------- 4. DNS 解析器检测 ----------
async function checkDNS() {
  setDetail("dns", "正在检测 DNS 解析器…");
  try {
    // 1. 获取测试 ID
    const idRes = await fetch("https://bash.ws/dnsleak/test", { cache: "no-store" });
    const idData = await idRes.json();
    const testId = idData.id;
    if (!testId) throw new Error("无法获取 DNS 测试 ID");

    // 2. 触发 DNS 解析（加载一张唯一子域名图片）
    await new Promise((resolve) => {
      const img = new Image();
      img.onload = img.onerror = () => resolve();
      img.src = `https://${testId}.bash.ws/logo.png`;
      setTimeout(resolve, 2500);
    });

    // 等一小会让服务端记录
    await new Promise((r) => setTimeout(r, 800));

    // 3. 查询解析结果
    const resRes = await fetch(`https://bash.ws/dnsleak/test/${testId}?json`, { cache: "no-store" });
    const resolvers = await resRes.json();

    if (!Array.isArray(resolvers) || resolvers.length === 0) {
      setBadge("check-dns", RISK.WARN, "未识别");
      setDetail("dns", "未能获取 DNS 解析器信息");
      results.dns = { risk: RISK.WARN, weight: WEIGHTS.dns };
      return;
    }

    const items = resolvers.map((r) => {
      const ip = r.ip || r.address || "未知";
      const cc = (r.country || "").toUpperCase();
      const risk = logIpRisk(cc);
      return { ip, country: r.country || "未知", cc, risk };
    });

    const maxRisk = Math.max(...items.map((i) => i.risk));
    let detail = "检测到 " + items.length + " 个 DNS 解析器：<br/>";
    detail += items
      .map((i) => {
        const flag =
          i.risk === RISK.DANGER ? "⚠️" : i.risk === RISK.WARN ? "❗" : "✅";
        return `${flag} <code>${i.ip}</code>（${i.country}）`;
      })
      .join("<br/>");

    if (maxRisk === RISK.DANGER) detail += "<br/>⚠️ 存在中国大陆 DNS 解析器";
    else if (maxRisk === RISK.WARN) detail += "<br/>⚠️ 存在港澳台 DNS 解析器";
    else detail += "<br/>✅ DNS 解析器不在大中华区";

    results.dns = { risk: maxRisk, weight: WEIGHTS.dns };
    setBadge("check-dns", maxRisk);
    setDetail("dns", detail);
  } catch (err) {
    setBadge("check-dns", RISK.WARN, "查询失败");
    setDetail("dns", "DNS 检测失败：" + err.message);
    results.dns = { risk: RISK.WARN, weight: WEIGHTS.dns };
  }
}

// ---------- 5. WebRTC 真实 IP 泄露检测 ----------
function checkWebRTC() {
  return new Promise((resolve) => {
    setDetail("webrtc", "正在检测 WebRTC IP 泄露…");
    const ips = new Set();
    const pc = new RTCPeerConnection({ iceServers: [] });
    pc.createDataChannel("");

    pc.onicecandidate = (e) => {
      if (!e.candidate) {
        // 收集完毕
        showWebRTCResult(Array.from(ips));
        resolve();
        return;
      }
      const cand = e.candidate.candidate;
      // 提取 IP（IPv4 / IPv6）
      const ipMatch = cand.match(/([0-9]{1,3}(\.[0-9]{1,3}){3}|[a-f0-9:]+:[a-f0-9:]+)/i);
      if (ipMatch) {
        const ip = ipMatch[1];
        if (!ip.endsWith(".local") && !ip.includes(":")) {
          ips.add(ip);
        } else if (ip.includes(":")) {
          ips.add(ip);
        }
      }
    };

    pc.createOffer()
      .then((offer) => pc.setLocalDescription(offer))
      .catch(() => {
        showWebRTCResult(Array.from(ips));
        resolve();
      });

    // 超时兜底
    setTimeout(() => {
      showWebRTCResult(Array.from(ips));
      try { pc.close(); } catch {}
      resolve();
    }, 5000);
  });
}

function showWebRTCResult(ips) {
  if (ips.length === 0) {
    setBadge("check-webrtc", RISK.SAFE, "未泄露");
    setDetail("webrtc", "✅ 未检测到 WebRTC IP 泄露（可能已被浏览器/扩展屏蔽）");
    results.webrtc = { risk: RISK.SAFE, weight: WEIGHTS.webrtc, ips: [] };
    return;
  }

  const localIps = ips.filter(isPrivateIp);
  const publicIps = ips.filter((ip) => !isPrivateIp(ip));

  let detail = "泄露 IP 列表：<br/>";
  if (publicIps.length) {
    detail += `公网 IP：<code>${publicIps.join("</code>, <code>")}</code><br/>`;
  }
  if (localIps.length) {
    detail += `内网 IP：<code>${localIps.join("</code>, <code>")}</code><br/>`;
  }

  // 判断风险：如果泄露的公网 IP 与 API 查询到的 IP 不同，说明可能存在真实 IP 泄露
  const apiIp = results.ip?.ip;
  let risk = RISK.SAFE;
  if (publicIps.length > 0) {
    risk = RISK.WARN;
    if (apiIp && !publicIps.includes(apiIp)) {
      risk = RISK.DANGER;
      detail += `⚠️ 泄露的公网 IP <code>${publicIps[0]}</code> 与对外 IP <code>${apiIp}</code> 不一致，可能暴露了真实网络环境`;
    } else {
      detail += "ℹ️ 泄露的公网 IP 与对外 IP 一致";
    }
  } else {
    detail += "✅ 仅泄露内网 IP";
  }

  results.webrtc = { risk, weight: WEIGHTS.webrtc, ips };
  setBadge("check-webrtc", risk);
  setDetail("webrtc", detail);
}

function isPrivateIp(ip) {
  if (ip.startsWith("10.") || ip.startsWith("192.168.")) return true;
  if (ip.startsWith("172.")) {
    const parts = ip.split(".");
    const second = parseInt(parts[1], 10);
    if (second >= 16 && second <= 31) return true;
  }
  if (ip.startsWith("127.") || ip.startsWith("169.254.")) return true;
  if (ip.startsWith("fe80:") || ip.startsWith("::1") || ip.startsWith("fc") || ip.startsWith("fd")) return true;
  return false;
}

// ---------- 6. 代理/中转站特征检测 ----------
function checkProxy() {
  const webrtcIps = results.webrtc?.ips || [];
  const apiIp = results.ip?.ip;
  const publicIps = webrtcIps.filter((ip) => !isPrivateIp(ip));

  let risk = RISK.SAFE;
  let detail = "";

  if (!apiIp) {
    detail = "无法获取对外 IP，跳过代理检测";
    risk = RISK.WARN;
  } else if (publicIps.length === 0) {
    detail = `对外 IP：<code>${apiIp}</code><br/>WebRTC 未泄露公网 IP，无法判断是否使用代理`;
    risk = RISK.SAFE;
  } else if (publicIps.includes(apiIp)) {
    detail = `对外 IP（<code>${apiIp}</code>）与 WebRTC 泄露 IP 一致<br/>✅ 未检测到代理/VPN 特征`;
    risk = RISK.SAFE;
  } else {
    detail = `对外 IP：<code>${apiIp}</code><br/>WebRTC 泄露 IP：<code>${publicIps.join(", ")}</code><br/>⚠️ 两者不一致，可能正在使用代理/VPN/中转站`;
    risk = RISK.DANGER;
  }

  results.proxy = { risk, weight: WEIGHTS.proxy };
  setBadge("check-proxy", risk);
  setDetail("proxy", detail);
}

// ---------- 风险评分汇总 ----------
function calcScore() {
  let total = 0;
  let max = 0;
  Object.entries(results).forEach(([key, r]) => {
    if (r) {
      // SAFE=0 分, WARN=0.5*权重, DANGER=1*权重
      const score = r.risk === RISK.DANGER ? r.weight : r.risk === RISK.WARN ? r.weight * 0.5 : 0;
      total += score;
      max += r.weight;
    }
  });

  const score = Math.round((total / max) * 100);
  scoreNum.textContent = score;

  // 圆环颜色
  let color, title, desc;
  if (score < 30) {
    color = "#2ecc71";
    title = "环境风险较低";
    desc = "你的时区、语言、IP、DNS 等信息大多不在大中华区，被识别为该区域用户的概率较低。";
  } else if (score < 70) {
    color = "#f39c12";
    title = "存在一定识别风险";
    desc = "部分检测项命中了大中华区特征，建议调整相关设置（如系统语言、时区、DNS）。";
  } else {
    color = "#e74c3c";
    title = "识别风险较高";
    desc = "多项检测项命中大中华区特征，当前环境很可能被识别为该区域用户。";
  }
  scoreCircle.style.background = `conic-gradient(${color} ${(score / 100) * 360}deg, #444 0deg)`;
  scoreTitle.textContent = title;
  scoreDesc.textContent = desc;
}

// ---------- 主流程 ----------
async function runAllChecks() {
  btnStart.disabled = true;
  btnStart.textContent = "检测中…";
  scoreNum.textContent = "…";

  // 同步检测
  checkTimezone();
  checkLanguage();

  // 异步检测（需要网络）
  await checkIP();
  await checkWebRTC();
  checkProxy();
  await checkDNS();

  calcScore();

  btnStart.disabled = false;
  btnStart.textContent = "🔄 重新检测";
}

btnStart.addEventListener("click", runAllChecks);

// ---------- 输入解析器 ----------
btnParse.addEventListener("click", () => {
  const raw = inputArea.value.trim();
  if (!raw) {
    parserCount.textContent = "";
    parserResult.classList.remove("show");
    parserResult.innerHTML = "";
    return;
  }

  // 支持：中文逗号（，）、英文逗号（,）、中文分号（；）、英文分号（;）、换行、竖线（|）
  // 自动去除首尾空格，支持逗号后无空格
  const items = raw
    .split(/[,，;；|\n\r]+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);

  parserCount.textContent = `共解析出 ${items.length} 项`;

  if (items.length === 0) {
    parserResult.classList.remove("show");
    parserResult.innerHTML = "";
    return;
  }

  parserResult.innerHTML = items
    .map((item, idx) => `<div class="item"><span class="idx">${idx + 1}.</span><span>${escapeHtml(item)}</span></div>`)
    .join("");
  parserResult.classList.add("show");
});

btnClear.addEventListener("click", () => {
  inputArea.value = "";
  parserResult.innerHTML = "";
  parserResult.classList.remove("show");
  parserCount.textContent = "";
});

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}
