"use strict";

(() => {
  const $ = (id) => document.getElementById(id);
  const stageNames = {idle: "尚未开始", captcha: "图形验证中", sms: "短信验证中", authenticated: "认证完成", error: "需要处理"};
  const controls = [...document.querySelectorAll("button")];
  let state = null;
  let busy = false;
  let refreshing = false;
  let forceLogin = false;
  let points = [];
  let captchaVersion = null;
  let lastEvents = "";
  let smsDeadline = 0;
  let smsCountdownValue = 0;

  function notice(text, error = false) {
    $("notice").hidden = !text;
    $("notice").classList.toggle("error", error);
    $("notice-text").textContent = text || "";
    $("notice-icon").textContent = error ? "!" : "ⓘ";
  }

  function setButton(id, text, disabled) {
    const button = $(id);
    if (text) button.textContent = text;
    button.disabled = Boolean(disabled || busy || (state && state.busy));
  }

  function renderPoints() {
    $("captcha-markers").replaceChildren();
    points.forEach(([x, y], index) => {
      const marker = document.createElement("span");
      marker.className = "captcha-marker";
      marker.textContent = String(index + 1);
      marker.style.left = `${x / 272 * 100}%`;
      marker.style.top = `${y / 192 * 100}%`;
      $("captcha-markers").append(marker);
    });
    $("point-counter").textContent = `已选择 ${points.length} / 3`;
    setButton("submit-captcha", null, points.length !== 3);
    setButton("undo-point", null, points.length === 0);
    setButton("reset-points", null, points.length === 0);
  }

  function renderEvents(events) {
    const signature = JSON.stringify(events || []);
    if (signature === lastEvents) return;
    lastEvents = signature;
    const list = $("event-list");
    list.replaceChildren();
    if (!events || !events.length) {
      const empty = document.createElement("li");
      empty.className = "empty-events";
      empty.textContent = "尚无活动。开始认证后，进度会显示在这里。";
      list.append(empty);
      return;
    }
    [...events].reverse().forEach((event) => {
      const row = document.createElement("li");
      const dot = document.createElement("span");
      dot.className = "event-indicator";
      const time = document.createElement("time");
      let value = event.time;
      if (typeof value === "number") value = new Date(value < 1e12 ? value * 1000 : value).toLocaleTimeString("zh-CN", {hour12: false});
      time.textContent = value || "—";
      const content = document.createElement("span");
      content.textContent = event.message || "";
      row.append(dot, time, content);
      list.append(row);
    });
  }

  function render() {
    if (!state) return;
    const stage = state.stage || "idle";
    const authenticated = stage === "authenticated";
    const online = state.tunnel === "online";
    const blocked = busy || state.busy;
    $("server").value = state.server || "未配置接入地址";
    if (!$("username").value && state.username) $("username").value = state.username;
    $("auth-overview").textContent = authenticated ? "已认证" : ({captcha: "等待图形验证", sms: "等待短信验证", error: "认证未完成"}[stage] || "等待认证");
    $("account-overview").textContent = state.username ? `账号 ${state.username}` : "尚未登录账号";
    $("auth-dot").classList.toggle("good", authenticated);
    $("auth-dot").classList.toggle("bad", stage === "error");
    $("tunnel-overview").textContent = online ? "已连接" : state.tunnel === "unavailable" ? "后台未就绪" : "未连接";
    $("tunnel-dot").classList.toggle("good", online);
    $("isolation-overview").textContent = state.isolated ? "隔离环境" : "认证模式";
    $("isolation-caption").textContent = state.isolated ? "VPN 在独立环境中运行" : "当前环境禁止建立隧道";
    $("isolation-dot").classList.toggle("good", Boolean(state.isolated));
    $("stage-badge").textContent = forceLogin ? "重新认证" : stageNames[stage] || stage;
    $("stage-badge").className = `badge ${authenticated && !forceLogin ? "success" : ["captcha", "sms"].includes(stage) ? "pending" : "neutral"}`;
    const index = forceLogin ? 0 : ({captcha: 1, sms: 2, authenticated: 3}[stage] || 0);
    ["password", "captcha", "sms"].forEach((name, i) => {
      $("step-" + name).classList.toggle("current", i === index);
      $("step-" + name).classList.toggle("complete", i < index);
    });
    $("login-form").hidden = !forceLogin && ["captcha", "sms", "authenticated"].includes(stage);
    $("captcha-panel").hidden = forceLogin || stage !== "captcha";
    $("sms-form").hidden = forceLogin || stage !== "sms";
    $("success-panel").hidden = forceLogin || !authenticated;
    $("success-account").textContent = state.username || "当前账号";
    $("session-details").textContent = `已保存 ${Number(state.cookie_count) || 0} 个 Cookie · 凭据已加密`;
    if (stage === "captcha" && captchaVersion !== state.captcha_version) {
      captchaVersion = state.captcha_version;
      points = [];
      $("coordinate-value").value = "";
      $("captcha-image").src = `/api/captcha?v=${encodeURIComponent(captchaVersion || 0)}`;
    }
    $("proxy-address").textContent = state.proxy_address || "127.0.0.1:10808";
    $("connection-badge").textContent = online ? "已连接" : "未连接";
    $("connection-badge").className = `badge ${online ? "success" : "neutral"}`;
    $("network-line").classList.toggle("connected", online);
    $("connection-heading").textContent = online ? "已接入内网。" : "准备好后，再连接。";
    $("connection-description").textContent = online ? "VPN 隧道正在隔离环境中运行。需要内网访问的应用可使用下方代理入口。" : state.disconnect_reason ? state.disconnect_reason : !state.isolated ? "当前仅允许完成身份认证。请在隔离运行环境中运行服务，再建立 VPN 隧道。" : "认证只确认你的身份；点击连接后，才会在隔离环境中建立 VPN 隧道。";
    $("connect-button").hidden = online;
    $("disconnect-button").hidden = !online;
    controls.forEach((control) => { control.disabled = Boolean(blocked); });
    setButton("connect-button", null, !authenticated || !state.isolated || online);
    setButton("disconnect-button", null, !online || !state.isolated);
    setButton("restore-session", null, !state.session_available);
    setButton("forget-session", null, !state.session_available);
    setButton("verify-sms", null, stage !== "sms");
    setButton("send-sms", smsCountdownValue > 0 ? `重新发送 (${smsCountdownValue}s)` : "发送验证码", stage !== "sms" || smsCountdownValue > 0);
    setButton("refresh-captcha", null, stage !== "captcha");
    renderPoints();
    renderEvents(state.events);
  }

  function acceptState(next) {
    if (!next || typeof next !== "object") return;
    if (next.state && typeof next.state === "object") next = next.state;
    state = next;
    if (typeof state.sms_retry_after === "number" && state.sms_retry_after > 0) {
      smsDeadline = Date.now() + state.sms_retry_after * 1000;
    }
    render();
  }

  async function refresh() {
    if (refreshing || busy) return;
    refreshing = true;
    try {
      const response = await fetch("/api/state", {cache: "no-store", credentials: "same-origin"});
      if (!response.ok) throw new Error("暂时无法读取服务状态，请稍后刷新。");
      acceptState(await response.json());
    } catch (error) {
      notice(error.message || "无法连接管理服务。", true);
    } finally {
      refreshing = false;
    }
  }

  async function action(path, data = {}, element) {
    if (busy || !state || state.busy) return false;
    busy = true;
    notice("");
    if (element) element.classList.add("is-loading");
    render();
    try {
      const response = await fetch(path, {
        method: "POST", credentials: "same-origin", cache: "no-store",
        headers: {"Content-Type": "application/json", "X-CSRF-Token": state.csrf || ""},
        body: JSON.stringify(data),
      });
      const result = await response.json();
      if (result.state) acceptState(result.state);
      else if (result.stage) acceptState(result);
      if (!response.ok || result.error) throw new Error(result.error || "操作未完成，请稍后重试。");
      forceLogin = false;
      notice((result.state || result).message || "操作已完成。");
      return true;
    } catch (error) {
      notice(error.message || "操作未完成，请稍后重试。", true);
      return false;
    } finally {
      data.password = "";
      data.code = "";
      busy = false;
      if (element) element.classList.remove("is-loading");
      render();
      await refresh();
    }
  }

  $("login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!event.currentTarget.reportValidity()) return;
    const data = {username: $("username").value.trim(), password: $("password").value};
    $("password").value = "";
    $("password").type = "password";
    $("toggle-password").textContent = "显示";
    await action("/api/auth/begin", data, $("login-button"));
  });
  $("toggle-password").addEventListener("click", () => {
    const input = $("password");
    input.type = input.type === "password" ? "text" : "password";
    $("toggle-password").textContent = input.type === "password" ? "显示" : "隐藏";
    $("toggle-password").setAttribute("aria-label", input.type === "password" ? "显示密码" : "隐藏密码");
  });
  $("captcha-board").addEventListener("click", (event) => {
    if (busy || !state || state.stage !== "captcha" || points.length >= 3) return;
    const image = $("captcha-image");
    if (!image.complete || !image.naturalWidth) return;
    const bounds = image.getBoundingClientRect();
    const x = Math.round((event.clientX - bounds.left) / bounds.width * 272);
    const y = Math.round((event.clientY - bounds.top) / bounds.height * 192);
    if (x < 0 || x >= 272 || y < 0 || y >= 160) return;
    points.push([x, y]);
    renderPoints();
  });
  $("undo-point").addEventListener("click", () => { points.pop(); renderPoints(); });
  $("reset-points").addEventListener("click", () => { points = []; renderPoints(); });
  $("apply-coordinates").addEventListener("click", () => {
    const pairs = $("coordinate-value").value.trim().split(/[;；]/).map((pair) => pair.trim().split(/[,，]/).map(Number));
    if (pairs.length !== 3 || !pairs.every((pair) => pair.length === 2 && pair.every(Number.isFinite) && pair[0] >= 0 && pair[0] < 272 && pair[1] >= 0 && pair[1] < 160)) {
      notice("请输入三组有效坐标：x 在 0–271 之间，y 在 0–159 之间。", true);
      return;
    }
    points = pairs.map(([x, y]) => [Math.min(271, Math.round(x)), Math.min(159, Math.round(y))]);
    renderPoints();
  });
  $("refresh-captcha").addEventListener("click", async () => {
    const success = await action("/api/auth/captcha/refresh", {}, $("refresh-captcha"));
    if (success) { points = []; renderPoints(); }
  });
  $("submit-captcha").addEventListener("click", () => action("/api/auth/captcha", {coordinates: points.map((point) => [...point]), width: 272, height: 192}, $("submit-captcha")));
  $("captcha-image").addEventListener("error", () => { if (state && state.stage === "captcha") notice("验证码图片未能载入，请点击“换一张”重试。", true); });
  $("send-sms").addEventListener("click", () => action("/api/auth/sms/send", {}, $("send-sms")));
  $("sms-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!event.currentTarget.reportValidity()) return;
    const code = $("sms-code").value.trim();
    $("sms-code").value = "";
    await action("/api/auth/sms/verify", {code}, $("verify-sms"));
  });
  $("restore-session").addEventListener("click", () => action("/api/auth/restore", {}, $("restore-session")));
  $("connect-button").addEventListener("click", () => action("/api/tunnel/connect", {}, $("connect-button")));
  $("disconnect-button").addEventListener("click", () => action("/api/tunnel/disconnect", {}, $("disconnect-button")));
  $("forget-session").addEventListener("click", () => {
    if (window.confirm("清除本地保存的认证会话？此操作不会自动注销或断开已运行的 VPN 隧道。")) action("/api/session/forget", {}, $("forget-session"));
  });
  $("switch-account").addEventListener("click", () => { forceLogin = true; render(); $("password").focus(); });
  $("dismiss-notice").addEventListener("click", () => notice(""));
  $("refresh-state").addEventListener("click", refresh);
  $("copy-proxy").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText($("proxy-address").textContent);
      $("copy-proxy").textContent = "已复制";
      setTimeout(() => { $("copy-proxy").textContent = "复制"; }, 1800);
    } catch (_) {
      notice(`代理地址：${$("proxy-address").textContent}。请手动复制。`);
    }
  });
  setInterval(() => {
    const remaining = Math.max(0, Math.ceil((smsDeadline - Date.now()) / 1000));
    if (remaining !== smsCountdownValue) {
      smsCountdownValue = remaining;
      if (state) setButton("send-sms", remaining > 0 ? `重新发送 (${remaining}s)` : "发送验证码", state.stage !== "sms" || remaining > 0);
    }
  }, 250);
  setInterval(refresh, 5000);
  refresh();
})();
