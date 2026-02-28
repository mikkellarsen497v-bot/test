// Minimal client-side enhancements for the static preview
(function () {
  // When API_BASE is set (e.g. for InfinityFree + Render), send relative /api/* requests to that host
  window.API_BASE = window.API_BASE || "";
  const origFetch = window.fetch;
  window.fetch = function (url, opts) {
    if (typeof url === "string" && url.startsWith("/") && window.API_BASE) {
      url = window.API_BASE + url;
      opts = (opts ? { ...opts } : {});
      opts.credentials = "include";
    }
    return origFetch.call(this, url, opts || {});
  };

  const setActiveNav = () => {
    const path = (location.pathname.split("/").pop() || "index.html").toLowerCase();
    document.querySelectorAll("[data-nav]").forEach((a) => {
      const href = (a.getAttribute("href") || "").toLowerCase();
      const isActive = href === path;
      if (isActive) a.classList.add("active");
    });
  };

  const fetchMe = async () => {
    try {
      const res = await fetch("/api/me", { headers: { "Accept": "application/json" } });
      const json = await res.json();
      return json && json.ok ? json.user : null;
    } catch {
      return null;
    }
  };

  const wireAuthUi = async () => {
    const user = await fetchMe();

    // Replace Sign In link with account/logout when logged in
    const signInLink = Array.from(document.querySelectorAll("a")).find((a) => (a.getAttribute("href") || "").includes("signin.html"));
    const nav = document.querySelector("nav.nav");

    if (user) {
      if (signInLink && !document.querySelector(".user-menu")) {
        const displayName = user.displayName || user.username;
        const userId = user.id != null ? String(user.id) : "";

        const wrap = document.createElement("div");
        wrap.className = "user-menu";
        wrap.setAttribute("role", "group");

        const trigger = document.createElement("button");
        trigger.type = "button";
        trigger.className = "pill user-menu-trigger";
        trigger.setAttribute("aria-haspopup", "true");
        trigger.setAttribute("aria-expanded", "false");
        trigger.textContent = displayName;

        const dropdown = document.createElement("div");
        dropdown.className = "user-menu-dropdown";
        dropdown.setAttribute("role", "menu");
        dropdown.innerHTML = [
          userId ? `<a href="./profile.html?id=${encodeURIComponent(userId)}" role="menuitem">My profile</a>` : "",
          `<a href="./account.html" role="menuitem">Account</a>`,
          `<a href="./settings.html" role="menuitem">Profile settings</a>`,
          `<a href="#" data-logout role="menuitem">Logout</a>`,
        ].filter(Boolean).join("");

        dropdown.querySelector("[data-logout]").addEventListener("click", async (e) => {
          e.preventDefault();
          await fetch("/api/logout", { method: "POST" });
          location.href = "./index.html";
        });

        trigger.addEventListener("click", (e) => {
          e.stopPropagation();
          const open = wrap.classList.toggle("open");
          trigger.setAttribute("aria-expanded", open ? "true" : "false");
        });

        document.addEventListener("click", () => wrap.classList.remove("open"));

        wrap.appendChild(trigger);
        wrap.appendChild(dropdown);
        signInLink.parentNode.replaceChild(wrap, signInLink);
      }
    } else {
      // If not logged in, ensure there's a Sign Up link near Sign In
      const hasSignup = Array.from(document.querySelectorAll("a")).some((a) => (a.getAttribute("href") || "").includes("signup.html"));
      if (nav && !hasSignup) {
        const signUp = document.createElement("a");
        signUp.className = "pill";
        signUp.setAttribute("href", "./signup.html");
        signUp.textContent = "Sign Up";

        // insert before Sign In if possible
        if (signInLink && signInLink.parentElement === nav) nav.insertBefore(signUp, signInLink);
        else nav.appendChild(signUp);
      }
    }

    // If admin, show Admin Panel link
    if (user && user.role === "admin") {
      const hasAdmin = Array.from(document.querySelectorAll("a")).some((a) => (a.getAttribute("href") || "").includes("admin.html"));
      if (nav && !hasAdmin) {
        const admin = document.createElement("a");
        admin.className = "pill";
        admin.setAttribute("href", "./admin.html");
        admin.textContent = "Admin";
        nav.appendChild(admin);
      }
    }

    // Guard pages that require login
    document.querySelectorAll("[data-require-auth]").forEach((el) => {
      if (!user) {
        const next = encodeURIComponent(location.pathname.split("/").pop() || "index.html");
        location.href = `./signin.html?next=${next}`;
      }
    });

    // Guard pages that require admin
    document.querySelectorAll("[data-require-admin]").forEach((_el) => {
      if (!user) {
        const next = encodeURIComponent(location.pathname.split("/").pop() || "index.html");
        location.href = `./signin.html?next=${next}`;
        return;
      }
      if (user.role !== "admin") location.href = "./index.html";
    });
  };

  const updateStatusClock = () => {
    const el = document.querySelector("[data-now]");
    if (!el) return;
    const d = new Date();
    el.textContent = d.toLocaleString(undefined, {
      weekday: "short",
      year: "numeric",
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  const updateServerPlayers = () => {
    fetch("/api/server-status", { headers: { Accept: "application/json" } })
      .then((res) => res.json())
      .then((data) => {
        const maxPlayers = data && typeof data.maxPlayers === "number" ? data.maxPlayers : 128;
        const online = !!(data && data.ok && data.online);
        document.querySelectorAll("[data-server-players]").forEach((el) => {
          if (online && typeof data.players === "number" && typeof data.maxPlayers === "number") {
            el.textContent = `${data.players} / ${data.maxPlayers}`;
          } else {
            el.textContent = "— / " + maxPlayers;
          }
        });
        document.querySelectorAll("[data-server-uptime]").forEach((el) => {
          el.textContent = (data && data.ok && data.uptimeFormatted) ? data.uptimeFormatted : "—";
        });
        document.querySelectorAll("[data-server-map]").forEach((el) => {
          el.textContent = (data && data.ok && data.online && data.map) ? data.map : "—";
        });
        document.querySelectorAll("[data-server-badge]").forEach((el) => {
          el.textContent = online ? "Online" : "Offline";
          el.classList.toggle("ok", online);
          el.classList.toggle("off", !online);
        });
      })
      .catch(() => {
        document.querySelectorAll("[data-server-players]").forEach((el) => { el.textContent = "— / 128"; });
        document.querySelectorAll("[data-server-uptime]").forEach((el) => { el.textContent = "—"; });
        document.querySelectorAll("[data-server-map]").forEach((el) => { el.textContent = "—"; });
        document.querySelectorAll("[data-server-badge]").forEach((el) => {
          el.textContent = "Offline";
          el.classList.remove("ok");
          el.classList.add("off");
        });
      });
  };

  const wireForms = () => {
    document.querySelectorAll("form[data-api]").forEach((form) => {
      const endpoint = form.getAttribute("data-api");
      const status = form.querySelector("[data-form-status]");
      const submitBtn = form.querySelector("button[type='submit']");

      form.addEventListener("submit", async (e) => {
        e.preventDefault();
        if (!endpoint) return;

        if (status) status.textContent = "Submitting…";
        if (submitBtn) submitBtn.disabled = true;

        try {
          const fd = new FormData(form);
          const payload = {};
          for (const [k, v] of fd.entries()) payload[k] = String(v);

          const res = await fetch(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
            credentials: "same-origin",
          });
          const json = await res.json().catch(() => null);

          if (!res.ok || !json || !json.ok) {
            const msg = (json && json.error) || `Request failed (${res.status})`;
            if (status) status.textContent = msg;
            return;
          }

          form.reset();
          const refMsg = `Submitted successfully. Reference ID: ${json.id}`;
          const topicMsg = json.topicId ? ` You can view your application <a href="./topic.html?id=${encodeURIComponent(json.topicId)}">here</a>.` : "";
          if (status) {
            status.innerHTML = refMsg + topicMsg;
          }
        } catch (err) {
          if (status) status.textContent = "Network error. Is the site server running?";
        } finally {
          if (submitBtn) submitBtn.disabled = false;
        }
      });
    });
  };

  function injectSiteAnnouncement() {
    function showBanner(text, link, dismissKey) {
      if (!text || !text.trim()) return;
      const wrap = document.createElement("div");
      wrap.className = "site-announcement";
      wrap.setAttribute("role", "banner");
      let inner = document.createTextNode(text);
      if (link) {
        const a = document.createElement("a");
        a.href = link;
        a.target = "_blank";
        a.rel = "noopener noreferrer";
        a.textContent = " Learn more";
        wrap.appendChild(inner);
        wrap.appendChild(a);
      } else wrap.appendChild(inner);
      const dismiss = document.createElement("button");
      dismiss.type = "button";
      dismiss.className = "site-announcement-dismiss";
      dismiss.textContent = "Dismiss";
      dismiss.addEventListener("click", () => {
        sessionStorage.setItem(dismissKey, "1");
        wrap.remove();
      });
      wrap.appendChild(dismiss);
      document.body.insertBefore(wrap, document.body.firstChild);
    }
    fetch("/api/announcement", { headers: { Accept: "application/json" } })
      .then((r) => r.json())
      .then((data) => {
        if (data && data.ok && data.announcement && data.announcement.text) {
          const key = "pny_announcement_dismissed_" + (data.announcement.id || "server");
          if (sessionStorage.getItem(key)) return;
          showBanner(data.announcement.text, data.announcement.link || "", key);
          return;
        }
        if (sessionStorage.getItem("pny_announcement_dismissed")) return;
        const text = localStorage.getItem("pny_announcement");
        const link = (localStorage.getItem("pny_announcement_link") || "").trim();
        showBanner(text, link, "pny_announcement_dismissed");
      })
      .catch(() => {
        if (sessionStorage.getItem("pny_announcement_dismissed")) return;
        const text = localStorage.getItem("pny_announcement");
        const link = (localStorage.getItem("pny_announcement_link") || "").trim();
        showBanner(text, link, "pny_announcement_dismissed");
      });
  }

  document.addEventListener("DOMContentLoaded", () => {
    injectSiteAnnouncement();
    setActiveNav();
    updateStatusClock();
    updateServerPlayers();
    wireForms();
    wireAuthUi();
    setInterval(updateStatusClock, 30_000);
    setInterval(updateServerPlayers, 60_000);
  });
})();

