/* =========================================================================
 *  EDIT ME — your links live here. Change these five values and you're done.
 * ========================================================================= */
var CONFIG = {
  // Where your live auth demo is hosted (the auth-service). Once deployed, set
  // this to e.g. "https://auth.yourdomain.com". Until then it points nowhere.
  demoUrl: "https://auth.yourdomain.com",

  // Used INSTEAD of demoUrl whenever this page is itself opened from localhost,
  // so local testing hits your local auth-service without you having to edit
  // (and remember to revert) demoUrl above. Ignored once the site is deployed.
  localDemoUrl: "http://localhost:8080",

  // Your GitHub repo for the auth platform.
  githubUrl: "https://github.com/kaushal-bhatt/auth-platform",

  // Optional: a link straight to the README (defaults to the repo).
  readmeUrl: "https://github.com/kaushal-bhatt/auth-platform#readme",

  // Résumé. Points at the resume page shipped alongside this site; swap for a
  // PDF/Drive link if you prefer. Leave "" to hide the button.
  resumeUrl: "resume.html",

  // Contact.
  email: "kaushalbhatt28650@gmail.com",
  linkedinUrl: "https://www.linkedin.com/in/kaushal8650",

  // Shown as small text under the contact buttons. Set to "" to hide it.
  phone: ""
};
/* ===================== end of things you need to edit ===================== */

(function () {
  "use strict";

  // ---- resolve the demo URL: local instance when testing locally, deployed one otherwise ----
  // file:// has an empty hostname, which counts as local too (opening index.html by double-click).
  var isLocal = ["localhost", "127.0.0.1", "::1", ""].indexOf(location.hostname) !== -1;
  var demoUrl = (isLocal && CONFIG.localDemoUrl) ? CONFIG.localDemoUrl : CONFIG.demoUrl;

  // ---- wire up all the configurable links ----
  function setLinks(selector, href, opts) {
    var nodes = document.querySelectorAll(selector);
    for (var i = 0; i < nodes.length; i++) {
      if (!href) { nodes[i].style.display = "none"; continue; }
      nodes[i].setAttribute("href", href);
      if (opts && opts.blank) { nodes[i].setAttribute("target", "_blank"); nodes[i].setAttribute("rel", "noopener"); }
    }
  }
  setLinks("[data-demo-link]", demoUrl, { blank: true });
  setLinks("[data-github-link]", CONFIG.githubUrl, { blank: true });
  setLinks("[data-readme-link]", CONFIG.readmeUrl, { blank: true });
  setLinks("[data-resume-link]", CONFIG.resumeUrl, { blank: true });
  setLinks("[data-linkedin-link]", CONFIG.linkedinUrl, { blank: true });
  setLinks("[data-email-link]", CONFIG.email ? "mailto:" + CONFIG.email : "");

  // ---- contact detail line (email + optional phone) ----
  var detail = document.querySelector("[data-contact-detail]");
  if (detail) {
    var parts = [];
    if (CONFIG.email) parts.push('<a href="mailto:' + CONFIG.email + '">' + CONFIG.email + "</a>");
    if (CONFIG.phone) parts.push('<a href="tel:' + CONFIG.phone.replace(/\s/g, "") + '">' + CONFIG.phone + "</a>");
    detail.innerHTML = parts.join(" &nbsp;&middot;&nbsp; ");
  }

  // ---- footer year ----
  var yearEl = document.getElementById("year");
  if (yearEl) yearEl.textContent = new Date().getFullYear();

  // ---- mobile nav ----
  var toggle = document.getElementById("nav-toggle");
  var links = document.getElementById("nav-links");
  if (toggle && links) {
    toggle.addEventListener("click", function () {
      var open = links.classList.toggle("open");
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
    });
    links.addEventListener("click", function (e) {
      if (e.target.tagName === "A") { links.classList.remove("open"); toggle.setAttribute("aria-expanded", "false"); }
    });
  }

  // ---- reveal-on-scroll ----
  var revealTargets = document.querySelectorAll(".section");
  revealTargets.forEach(function (el) { el.setAttribute("data-reveal", ""); });
  if ("IntersectionObserver" in window) {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) { entry.target.classList.add("in"); io.unobserve(entry.target); }
      });
    }, { threshold: 0.08 });
    revealTargets.forEach(function (el) { io.observe(el); });
  } else {
    revealTargets.forEach(function (el) { el.classList.add("in"); });
  }

  // ---- active nav link on scroll ----
  var navAnchors = Array.prototype.slice.call(document.querySelectorAll('.nav-links a[href^="#"]'));
  var sections = navAnchors
    .map(function (a) { return document.querySelector(a.getAttribute("href")); })
    .filter(Boolean);
  if ("IntersectionObserver" in window && sections.length) {
    var spy = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        navAnchors.forEach(function (a) {
          a.classList.toggle("active", a.getAttribute("href") === "#" + entry.target.id);
        });
      });
    }, { rootMargin: "-45% 0px -50% 0px" });
    sections.forEach(function (s) { spy.observe(s); });
  }

  // ---- live demo status ping ----
  // Uses a no-cors probe so it works without any CORS config on the service: if the
  // request resolves the host is reachable (online); if it errors/times out we show
  // "waking up" (free-tier cold start) rather than a hard failure.
  var statusText = document.getElementById("demo-status-text");
  var statusDot = document.querySelector("#demo-status .status-dot");
  function setStatus(cls, text) {
    if (statusDot) statusDot.className = "status-dot " + cls;
    if (statusText) statusText.textContent = text;
  }
  function pingDemo() {
    if (!demoUrl || demoUrl.indexOf("yourdomain") !== -1) {
      setStatus("offline", "Live demo URL not configured yet");
      return;
    }
    var controller = new AbortController();
    var timer = setTimeout(function () { controller.abort(); }, 5000);
    fetch(demoUrl + "/health", { mode: "no-cors", signal: controller.signal })
      .then(function () { clearTimeout(timer); setStatus("online", "Live demo is online — click to try it"); })
      .catch(function () {
        clearTimeout(timer);
        setStatus("warming", isLocal
          ? "Local demo not running — start it with .\\run-local.ps1"
          : "Live demo is waking up (free-tier cold start)…");
      });
  }
  pingDemo();
})();
