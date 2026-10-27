// xssql dashboard — vanilla JS SPA, no build step, no framework.
// Evidence/payload text is always inserted with textContent (never
// innerHTML), so a captured XSS payload cannot execute in this dashboard.
(function () {
  "use strict";

  const app = document.getElementById("app");

  function el(tag, attrs, children) {
    const node = document.createElement(tag);
    for (const k in attrs || {}) {
      if (k === "class") node.className = attrs[k];
      else if (k === "html") node.innerHTML = attrs[k];   // only for static, trusted markup
      else node.setAttribute(k, attrs[k]);
    }
    (children || []).forEach((c) => {
      if (c == null) return;
      node.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
    });
    return node;
  }

  function fmtPct(n) {
    return (n * 100).toFixed(0) + "%";
  }

  // ------------------------------------------------------------ scan list
  async function renderScanList() {
    app.innerHTML = "";
    app.appendChild(el("header", { class: "topbar" }, [
      el("div", { class: "logo" }, ["xssql"]),
      el("a", { class: "btn", href: "/scan/new" }, ["+ New scan"]),
    ]));

    const res = await fetch("/api/scans");
    const data = await res.json();
    const table = el("table", { class: "scans" });
    table.appendChild(el("thead", {}, [el("tr", {}, [
      el("th", {}, ["#"]), el("th", {}, ["Target"]), el("th", {}, ["Status"]),
      el("th", {}, ["Findings"]), el("th", {}, ["Endpoints"]),
      el("th", {}, ["Requests"]),
    ])]));
    const tbody = el("tbody");
    (data.scans || []).forEach((s) => {
      const row = el("tr", { class: "clickable" }, [
        el("td", {}, [String(s.id)]),
        el("td", {}, [s.target]),
        el("td", {}, [el("span", { class: "pill pill-" + s.status }, [s.status])]),
        el("td", {}, [String(s.findings_count)]),
        el("td", {}, [String(s.endpoints_found)]),
        el("td", {}, [String(s.requests_sent)]),
      ]);
      row.addEventListener("click", () => {
        history.pushState({}, "", "/scan/" + s.id);
        renderScanDetail(s.id);
      });
      tbody.appendChild(row);
    });
    table.appendChild(tbody);
    app.appendChild(table);
  }

  // ------------------------------------------------------------ scan detail
  async function renderScanDetail(scanId) {
    app.innerHTML = "";
    app.appendChild(el("header", { class: "topbar" }, [
      el("a", { class: "btn", href: "/" }, ["\u2190 scans"]),
      el("div", { class: "logo" }, ["scan #" + scanId]),
      el("a", { class: "btn", href: "/scan/" + scanId + "/report.html" }, ["HTML report"]),
      el("a", { class: "btn", href: "/scan/" + scanId + "/report.pdf" }, ["PDF report"]),
      el("a", { class: "btn", href: "/scan/" + scanId + "/findings.json" }, ["JSON"]),
    ]));

    const res = await fetch("/api/scans/" + scanId);
    if (!res.ok) {
      app.appendChild(el("p", {}, ["Scan not found."]));
      return;
    }
    const data = await res.json();
    app.appendChild(renderSummary(data));
    app.appendChild(renderFindings(data.findings || []));
  }

  function renderSummary(data) {
    const s = data.scan;
    const stats = el("div", { class: "stats" }, [
      statCard("Status", s.status),
      statCard("Duration", s.duration_s + "s"),
      statCard("Endpoints", s.endpoints_found),
      statCard("Requests", s.requests_sent),
      statCard("Findings", (data.findings || []).length),
    ]);
    return stats;
  }

  function statCard(label, value) {
    return el("div", { class: "stat" }, [
      el("div", { class: "stat-value" }, [String(value)]),
      el("div", { class: "stat-label" }, [label]),
    ]);
  }

  // Renders the findings table. Every piece of attacker-influenced text
  // (payload, evidence) is set via a text node, never parsed as HTML.
  function renderFindings(findings) {
    if (!findings.length) {
      return el("p", { class: "empty" }, ["No findings."]);
    }
    const table = el("table", { class: "findings" });
    table.appendChild(el("thead", {}, [el("tr", {}, [
      el("th", {}, ["Type"]), el("th", {}, ["Severity"]), el("th", {}, ["Confidence"]),
      el("th", {}, ["URL"]), el("th", {}, ["Param"]), el("th", {}, ["Payload"]),
      el("th", {}, ["Evidence"]), el("th", {}, ["CWE"]),
    ])]));
    const tbody = el("tbody");
    findings.forEach((f) => {
      tbody.appendChild(el("tr", { class: "sev-" + f.severity }, [
        el("td", {}, [f.vuln_type]),
        el("td", {}, [f.severity]),
        el("td", {}, [fmtPct(f.confidence)]),
        el("td", { class: "mono" }, [f.url]),
        el("td", {}, [f.parameter]),
        el("td", { class: "mono" }, [f.payload]),
        el("td", { class: "mono" }, [f.evidence]),
        el("td", {}, [f.cwe]),
      ]));
    });
    table.appendChild(tbody);
    return table;
  }

  // ------------------------------------------------------------ router
  function route() {
    const m = location.pathname.match(/^\/scan\/(\d+)$/);
    if (m) renderScanDetail(Number(m[1]));
    else renderScanList();
  }

  window.addEventListener("popstate", route);
  route();
})();
