// Reloads the run page when the review makes progress (an agent starts or finishes, or the status changes).
(function () {
  var el = document.getElementById("live");
  if (!el) return;
  var url = el.getAttribute("data-url"), sig = el.getAttribute("data-sig");
  function tick() {
    fetch(url, { credentials: "same-origin", headers: { "Accept": "application/json" } })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (d.sig !== sig) { window.location.reload(); return; }
        setTimeout(tick, 1500);
      })
      .catch(function () { setTimeout(tick, 4000); });
  }
  setTimeout(tick, 1500);
})();
