// Catalog page: live search, ransomware filter, and sorting by date.
(function () {
  var input = document.getElementById("q");
  var ransomwareOnly = document.getElementById("ransomware-only");
  var sortSelect = document.getElementById("sort");
  var count = document.getElementById("count");
  var tbody = document.querySelector("#catalog tbody");
  var rows = Array.prototype.slice.call(tbody.querySelectorAll("tr"));

  function applyFilters() {
    var query = input.value.trim().toLowerCase();
    var shown = 0;
    rows.forEach(function (row) {
      var matches =
        row.dataset.search.indexOf(query) !== -1 &&
        (!ransomwareOnly.checked || row.dataset.ransomware === "1");
      row.hidden = !matches;
      if (matches) shown++;
    });
    count.textContent = shown.toLocaleString() + " of " + rows.length.toLocaleString() + " vulnerabilities";
  }

  // Dates are YYYY-MM-DD, so comparing them as text sorts them correctly.
  // Rows with no date always go to the bottom, whichever direction is chosen.
  function applySort() {
    var parts = sortSelect.value.split("-");
    var field = parts[0] === "due" ? "due" : "added";
    var direction = parts[1] === "asc" ? 1 : -1;
    rows.sort(function (a, b) {
      var x = a.dataset[field];
      var y = b.dataset[field];
      if (!x || !y) return x ? -1 : y ? 1 : 0;
      return x < y ? -direction : x > y ? direction : 0;
    });
    rows.forEach(function (row) { tbody.appendChild(row); });
  }

  input.addEventListener("input", applyFilters);
  ransomwareOnly.addEventListener("change", applyFilters);
  sortSelect.addEventListener("change", applySort);
})();
