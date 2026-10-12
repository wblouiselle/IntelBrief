// Live search for the catalog page: hides table rows that don't match the filters.
(function () {
  var input = document.getElementById("q");
  var ransomwareOnly = document.getElementById("ransomware-only");
  var count = document.getElementById("count");
  var rows = document.querySelectorAll("#catalog tbody tr");

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

  input.addEventListener("input", applyFilters);
  ransomwareOnly.addEventListener("change", applyFilters);
})();
