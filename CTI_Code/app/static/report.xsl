<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="html" indent="yes" encoding="UTF-8"/>

  <xsl:template match="/ctiReport">
    <html lang="cs">
      <head>
        <meta charset="utf-8" />
        <title>CTI XML Report</title>
        <style>
          body { font-family: system-ui, sans-serif; margin: 0; background: #f5f7fb; color: #1f2a37; }
          .wrap { max-width: 1300px; margin: 0 auto; padding: 20px; }
          h1 { margin: 0 0 5px; }
          .sub { color: #5b6776; margin-bottom: 14px; }
          .tools { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 14px; }
          .tools input, .tools select { padding: 7px 9px; border: 1px solid #c9d1dc; border-radius: 8px; }
          section { background: white; border: 1px solid #dde3ec; border-radius: 12px; margin-bottom: 12px; overflow: hidden; }
          h2 { margin: 0; padding: 10px 12px; background: #edf2fb; border-bottom: 1px solid #dde3ec; font-size: 16px; }
          table { width: 100%; border-collapse: collapse; }
          th, td { padding: 8px 10px; border-bottom: 1px solid #eef2f7; text-align: left; font-size: 13px; }
          th { background: #fafcff; }
          tr:hover td { background: #f8fbff; }
        </style>
      </head>
      <body>
        <div class="wrap">
          <h1>CTI XML report</h1>
          <div class="sub">Automaticky generovaný přehled z Neo4j (tabulky + filtry pro browser).</div>

          <div class="tools">
            <input id="tableFilter" type="search" placeholder="Filtrovat text ve všech tabulkách..." />
            <select id="tableSelect">
              <option value="all">Všechny tabulky</option>
              <option value="summary">Souhrn uzlů dle typu</option>
              <option value="hosts">Top hosty dle počtu CVE</option>
              <option value="cves">Top CVE dle počtu hostů</option>
              <option value="threat">Top threat classes</option>
              <option value="malware">Top malware</option>
              <option value="locations">Top lokace</option>
            </select>
          </div>

          <section data-group="summary">
            <h2>Souhrn uzlů podle labelu</h2>
            <table>
              <thead><tr><th>Label</th><th>Počet</th></tr></thead>
              <tbody>
                <xsl:for-each select="summaryByLabel/row">
                  <tr><td><xsl:value-of select="label"/></td><td><xsl:value-of select="total"/></td></tr>
                </xsl:for-each>
              </tbody>
            </table>
          </section>

          <section data-group="hosts">
            <h2>Top hosty podle počtu CVE</h2>
            <table>
              <thead><tr><th>Host</th><th>CVE</th></tr></thead>
              <tbody>
                <xsl:for-each select="topHostsByCves/row">
                  <tr><td><xsl:value-of select="host"/></td><td><xsl:value-of select="cves"/></td></tr>
                </xsl:for-each>
              </tbody>
            </table>
          </section>

          <section data-group="cves">
            <h2>Top CVE podle zasažených hostů</h2>
            <table>
              <thead><tr><th>CVE</th><th>Počet hostů</th></tr></thead>
              <tbody>
                <xsl:for-each select="topCvesByHosts/row">
                  <tr><td><xsl:value-of select="cve"/></td><td><xsl:value-of select="hosts"/></td></tr>
                </xsl:for-each>
              </tbody>
            </table>
          </section>

          <section data-group="threat">
            <h2>Top threat classes podle NVT hitů</h2>
            <table>
              <thead><tr><th>Threat class</th><th>Počet hitů</th></tr></thead>
              <tbody>
                <xsl:for-each select="topThreatClasses/row">
                  <tr><td><xsl:value-of select="threat_class"/></td><td><xsl:value-of select="hits"/></td></tr>
                </xsl:for-each>
              </tbody>
            </table>
          </section>

          <section data-group="malware">
            <h2>Top malware podle usage v IntrusionSet</h2>
            <table>
              <thead><tr><th>Malware</th><th>Použití</th></tr></thead>
              <tbody>
                <xsl:for-each select="topMalwareByGroupUsage/row">
                  <tr><td><xsl:value-of select="malware"/></td><td><xsl:value-of select="used_by_groups"/></td></tr>
                </xsl:for-each>
              </tbody>
            </table>
          </section>

          <section data-group="locations">
            <h2>Top cílené lokace</h2>
            <table>
              <thead><tr><th>Lokace</th><th>Počet target vazeb</th></tr></thead>
              <tbody>
                <xsl:for-each select="topLocationsTargeted/row">
                  <tr><td><xsl:value-of select="location"/></td><td><xsl:value-of select="targets"/></td></tr>
                </xsl:for-each>
              </tbody>
            </table>
          </section>
        </div>

        <script>
          (function () {
            const filterInput = document.getElementById('tableFilter');
            const tableSelect = document.getElementById('tableSelect');
            const sections = Array.from(document.querySelectorAll('section[data-group]'));

            function applyFilters() {
              const q = (filterInput.value || '').toLowerCase().trim();
              const group = tableSelect.value;

              sections.forEach((section) => {
                const visibleByGroup = group === 'all' || section.dataset.group === group;
                section.style.display = visibleByGroup ? '' : 'none';
                if (!visibleByGroup) return;

                Array.from(section.querySelectorAll('tbody tr')).forEach((row) => {
                  const txt = row.textContent.toLowerCase();
                  row.style.display = !q || txt.includes(q) ? '' : 'none';
                });
              });
            }

            filterInput.addEventListener('input', applyFilters);
            tableSelect.addEventListener('change', applyFilters);
            applyFilters();
          })();
        </script>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
