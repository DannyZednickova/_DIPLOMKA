<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="html" indent="yes" encoding="UTF-8"/>

  <xsl:template match="/ctiReport">
    <html lang="cs">
      <head>
        <meta charset="utf-8" />
        <title>CTI manažersko-technický report</title>
        <style>
          body { font-family: Inter, system-ui, sans-serif; margin: 0; background: #f3f6fb; color: #1f2937; }
          .wrap { max-width: 1500px; margin: 0 auto; padding: 18px; }
          h1 { margin: 0; }
          .sub { color: #5e6b7e; margin: 6px 0 14px; }
          .toolbar { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 12px; }
          .toolbar input, .toolbar select { padding: 8px 10px; border: 1px solid #c9d4e4; border-radius: 9px; }
          .toolbar label { display: inline-flex; align-items: center; gap: 6px; font-size: 13px; color: #435066; }
          section { background: #fff; border: 1px solid #dce5f0; border-radius: 12px; margin-bottom: 14px; overflow: hidden; }
          h2 { margin: 0; padding: 10px 12px; background: #ecf2fb; border-bottom: 1px solid #dce5f0; font-size: 16px; }
          table { width: 100%; border-collapse: collapse; font-size: 13px; }
          th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #edf2f8; vertical-align: top; }
          th { position: sticky; top: 0; background: #f8fbff; z-index: 2; }
          .table-wrap { max-height: 420px; overflow: auto; }
          tr:hover td { background: #f7fbff; }
          .muted { color: #748197; }
        </style>
      </head>

      <body>
        <div class="wrap">
          <h1>CTI manažersko-technický report</h1>
          <div class="sub">Zdrojem dat je Neo4j. Report kombinuje přehled zranitelností hostů s CTI kontextem.</div>

          <div class="toolbar">
            <input id="globalFilter" type="search" placeholder="Filtrovat text ve viditelných tabulkách..." />
            <select id="tableSelect">
              <option value="all">Všechny tabulky</option>
              <option value="host-summary">Souhrn podle hostů</option>
              <option value="host-threat">Detail host → threat class</option>
              <option value="top-cve">Top CVE podle dopadu</option>
              <option value="top-threat">Top threat classes</option>
              <option value="cti-corr">CTI korelace</option>
            </select>
            <input id="hostFilter" type="search" placeholder="Host IP..." />
            <input id="threatFilter" type="search" placeholder="Threat class..." />
            <input id="cveFilter" type="search" placeholder="CVE..." />
            <select id="severityFilter">
              <option value="all">Severity: vše</option>
              <option value="high">Severity: high+ (>= 7.0)</option>
              <option value="critical">Severity: critical (>= 9.0)</option>
            </select>
            <select id="relationFilter">
              <option value="all">Relace: všechny</option>
              <option value="USES">USES</option>
              <option value="TARGETS">TARGETS</option>
              <option value="EXPLOITS">EXPLOITS</option>
              <option value="RELATED_TO">RELATED_TO</option>
            </select>
            <label><input id="onlyNonZero" type="checkbox" /> jen řádky s nenulovou hodnotou</label>
          </div>

          <section data-group="host-summary">
            <h2>Souhrn podle hostů</h2>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>IP hosta</th><th>Unikátní NVT</th><th>Unikátní CVE</th><th>Threat classes</th>
                    <th>Max severity</th><th>Průměrná severity</th><th>High/Critical nálezy</th>
                  </tr>
                </thead>
                <tbody>
                  <xsl:for-each select="hostSummary/row">
                    <tr>
                      <td><xsl:value-of select="host_ip"/></td>
                      <td><xsl:value-of select="unique_nvt_count"/></td>
                      <td><xsl:value-of select="unique_cve_count"/></td>
                      <td><xsl:value-of select="threat_class_count"/></td>
                      <td><xsl:value-of select="max_severity"/></td>
                      <td><xsl:value-of select="avg_severity"/></td>
                      <td><xsl:value-of select="high_critical_findings"/></td>
                    </tr>
                  </xsl:for-each>
                </tbody>
              </table>
            </div>
          </section>

          <section data-group="host-threat">
            <h2>Detail host → threat class</h2>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Host IP</th><th>Threat class</th><th>NVT v třídě</th><th>CVE přes NVT</th><th>Nejvyšší severity</th><th>Příklady NVT</th>
                  </tr>
                </thead>
                <tbody>
                  <xsl:for-each select="hostThreatClassDetail/row">
                    <tr>
                      <td><xsl:value-of select="host_ip"/></td>
                      <td><xsl:value-of select="threat_class"/></td>
                      <td><xsl:value-of select="nvt_count"/></td>
                      <td><xsl:value-of select="cve_count"/></td>
                      <td><xsl:value-of select="max_severity"/></td>
                      <td><xsl:value-of select="nvt_examples"/></td>
                    </tr>
                  </xsl:for-each>
                </tbody>
              </table>
            </div>
          </section>

          <section data-group="top-cve">
            <h2>Top CVE podle dopadu</h2>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>CVE</th><th>Zasažené hosty</th><th>NVT referující na CVE</th><th>OpenCTI kontext</th>
                  </tr>
                </thead>
                <tbody>
                  <xsl:for-each select="topCveImpact/row">
                    <tr>
                      <td><xsl:value-of select="cve"/></td>
                      <td><xsl:value-of select="affected_hosts"/></td>
                      <td><xsl:value-of select="nvt_ref_count"/></td>
                      <td><xsl:value-of select="opencti_context"/></td>
                    </tr>
                  </xsl:for-each>
                </tbody>
              </table>
            </div>
          </section>

          <section data-group="top-threat">
            <h2>Top threat classes</h2>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Threat class</th><th>Zasažené hosty</th><th>Počet NVT</th><th>Počet CVE</th><th>Top hosty</th>
                  </tr>
                </thead>
                <tbody>
                  <xsl:for-each select="topThreatClasses/row">
                    <tr>
                      <td><xsl:value-of select="threat_class"/></td>
                      <td><xsl:value-of select="affected_hosts"/></td>
                      <td><xsl:value-of select="nvt_count"/></td>
                      <td><xsl:value-of select="cve_count"/></td>
                      <td><xsl:value-of select="top_hosts"/></td>
                    </tr>
                  </xsl:for-each>
                </tbody>
              </table>
            </div>
          </section>

          <section data-group="cti-corr">
            <h2>CTI korelace</h2>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>CVE</th><th>Navázaný Malware / IntrusionSet / AttackPattern</th><th>Typ vztahu</th><th>Lokální hosty</th>
                  </tr>
                </thead>
                <tbody>
                  <xsl:for-each select="ctiCorrelation/row">
                    <tr>
                      <td><xsl:value-of select="cve"/></td>
                      <td><xsl:value-of select="linked_entity"/></td>
                      <td><xsl:value-of select="relation_type"/></td>
                      <td><xsl:value-of select="local_hosts"/></td>
                    </tr>
                  </xsl:for-each>
                </tbody>
              </table>
            </div>
          </section>

          <div class="muted">Tip: Vyber konkrétní tabulku v dropdownu a potom použij textový filtr.</div>
        </div>

        <script>
          (function () {
            const q = document.getElementById('globalFilter');
            const sel = document.getElementById('tableSelect');
            const hostFilter = document.getElementById('hostFilter');
            const threatFilter = document.getElementById('threatFilter');
            const cveFilter = document.getElementById('cveFilter');
            const severityFilter = document.getElementById('severityFilter');
            const relationFilter = document.getElementById('relationFilter');
            const onlyNonZero = document.getElementById('onlyNonZero');
            const sections = Array.from(document.querySelectorAll('section[data-group]'));
            const emptyState = document.createElement('div');
            emptyState.className = 'muted';
            emptyState.style.marginTop = '10px';
            emptyState.textContent = 'V reportu aktuálně nejsou data pro vybrané tabulky.';
            let hasAppendedEmpty = false;

            function visibleRowsInSection(section) {
              return Array.from(section.querySelectorAll('tbody tr')).filter((row) => row.style.display !== 'none').length;
            }

            function removeEmptySectionsFromDropdown() {
              sections.forEach((section) => {
                const rows = section.querySelectorAll('tbody tr').length;
                const option = sel.querySelector(`option[value=\"${section.dataset.group}\"]`);
                if (!option) return;
                if (rows === 0) {
                  option.remove();
                  section.remove();
                }
              });
            }

            function apply() {
              const needle = (q.value || '').toLowerCase().trim();
              const group = sel.value;
              const hostNeedle = (hostFilter.value || '').toLowerCase().trim();
              const threatNeedle = (threatFilter.value || '').toLowerCase().trim();
              const cveNeedle = (cveFilter.value || '').toLowerCase().trim();
              const sevMode = severityFilter.value;
              const relationMode = relationFilter.value;
              const onlyNonZeroRows = !!onlyNonZero.checked;
              let anyVisibleRows = false;

              sections.forEach((section) => {
                if (!section.isConnected) return;
                const visible = group === 'all' || section.dataset.group === group;
                section.style.display = visible ? '' : 'none';
                if (!visible) return;

                section.querySelectorAll('tbody tr').forEach((row) => {
                  const txt = row.textContent.toLowerCase();
                  const cells = Array.from(row.children).map((c) => c.textContent.trim());

                  const matchesGlobal = !needle || txt.includes(needle);

                  let matchesHost = true;
                  if (hostNeedle) {
                    if (section.dataset.group === 'host-summary' || section.dataset.group === 'host-threat') {
                      matchesHost = (cells[0] || '').toLowerCase().includes(hostNeedle);
                    } else if (section.dataset.group === 'top-threat') {
                      matchesHost = (cells[4] || '').toLowerCase().includes(hostNeedle);
                    }
                  }

                  let matchesThreat = true;
                  if (threatNeedle) {
                    if (section.dataset.group === 'host-threat' || section.dataset.group === 'top-threat') {
                      matchesThreat = (cells[1] || cells[0] || '').toLowerCase().includes(threatNeedle);
                    }
                  }

                  let matchesCve = true;
                  if (cveNeedle) {
                    if (section.dataset.group === 'top-cve' || section.dataset.group === 'cti-corr') {
                      matchesCve = (cells[0] || '').toLowerCase().includes(cveNeedle);
                    } else if (section.dataset.group === 'host-summary') {
                      matchesCve = (cells[2] || '').toLowerCase().includes(cveNeedle);
                    }
                  }

                  let matchesSeverity = true;
                  if (sevMode !== 'all') {
                    const sevIdx =
                      section.dataset.group === 'host-summary' ? 4 :
                      section.dataset.group === 'host-threat' ? 4 : -1;
                    if (sevIdx >= 0) {
                      const sev = parseFloat((cells[sevIdx] || '0').replace(',', '.')) || 0;
                      if (sevMode === 'high') matchesSeverity = sev >= 7.0;
                      if (sevMode === 'critical') matchesSeverity = sev >= 9.0;
                    }
                  }

                  let matchesRelation = true;
                  if (relationMode !== 'all') {
                    if (section.dataset.group === 'cti-corr') {
                      matchesRelation = (cells[2] || '').toUpperCase() === relationMode;
                    }
                  }

                  let matchesNonZero = true;
                  if (onlyNonZeroRows) {
                    const nums = cells
                      .map((v) => parseFloat(String(v).replace(',', '.')))
                      .filter((v) => Number.isFinite(v));
                    matchesNonZero = nums.length === 0 ? true : nums.some((v) => v > 0);
                  }

                  row.style.display = (matchesGlobal &amp;&amp; matchesHost &amp;&amp; matchesThreat &amp;&amp; matchesCve &amp;&amp; matchesSeverity &amp;&amp; matchesRelation &amp;&amp; matchesNonZero) ? '' : 'none';
                });
                if (visibleRowsInSection(section) > 0) anyVisibleRows = true;
              });

              if (!anyVisibleRows &amp;&amp; !hasAppendedEmpty) {
                document.querySelector('.wrap').appendChild(emptyState);
                hasAppendedEmpty = true;
              } else if (anyVisibleRows &amp;&amp; hasAppendedEmpty) {
                emptyState.remove();
                hasAppendedEmpty = false;
              }
            }

            removeEmptySectionsFromDropdown();
            if (!sel.querySelector(`option[value=\"${sel.value}\"]`)) sel.value = 'all';
            q.addEventListener('input', apply);
            sel.addEventListener('change', apply);
            hostFilter.addEventListener('input', apply);
            threatFilter.addEventListener('input', apply);
            cveFilter.addEventListener('input', apply);
            severityFilter.addEventListener('change', apply);
            relationFilter.addEventListener('change', apply);
            onlyNonZero.addEventListener('change', apply);
            apply();
          })();
        </script>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
