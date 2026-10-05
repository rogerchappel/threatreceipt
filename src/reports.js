const xml = value => String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&apos;'}[c]));
export function formatReport(report, format) {
  if (format === 'json') return JSON.stringify(report, null, 2) + '\n';
  if (format === 'junit') return '<?xml version="1.0" encoding="UTF-8"?>\n' +
    `<testsuite name="${xml(report.feature)}" tests="${report.results.length}" failures="${report.summary.fail}" skipped="${report.summary.inconclusive}">\n` +
    `  <properties><property name="provenance" value="${xml(JSON.stringify(report.provenance))}"/></properties>\n` +
    report.results.map(r => `  <testcase name="${xml(r.threat)}" classname="${xml(r.check)}">` +
      (r.status === 'fail' ? `<failure message="${xml(r.evidence)}"/>` : r.status === 'inconclusive' ? `<skipped message="${xml(r.evidence)}"/>` : '') +
      `<system-out>${xml(r.invariant)}: ${xml(r.evidence)}</system-out></testcase>`).join('\n') + '\n</testsuite>\n';
  return `ThreatReceipt | ${report.feature} | ${report.mode}\nProvenance: ${JSON.stringify(report.provenance)}\n` +
    report.results.map(r => `${r.status.toUpperCase()} ${r.threat} [${r.check}]: ${r.evidence}`).join('\n') +
    `\n${report.summary.pass} passed; ${report.summary.fail} failed; ${report.summary.inconclusive} inconclusive.\n`;
}
