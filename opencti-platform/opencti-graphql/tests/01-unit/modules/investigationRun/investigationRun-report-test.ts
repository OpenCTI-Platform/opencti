import { describe, expect, it } from 'vitest';
import { buildInvestigationNoteContent, buildInvestigationReportSections, escapeMarkdown } from '../../../../src/modules/investigationRun/investigationRun-report';
import { buildRun } from './investigationRun-fixtures';

describe('Case Autopilot report', () => {
  it('escapes markdown structure in values coming from the graph or the agent', () => {
    expect(escapeMarkdown('a | b')).toBe('a \\| b');
    expect(escapeMarkdown('<script>alert(1)</script>')).toBe('\\<script\\>alert\\(1\\)\\</script\\>');
    expect(escapeMarkdown('line\nbreak')).toBe('line break');
    expect(escapeMarkdown(null)).toBe('');
  });

  it('renders every section from the run data', () => {
    const sections = buildInvestigationReportSections(buildRun());
    expect(sections.executive_summary).toContain('The phishing wave is most likely APT28.');
    expect(sections.executive_summary).toContain('**Leading hypothesis:** APT28');
    expect(sections.timeline).toContain('| 2026-09-30 08:00 | Incident | Phishing wave | created |');
    expect(sections.hypotheses).toContain('| 1 | APT28 | Intrusion-Set | 61% | likely (61%) | 1 |');
    expect(sections.executive_summary).toContain('(Intrusion-Set), likely (61%).');
    expect(sections.hypotheses).toContain('Known C2 \\| reused');
    expect(sections.recommendations).toContain('| P1 | Block 185.12.4.2 at the proxy | task | proposed |');
    expect(sections.iocs).toContain('| IPv4-Addr | 185.12.4.2 | [1] |');
    expect(sections.iocs).toContain('| Indicator | \\[domain-name:value = \'evil.example\'\\] | - |');
    expect(sections.iocs).not.toContain('Phishing wave');
    expect(sections.iocs).not.toContain('Vendor write-up');
  });

  it('keeps the cited report of the engine and lists its sources', () => {
    const sections = buildInvestigationReportSections(buildRun({
      report_sources: [
        { n: 2, label: 'Vendor write-up', href: 'https://vendor.example/apt28' },
        { n: 3, label: 'Internal | note', href: null },
      ],
    }));
    expect(sections.report).toContain('APT28 operates the C2 [2].');
    expect(sections.report).toContain('**Sources**');
    expect(sections.report).toContain('2. Vendor write-up - <https://vendor.example/apt28>');
    expect(sections.report).toContain('3. Internal \\| note');
    expect(sections.executive_summary).toContain('Iterations: 0.');
  });

  it('says so when a section has no data', () => {
    const empty = buildRun({ hypotheses: [], timeline: [], recommendations: [], evidence: [], summary: null, report: null, report_sources: [] });
    const sections = buildInvestigationReportSections(empty);
    expect(sections.hypotheses).toBe('No attribution hypothesis was assessed.');
    expect(sections.timeline).toBe('No dated event was found.');
    expect(sections.recommendations).toBe('No recommendation.');
    expect(sections.iocs).toBe('No indicator or observable was collected.');
    expect(sections.report).toBe('No report was written.');
    expect(sections.executive_summary).toContain('Investigation of Incident');
  });

  it('says a hypothesis no evidence assessed has no confidence, never a defaulted one', () => {
    const run = buildRun();
    const unassessed = { ...run.hypotheses[0], confidence: null, confidence_label: null };
    const sections = buildInvestigationReportSections(buildRun({ hypotheses: [unassessed] }));
    expect(sections.hypotheses).toContain('| 1 | APT28 | Intrusion-Set | 61% | not assessed | 1 |');
    expect(sections.executive_summary).toContain('(Intrusion-Set), not assessed.');
  });

  it('assembles the summary note', () => {
    const content = buildInvestigationNoteContent(buildRun());
    ['## Executive summary', '## Timeline', '## Hypotheses (Analysis of Competing Hypotheses)', '## Recommendations', '## Indicators and observables']
      .forEach((heading) => expect(content).toContain(heading));
  });
});
