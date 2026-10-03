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
    expect(sections.hypotheses).toContain('| 1 | APT28 | Intrusion-Set | 61% | likely | 1 |');
    expect(sections.hypotheses).toContain('Known C2 \\| reused');
    expect(sections.recommendations).toContain('| P1 | Block 185.12.4.2 at the proxy | task | proposed |');
    expect(sections.iocs).toContain('| IPv4-Addr | 185.12.4.2 | enrichment |');
    expect(sections.iocs).toContain('| Indicator |');
    expect(sections.iocs).not.toContain('Phishing wave');
  });

  it('says so when a section has no data', () => {
    const sections = buildInvestigationReportSections(buildRun({ hypotheses: [], timeline: [], recommendations: [], evidence: [], summary: null }));
    expect(sections.hypotheses).toBe('No attribution hypothesis was assessed.');
    expect(sections.timeline).toBe('No dated event was found.');
    expect(sections.recommendations).toBe('No recommendation.');
    expect(sections.iocs).toBe('No indicator or observable was collected.');
    expect(sections.executive_summary).toContain('Investigation of Incident');
  });

  it('assembles the summary note', () => {
    const content = buildInvestigationNoteContent(buildRun());
    ['## Executive summary', '## Timeline', '## Hypotheses (Analysis of Competing Hypotheses)', '## Recommendations', '## Indicators and observables']
      .forEach((heading) => expect(content).toContain(heading));
  });
});
