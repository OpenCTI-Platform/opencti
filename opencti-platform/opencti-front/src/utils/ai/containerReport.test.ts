import { describe, expect, it } from 'vitest';
import { buildContainerReportPrompt, CONTAINER_REPORT_FORMAT, CONTAINER_REPORT_INTENT, MAX_REPORT_PARAGRAPHS } from './containerReport';

const base = {
  containerId: 'report--0001',
  containerName: 'APT42 spear-phishing wave',
  containerType: 'Report',
  paragraphs: 10,
  tone: 'tactical',
  language: 'English',
};

describe('buildContainerReportPrompt', () => {
  it('names the container and carries every option of the dialog', () => {
    const prompt = buildContainerReportPrompt(base);

    expect(prompt).toContain('OpenCTI container with ID: report--0001');
    expect(prompt).toContain('Report: "APT42 spear-phishing wave"');
    expect(prompt).toContain('10 paragraphs long');
    expect(prompt).toContain('focused on tactical aspects');
    expect(prompt).toContain('Answer using English language.');
  });

  it('keeps the paragraph count within the legacy bounds', () => {
    expect(buildContainerReportPrompt({ ...base, paragraphs: 50 })).toContain(`${MAX_REPORT_PARAGRAPHS} paragraphs long`);
    expect(buildContainerReportPrompt({ ...base, paragraphs: 0 })).toContain('1 paragraph long');
    expect(buildContainerReportPrompt({ ...base, paragraphs: Number.NaN })).toContain('1 paragraph long');
  });

  it('targets the intent XTM One binds to its report-writing agent, which answers in HTML', () => {
    expect(CONTAINER_REPORT_INTENT).toBe('cti.container_report');
    expect(CONTAINER_REPORT_FORMAT).toBe('html');
  });
});
