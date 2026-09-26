// Ask AI container report generation through XTM One.
//
// The legacy path (`aiContainerGenerateReport`) builds its prompt server-side
// from the container's knowledge graph. Through XTM One, the agent bound to
// the intent reads the container itself with its OpenCTI tools, so the prompt
// only has to name the container and carry the options the dialog collected.

export const CONTAINER_REPORT_INTENT = 'cti.container_report';

// Same ceiling as the legacy mutation.
export const MAX_REPORT_PARAGRAPHS = 20;

export type ContainerReportFormat = 'html' | 'markdown' | 'text' | 'json';

export interface ContainerReportOptions {
  containerId: string;
  containerName: string;
  containerType: string;
  paragraphs: number;
  tone: string;
  format: ContainerReportFormat;
  language: string;
}

const FORMAT_NAMES: Record<ContainerReportFormat, string> = {
  html: 'HTML',
  markdown: 'Markdown',
  text: 'plain text',
  json: 'JSON',
};

export const buildContainerReportPrompt = ({
  containerId,
  containerName,
  containerType,
  paragraphs,
  tone,
  format,
  language,
}: ContainerReportOptions): string => {
  const count = Math.min(Math.max(Math.trunc(paragraphs) || 1, 1), MAX_REPORT_PARAGRAPHS);
  return `Write a report from the OpenCTI container with ID: ${containerId} `
    + `(${containerType}: "${containerName}"). `
    + `The report must be ${count} paragraph${count === 1 ? '' : 's'} long, focused on ${tone} aspects, `
    + `in ${FORMAT_NAMES[format]} format. `
    + `Answer using ${language} language.`;
};
