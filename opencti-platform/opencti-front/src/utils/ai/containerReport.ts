// Ask AI container report generation through XTM One.
//
// The legacy path (`aiContainerGenerateReport`) builds its prompt server-side
// from the container's knowledge graph. Through XTM One, the agent bound to
// the intent reads the container itself with its OpenCTI tools, so the prompt
// only has to name the container and carry the options the dialog collected.
// The agent answers in HTML (its configured output format), which is why the
// dialog offers no other format on this path.

export const CONTAINER_REPORT_INTENT = 'cti.container_report';

export const CONTAINER_REPORT_FORMAT = 'html';

// Same ceiling as the legacy mutation.
export const MAX_REPORT_PARAGRAPHS = 20;

export interface ContainerReportOptions {
  containerId: string;
  containerName: string;
  containerType: string;
  paragraphs: number;
  tone: string;
  language: string;
}

export const buildContainerReportPrompt = ({
  containerId,
  containerName,
  containerType,
  paragraphs,
  tone,
  language,
}: ContainerReportOptions): string => {
  const count = Math.min(Math.max(Math.trunc(paragraphs) || 1, 1), MAX_REPORT_PARAGRAPHS);
  return `Write a report from the OpenCTI container with ID: ${containerId} `
    + `(${containerType}: "${containerName}"). `
    + `The report must be ${count} paragraph${count === 1 ? '' : 's'} long and focused on ${tone} aspects. `
    + `Answer using ${language} language.`;
};
