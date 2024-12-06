import { fintelTemplateIncidentResponse } from './__incidentCase.template';
import { generateFintelTemplateExecutiveSummary } from './__executiveSummary.template';

export const usedFintelTemplatesByEntityType = {
  Report: [generateFintelTemplateExecutiveSummary('Report')],
  Grouping: [generateFintelTemplateExecutiveSummary('Grouping')],
  'Case-Incident': [fintelTemplateIncidentResponse, generateFintelTemplateExecutiveSummary('Case-Incident')],
  'Case-Rfi': [generateFintelTemplateExecutiveSummary('Case-Rfi')],
  'Case-Rft': [generateFintelTemplateExecutiveSummary('Case-Rft')],
};
