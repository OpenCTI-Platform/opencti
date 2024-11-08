import { templateIncidentResponse } from './__incidentCase.template';
import { generateTemplateExecutiveSummary } from './__executiveSummary.template';

export const usedTemplatesByEntityType = {
  Report: [generateTemplateExecutiveSummary('Report')],
  Grouping: [generateTemplateExecutiveSummary('Grouping')],
  'Case-Incident': [templateIncidentResponse, generateTemplateExecutiveSummary('Case-Incident')],
  'Case-Rfi': [generateTemplateExecutiveSummary('Case-Rfi')],
  'Case-Rft': [generateTemplateExecutiveSummary('Case-Rft')],
};
