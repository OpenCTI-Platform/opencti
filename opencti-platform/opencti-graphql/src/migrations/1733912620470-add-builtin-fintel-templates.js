import { logApp } from '../config/conf';
import { generateFintelTemplateExecutiveSummary } from '../utils/fintelTemplate/__executiveSummary.template';
import { fintelTemplateIncidentResponse } from '../utils/fintelTemplate/__incidentCase.template';
import { createEntity } from '../database/middleware';
import { ENTITY_TYPE_FINTEL_TEMPLATE } from '../modules/fintelTemplate/fintelTemplate-types';
import { executionContext, SYSTEM_USER } from '../utils/access';

const message = '[MIGRATION] Add built-in Fintel templates';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const context = executionContext('migration');
  const builtInTemplatesInputs = [
    generateFintelTemplateExecutiveSummary('Report'),
    generateFintelTemplateExecutiveSummary('Grouping'),
    fintelTemplateIncidentResponse,
    generateFintelTemplateExecutiveSummary('Case-Incident'),
    generateFintelTemplateExecutiveSummary('Case-Rfi'),
    generateFintelTemplateExecutiveSummary('Case-Rft')
  ];
  await Promise.all(builtInTemplatesInputs
    .map((input) => createEntity(context, SYSTEM_USER, input, ENTITY_TYPE_FINTEL_TEMPLATE)));
  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
