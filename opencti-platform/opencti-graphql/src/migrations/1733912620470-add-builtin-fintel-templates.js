import { v4 as uuidv4 } from 'uuid';
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
  // add id to fintel template widgets
  const finalInputs = builtInTemplatesInputs.map((input) => ({
    ...input,
    content: input.content ?? '',
    fintel_template_widgets: (input.fintel_template_widgets ?? []).map((templateWidget) => ({
      ...templateWidget,
      id: uuidv4(),
      widget: { ...templateWidget.widget, id: uuidv4() },
    })),
  }));
  await Promise.all(finalInputs
    .map((input) => createEntity(context, SYSTEM_USER, input, ENTITY_TYPE_FINTEL_TEMPLATE)));
  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
