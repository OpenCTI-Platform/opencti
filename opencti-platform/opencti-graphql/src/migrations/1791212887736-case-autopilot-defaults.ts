import { v4 as uuidv4 } from 'uuid';
import { logMigration } from '../config/conf';
import { FilterMode } from '../generated/graphql';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { fullEntitiesList } from '../database/middleware-loader';
import { createEntity } from '../database/middleware';
import { ENTITY_TYPE_FINTEL_TEMPLATE, type BasicStoreEntityFintelTemplate } from '../modules/fintelTemplate/fintelTemplate-types';
import {
  generateFintelTemplateInvestigationSummary,
  INVESTIGATION_SUMMARY_TEMPLATE_NAME,
  INVESTIGATION_SUMMARY_TEMPLATE_TYPES,
} from '../utils/fintelTemplate/__investigationSummary.template';
import { getDefaultInvestigationPolicy } from '../modules/investigationRun/investigationPolicy-domain';

const message = '[MIGRATION] Case Autopilot default investigation policy and fintel templates';

export const up = async (next: (error?: Error) => void) => {
  const startTime = Date.now();
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');
  // Idempotent: the default policy is only created when missing.
  await getDefaultInvestigationPolicy(context);
  const existing = await fullEntitiesList<BasicStoreEntityFintelTemplate>(context, SYSTEM_USER, [ENTITY_TYPE_FINTEL_TEMPLATE], {
    filters: { mode: FilterMode.And, filters: [{ key: ['name'], values: [INVESTIGATION_SUMMARY_TEMPLATE_NAME] }], filterGroups: [] },
  });
  const missingTypes = INVESTIGATION_SUMMARY_TEMPLATE_TYPES.filter((type) => !existing.some((template) => (template.settings_types ?? []).includes(type)));
  for (let index = 0; index < missingTypes.length; index += 1) {
    const input = generateFintelTemplateInvestigationSummary(missingTypes[index]);
    await createEntity(context, SYSTEM_USER, {
      ...input,
      fintel_template_widgets: (input.fintel_template_widgets ?? []).map((templateWidget) => ({
        ...templateWidget,
        widget: { ...templateWidget.widget, id: uuidv4() },
      })),
    }, ENTITY_TYPE_FINTEL_TEMPLATE);
    logMigration.info(`${message} > fintel template created for ${missingTypes[index]} (${index + 1}/${missingTypes.length})`);
  }
  logMigration.info(`${message} > done in ${Date.now() - startTime} ms`);
  next();
};

export const down = async (next: (error?: Error) => void) => {
  next();
};
