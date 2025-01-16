import { logApp } from '../config/conf';
import { createStatusTemplate } from '../domain/status';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { entitySettingEditField, findByType as findEntitySettingsByType } from '../modules/entitySetting/entitySetting-domain';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../modules/case/case-rfi/case-rfi-types';

const message = '[MIGRATION] migration title';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const context = executionContext('migration');
  const statusDeclined = await createStatusTemplate(context, SYSTEM_USER, { name: 'DECLINED', color: '#b83f13' });
  const statusApproved = await createStatusTemplate(context, SYSTEM_USER, { name: 'APPROVED', color: '#4caf50' });

  const initialConfig = {
    workflow: [statusApproved.id, statusDeclined.id],
    approved_workflow_id: statusApproved.id,
    declined_workflow_id: statusDeclined.id,
  };

  const rfiEntitySettings = await findEntitySettingsByType(context, SYSTEM_USER, ENTITY_TYPE_CONTAINER_CASE_RFI);
  if (rfiEntitySettings) {
    const editInput = [
      { key: 'request_access_workflow', value: [initialConfig] }
    ];
    // TODO use updateAttribute instead
    await entitySettingEditField(context, SYSTEM_USER, rfiEntitySettings.id, editInput);
  }
  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
