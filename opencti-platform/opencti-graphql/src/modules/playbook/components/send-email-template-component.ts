import type { JSONSchemaType } from 'ajv';
import * as R from 'ramda';
import { Promise as BluePromise } from 'bluebird';
import { type PlaybookComponent } from '../playbook-types';
import { AUTOMATION_MANAGER_USER, executionContext } from '../../../utils/access';
import { fullEntitiesList } from '../../../database/middleware-loader';
import { ENTITY_TYPE_EMAIL_TEMPLATE } from '../../emailTemplate/emailTemplate-types';
import { convertMembersToUsers, extractBundleBaseElement } from '../playbook-utils';
import { sendEmailToUser } from '../../../domain/user';
import { ACCOUNT_STATUS_ACTIVE, logApp } from '../../../config/conf';

export interface SendEmailTemplateConfiguration {
  email_template: string,
  targets: object,
}
const PLAYBOOK_SEND_EMAIL_TEMPLATE_COMPONENT_SCHEMA: JSONSchemaType<SendEmailTemplateConfiguration> = {
  type: 'object',
  properties: {
    email_template: {
      type: 'string', $ref: 'Email template', oneOf: [],
    },
    targets: { type: 'object' },
  },
  required: ['email_template']
};
export const PLAYBOOK_SEND_EMAIL_TEMPLATE_COMPONENT: PlaybookComponent<SendEmailTemplateConfiguration> = {
  id: 'PLAYBOOK_SEND_EMAIL_TEMPLATE_COMPONENT',
  name: 'Send email from template',
  description: 'Send email from template to targets',
  icon: 'emailtemplate',
  is_entry_point: false,
  is_internal: true,
  ports: [],
  configuration_schema: PLAYBOOK_SEND_EMAIL_TEMPLATE_COMPONENT_SCHEMA,
  schema: async () => {
    const context = executionContext('playbook_components');
    const emailTemplates = await fullEntitiesList(context, AUTOMATION_MANAGER_USER, [ENTITY_TYPE_EMAIL_TEMPLATE]);
    const elements = emailTemplates.map((c) => ({ const: c.id, title: c.name }));
    const schemaElement = { properties: { email_template: { oneOf: elements } } };
    return R.mergeDeepRight<JSONSchemaType<SendEmailTemplateConfiguration>, any>(PLAYBOOK_SEND_EMAIL_TEMPLATE_COMPONENT_SCHEMA, schemaElement);
  },
  executor: async ({ dataInstanceId, playbookNode, bundle }) => {
    const context = executionContext('playbook_components');
    const { email_template, targets } = playbookNode.configuration;
    const baseData = extractBundleBaseElement(dataInstanceId, bundle);
    const targetUsers = await convertMembersToUsers(targets as { value: string }[], baseData, bundle);
    const sendEmailUserIds = [];
    for (let index = 0; index < targetUsers.length; index += 1) {
      const targetUser = targetUsers[index];
      if (!targetUser.user_service_account && targetUser.account_status === ACCOUNT_STATUS_ACTIVE) {
        sendEmailUserIds.push(targetUser.id);
      }
    }
    const emailSend = async (user_id: string) => {
      try {
        await sendEmailToUser(context, AUTOMATION_MANAGER_USER, { target_user_id: user_id, email_template_id: email_template });
      } catch (_err) {
        logApp.warn('Could not send email to user', { user_id });
      }
    };
    if (sendEmailUserIds.length > 0) {
      await BluePromise.map(
        sendEmailUserIds,
        (user_id) => emailSend(user_id),
        { concurrency: 3 }
      );
    }
    return { output_port: undefined, bundle };
  }
};
