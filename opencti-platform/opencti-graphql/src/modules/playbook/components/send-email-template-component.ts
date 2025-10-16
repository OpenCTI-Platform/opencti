import type { JSONSchemaType } from 'ajv';
import * as R from 'ramda';
import { type PlaybookComponent } from '../playbook-types';
import { executionContext, SYSTEM_USER } from '../../../utils/access';
import { fullEntitiesList } from '../../../database/middleware-loader';
import { ENTITY_TYPE_EMAIL_TEMPLATE } from '../../emailTemplate/emailTemplate-types';

// const hackNotifierForTemplate = async (params: ExecutorParameters<NotifierConfiguration>) => {
//   const { playbookId, playbookNode, bundle } = params;
//   logApp.info('[PLAYBOOK EXEC] Notif component - EMAIL template');
//   const context = executionContext('playbook_components');
//   const { notifiers } = playbookNode.configuration;
//
//   for (let i = 0; i < bundle.objects.length; i += 1) {
//     const bundleObject: StixObject = bundle.objects[i];
//     if (bundleObject.extensions[STIX_EXT_OCTI].type === 'Organization') {
//       const internalId = bundleObject.extensions[STIX_EXT_OCTI].id;
//       const allMembers = await organizationMembersPaginated(context, SYSTEM_USER, internalId, {});
//       logApp.info('[PLAYBOOK EXEC] ==> Send email to all member of org', { orgId: bundleObject.id, template: notifiers[0] });
//       for (let j = 0; j < allMembers.edges.length; j += 1) {
//         const currentMember: any = allMembers.edges[j].node;
//         logApp.info('[PLAYBOOK EXEC] ==> Send email to user', { userId: currentMember.id, templateId: notifiers[0] });
//         await sendEmailToUser(context, AUTOMATION_MANAGER_USER, { target_user_id: currentMember.id, email_template_id: notifiers[0] });
//       }
//     } else {
//       logApp.info('[PLAYBOOK EXEC] NO EMAIL', { bundleObject });
//     }
//   }
//   return { output_port: undefined, bundle };
// };

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
    targets: { type: 'objet' },
  },
  required: ['email_template']
};
export const PLAYBOOK_SEND_EMAIL_TEMPLATE_COMPONENT: PlaybookComponent<SendEmailTemplateConfiguration> = {
  id: 'PLAYBOOK_SEND_EMAIL_TEMPLATE_COMPONENT',
  name: 'Send email from template',
  description: 'Send email from template to targets',
  icon: 'email-template',
  is_entry_point: false,
  is_internal: true,
  ports: [],
  configuration_schema: PLAYBOOK_SEND_EMAIL_TEMPLATE_COMPONENT_SCHEMA,
  schema: async () => {
    const context = executionContext('playbook_components');
    const emailTemplates = await fullEntitiesList(context, SYSTEM_USER, [ENTITY_TYPE_EMAIL_TEMPLATE]);
    const elements = emailTemplates.map((c) => ({ const: c.id, title: c.name }));
    const schemaElement = { properties: { email_template: { oneOf: elements } } };
    return R.mergeDeepRight<JSONSchemaType<SendEmailTemplateConfiguration>, any>(PLAYBOOK_SEND_EMAIL_TEMPLATE_COMPONENT_SCHEMA, schemaElement);
  },
  executor: async ({ bundle }) => {
    // const context = executionContext('playbook_components');
    // const playbook = await storeLoadById<BasicStoreEntityPlaybook>(context, SYSTEM_USER,ENTITY_TYPE_PLAYBOOK);
    // const { notifiers, authorized_members } = playbookNode.configuration;
    // const targetUsers = await convertAuthorizedMemberToUsers(authorized_members as { value: string }[]);
    // const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
    // const notificationsCall = [];
    // for (let index = 0; index < targetUsers.length; index += 1) {
    //   const targetUser = targetUsers[index];
    //   const user_inside_platform_organization = isUserInPlatformOrganization(targetUser, settings);
    //   const userContext = { ...context, user_inside_platform_organization };
    //   const stixElements = bundle.objects.filter((o) => isUserCanAccessStixElement(userContext, targetUser, o));
    //   const notificationEvent: DigestEvent = {
    //     version: EVENT_NOTIFICATION_VERSION,
    //     playbook_source: playbook.name,
    //     notification_id: playbookNode.id,
    //     target: convertToNotificationUser(targetUser, notifiers),
    //     type: 'digest',
    //     data: stixElements.map((stixObject) => ({
    //       notification_id: playbookNode.id,
    //       instance: stixObject,
    //       type: 'create', // TODO Improve that with type event follow up
    //       message: generateCreateMessage({
    //       ...stixObject, entity_type: convertStixToInternalTypes(stixObject.type) }) === '-' ? playbookNode.name : generateCreateMessage({ ...stixObject, entity_type: convertStixToInternalTypes(stixObject.type) }),
    //     }))
    //   };
    //   notificationsCall.push(storeNotificationEvent(context, notificationEvent));
    // }
    // if (notificationsCall.length > 0) {
    //   await Promise.all(notificationsCall);
    // }
    return { output_port: undefined, bundle };
  }
};
