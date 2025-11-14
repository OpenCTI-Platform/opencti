import type { JSONSchemaType } from 'ajv';
import * as R from 'ramda';
import { type BasicStoreEntityPlaybook, ENTITY_TYPE_PLAYBOOK, type PlaybookComponent } from '../playbook-types';
import { executionContext, isUserCanAccessStixElement, isUserInPlatformOrganization, SYSTEM_USER } from '../../../utils/access';
import { usableNotifiers } from '../../notifier/notifier-domain';
import { storeLoadById } from '../../../database/middleware-loader';
import { getEntityFromCache } from '../../../database/cache';
import type { BasicStoreSettings } from '../../../types/settings';
import { ENTITY_TYPE_SETTINGS } from '../../../schema/internalObject';
import { convertToNotificationUser, type DigestEvent, EVENT_NOTIFICATION_VERSION } from '../../../manager/notificationManager';
import { generateCreateMessage, generateDeleteMessage } from '../../../database/generate-message';
import { convertStixToInternalTypes } from '../../../schema/schemaUtils';
import { storeNotificationEvent } from '../../../database/redis';
import { convertMembersToUsers, extractBundleBaseElement } from '../playbook-utils';
import { isEventInPirRelationship } from '../../../manager/playbookManager/playbookManagerUtils';
import { extractEntityRepresentativeName } from '../../../database/entity-representative';

export interface NotifierConfiguration {
  notifiers: string[]
  authorized_members: object
}

const PLAYBOOK_NOTIFIER_COMPONENT_SCHEMA: JSONSchemaType<NotifierConfiguration> = {
  type: 'object',
  properties: {
    notifiers: {
      type: 'array',
      uniqueItems: true,
      default: [],
      $ref: 'Notifiers',
      items: { type: 'string', oneOf: [] }
    },
    authorized_members: { type: 'object' },
  },
  required: ['notifiers', 'authorized_members'],
};

export const PLAYBOOK_NOTIFIER_COMPONENT: PlaybookComponent<NotifierConfiguration> = {
  id: 'PLAYBOOK_NOTIFIER_COMPONENT',
  name: 'Send to notifier',
  description: 'Send user notification',
  icon: 'notification',
  is_entry_point: false,
  is_internal: true,
  ports: [],
  configuration_schema: PLAYBOOK_NOTIFIER_COMPONENT_SCHEMA,
  schema: async () => {
    const context = executionContext('playbook_components');
    const notifiers = await usableNotifiers(context, SYSTEM_USER);
    const elements = notifiers.map((c) => ({ const: c.id, title: c.name }));
    const schemaElement = { properties: { notifiers: { items: { oneOf: elements } } } };
    return R.mergeDeepRight<JSONSchemaType<NotifierConfiguration>, any>(PLAYBOOK_NOTIFIER_COMPONENT_SCHEMA, schemaElement);
  },
  executor: async ({ dataInstanceId, playbookId, playbookNode, bundle, event }) => {
    const context = executionContext('playbook_components');
    const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
    const playbook = await storeLoadById<BasicStoreEntityPlaybook>(context, SYSTEM_USER, playbookId, ENTITY_TYPE_PLAYBOOK);
    const { notifiers, authorized_members } = playbookNode.configuration;
    const baseData = extractBundleBaseElement(dataInstanceId, bundle);
    const targetUsers = await convertMembersToUsers(
      authorized_members as { value: string }[],
      baseData,
      bundle
    );

    const notificationsCall = [];

    for (let index = 0; index < targetUsers.length; index += 1) {
      const targetUser = targetUsers[index];
      const user_inside_platform_organization = isUserInPlatformOrganization(targetUser, settings);
      const userContext = { ...context, user_inside_platform_organization };
      const stixElements = bundle.objects.filter((o) => isUserCanAccessStixElement(userContext, targetUser, o));

      const notificationEvent: DigestEvent = {
        version: EVENT_NOTIFICATION_VERSION,
        playbook_source: playbook.name,
        notification_id: playbookNode.id,
        target: convertToNotificationUser(targetUser, notifiers),
        type: 'digest',
        data: stixElements.map((stixObject) => {
          // Default message.
          let message = generateCreateMessage({
            ...stixObject,
            entity_type: convertStixToInternalTypes(stixObject.type)
          });
          if (event) {
            if (event.type === 'update') {
              message = `${event.message} in \`${extractEntityRepresentativeName(stixObject)}\` ${event.data.type}`;
            } else if (isEventInPirRelationship(event)) {
              message = event.message;
            } else if (event.type === 'delete') {
              message = generateDeleteMessage({
                ...stixObject,
                entity_type: convertStixToInternalTypes(stixObject.type)
              });
            }
          }
          return {
            notification_id: playbookNode.id,
            instance: stixObject,
            type: event?.type ?? 'create',
            message: message === '-' ? playbookNode.name : message,
          };
        })
      };
      notificationsCall.push(storeNotificationEvent(context, notificationEvent));
    }
    if (notificationsCall.length > 0) {
      await Promise.all(notificationsCall);
    }
    return { output_port: undefined, bundle };
  }
};
