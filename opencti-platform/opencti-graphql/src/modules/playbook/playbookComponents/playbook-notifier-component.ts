import type { JSONSchemaType } from 'ajv';
import * as R from 'ramda';
import { type BasicStoreEntityPlaybook, ENTITY_TYPE_PLAYBOOK, type PlaybookComponent } from '../playbook-types';
import { executionContext, isInternalUser, isUserCanAccessStixElement, isUserInPlatformOrganization, SYSTEM_USER } from '../../../utils/access';
import { usableNotifiers } from '../../notifier/notifier-domain';
import { storeLoadById } from '../../../database/middleware-loader';
import { getEntitiesListFromCache, getEntityFromCache } from '../../../database/cache';
import type { BasicStoreSettings } from '../../../types/settings';
import { ENTITY_TYPE_SETTINGS, ENTITY_TYPE_USER } from '../../../schema/internalObject';
import { convertToNotificationUser, type DigestEvent, EVENT_NOTIFICATION_VERSION } from '../../../manager/notificationManager';
import { generateCreateMessage } from '../../../database/generate-message';
import { convertStixToInternalTypes } from '../../../schema/schemaUtils';
import { storeNotificationEvent } from '../../../database/redis';
import { isEmptyField } from '../../../database/utils';
import type { AuthUser } from '../../../types/user';

/**
 * Returns the list of all users authorized based on given authorized members array.
 *
 * @param authorized_members Array of authorized members.
 * @returns List of users.
 */
const convertAuthorizedMembersToUsers = async (authorized_members: { value: string }[]): Promise<AuthUser[]> => {
  if (isEmptyField(authorized_members)) return [];
  const authorizedMembersIds = authorized_members.map((member) => member.value) ?? [];
  const platformUsers = await getEntitiesListFromCache<AuthUser>(
    executionContext('playbook_components'),
    SYSTEM_USER,
    ENTITY_TYPE_USER
  );

  const authorizedUsers = platformUsers.filter((user) => {
    if (isInternalUser(user)) return false;
    const isDirectlyAuthorized = authorizedMembersIds.includes(user.id);
    const isAuthorizedByGroup = user.groups.some((g) => authorizedMembersIds.includes(g.internal_id));
    const isAuthorizedByOrganization = user.organizations.some((o) => authorizedMembersIds.includes(o.internal_id));
    return isDirectlyAuthorized || isAuthorizedByGroup || isAuthorizedByOrganization;
  });
  return R.uniqBy(R.prop('id'), authorizedUsers);
};

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
  executor: async ({ playbookId, playbookNode, bundle }) => {
    const context = executionContext('playbook_components');
    const playbook = await storeLoadById<BasicStoreEntityPlaybook>(context, SYSTEM_USER, playbookId, ENTITY_TYPE_PLAYBOOK);
    const { notifiers, authorized_members } = playbookNode.configuration;
    const targetUsers = await convertAuthorizedMembersToUsers(authorized_members as { value: string }[]);
    const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);

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
          const createMessage = generateCreateMessage({
            ...stixObject,
            entity_type: convertStixToInternalTypes(stixObject.type)
          });
          return {
            notification_id: playbookNode.id,
            instance: stixObject,
            type: 'create', // TODO Improve that with type event follow up
            message: createMessage === '-' ? playbookNode.name : createMessage,
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
