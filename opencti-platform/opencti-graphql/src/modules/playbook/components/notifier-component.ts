/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import * as R from 'ramda';
import type { JSONSchemaType } from 'ajv';
import { ENTITY_TYPE_PLAYBOOK, playbookBundleElementsToApply, type BasicStoreEntityPlaybook, type PlaybookBundleElementsToApply, type PlaybookComponent } from '../playbook-types';
import { convertMembersToUsersFromElements, extractBundleBaseElement, isBundleElementInScope } from '../playbook-utils';
import { getEntityFromCache } from '../../../database/cache';
import type { BasicStoreSettings } from '../../../types/settings';
import { executionContext, isUserCanAccessStixElement, isUserInPlatformOrganization, SYSTEM_USER } from '../../../utils/access';
import { ENTITY_TYPE_SETTINGS } from '../../../schema/internalObject';
import { convertToNotificationUser, EVENT_NOTIFICATION_VERSION, type DigestEvent } from '../../../manager/notificationManager';
import { generateCreateMessage, generateDeleteMessage } from '../../../database/data-changes';
import { convertStixToInternalTypes } from '../../../schema/schemaUtils';
import { storeNotificationEvent } from '../../../database/stream/stream-handler';
import { usableNotifiers } from '../../notifier/notifier-domain';
import { storeLoadById } from '../../../database/middleware-loader';
import { isEventInPirRelationship, StreamDataEventTypeEnum } from '../../../manager/playbookManager/playbookManagerUtils';
import { extractEntityRepresentativeName } from '../../../database/entity-representative';

export interface NotifierConfiguration {
  notifiers: string[];
  authorized_members: { value: string }[];
  applyToElements?: PlaybookBundleElementsToApply;
}

const PLAYBOOK_NOTIFIER_COMPONENT_SCHEMA: JSONSchemaType<NotifierConfiguration> = {
  type: 'object',
  properties: {
    notifiers: {
      type: 'array',
      uniqueItems: true,
      default: [],
      $ref: 'Notifiers',
      items: { type: 'string', oneOf: [] },
    },
    authorized_members: {
      type: 'array',
      default: [],
      items: {
        type: 'object',
        properties: {
          value: { type: 'string' },
        },
        required: ['value'],
      },
    },
    applyToElements: {
      type: 'string',
      nullable: true,
      default: playbookBundleElementsToApply.onlyMain.value,
      $ref: 'Resolve dynamic targets from',
      oneOf: [
        { const: playbookBundleElementsToApply.onlyMain.value, title: playbookBundleElementsToApply.onlyMain.title },
        { const: playbookBundleElementsToApply.allElements.value, title: playbookBundleElementsToApply.allElements.title },
        { const: playbookBundleElementsToApply.allExceptMain.value, title: playbookBundleElementsToApply.allExceptMain.title },
      ],
    },
  },
  required: ['notifiers', 'authorized_members'],
};
export const PLAYBOOK_NOTIFIER_COMPONENT: PlaybookComponent<NotifierConfiguration> = {
  id: 'PLAYBOOK_NOTIFIER_COMPONENT',
  name: 'Send to notifier',
  description: 'Automatically send notification',
  icon: 'notification',
  category: 'end_playbook',
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
    const { notifiers, authorized_members, applyToElements } = playbookNode.configuration;
    const baseData = extractBundleBaseElement(dataInstanceId, bundle);

    // Resolve which elements to extract dynamic targets from
    const scope = applyToElements || playbookBundleElementsToApply.onlyMain.value;
    const sourceElements = bundle.objects.filter((o) => isBundleElementInScope(o, scope as PlaybookBundleElementsToApply, dataInstanceId));

    const targetUsers = await convertMembersToUsersFromElements(
      authorized_members as { value: string }[],
      sourceElements.length > 0 ? sourceElements : [baseData],
      bundle,
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
            entity_type: convertStixToInternalTypes(stixObject.type),
          });
          if (event) {
            if (event.type === StreamDataEventTypeEnum.UPDATE) {
              message = `${event.message} in \`${extractEntityRepresentativeName(stixObject)}\` ${event.data.type}`;
            } else if (isEventInPirRelationship(event)) {
              message = event.message;
            } else if (event.type === StreamDataEventTypeEnum.DELETE) {
              message = generateDeleteMessage({
                ...stixObject,
                entity_type: convertStixToInternalTypes(stixObject.type),
              });
            }
          }
          return {
            notification_id: playbookNode.id,
            instance: stixObject,
            type: event?.type ?? StreamDataEventTypeEnum.CREATE,
            message: message === '-' ? playbookNode.name : message,
          };
        }),
      };
      notificationsCall.push(storeNotificationEvent(context, notificationEvent));
    }
    if (notificationsCall.length > 0) {
      await Promise.all(notificationsCall);
    }
    return { output_port: undefined, bundle };
  },
};
