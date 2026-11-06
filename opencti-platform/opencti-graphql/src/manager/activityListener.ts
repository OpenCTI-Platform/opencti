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

import { LRUCache } from 'lru-cache';
import { type ActionHandler, type ActionListener, registerUserActionListener, type UserAction, type UserReadAction } from '../listener/UserActionListener';
import conf, { auditLogTypes, INGESTION_HEALTH_FEATURE_FLAG, isFeatureEnabled, logAudit } from '../config/conf';
import type { BasicStoreSettings } from '../types/settings';
import { storeActivityEvent } from '../database/stream/stream-handler';
import { getEntityFromCache } from '../database/cache';
import { ENTITY_TYPE_SETTINGS, isInternalObject } from '../schema/internalObject';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { ENTITY_TYPE_WORKSPACE } from '../modules/workspace/workspace-types';
import { isStixCoreRelationship } from '../schema/stixCoreRelationship';
import { isStixCoreObject } from '../schema/stixCoreObject';
import { REDACTED_INFORMATION } from '../database/utils';
import type { ActivityStreamEvent } from '../types/event';
import { EVENT_ACTIVITY_VERSION } from '../database/stream/stream-utils';
import { isEnterpriseEditionFromSettings } from '../enterprise-edition/ee';
import { buildConfigPresetExportMessage, buildConfigPresetImportMessage } from '../modules/configPreset/configPreset-utils';

const INTERNAL_READ_ENTITIES = [ENTITY_TYPE_WORKSPACE];
const LOGS_SENSITIVE_FIELDS = conf.get('app:app_logs:logs_redacted_inputs') ?? [];
const UNSUPPORTED_INTPUT_PROPS = ['_id', 'sort', 'i_attributes', 'i_relation']; // add 'objectOrganization' ?
// The ingestion health events only exist behind their feature flag: their values are not offered in the filters without it
const isIngestionHealthEnabled = isFeatureEnabled(INGESTION_HEALTH_FEATURE_FLAG);
export const EVENT_SCOPE_VALUES = [
  'create', 'update', 'delete', 'merge', 'read', 'search', 'enrich', 'download', 'import', 'export', 'send', 'login', 'logout', 'unauthorized', 'disseminate', 'forgot',
  ...(isIngestionHealthEnabled ? ['critical', 'degraded', 'recovered'] : []),
];
export const EVENT_TYPE_VALUES = ['authentication', 'read', 'mutation', 'file', 'command', ...(isIngestionHealthEnabled ? ['ingestion_health'] : [])];
export const EVENT_ACCESS_VALUES = ['extended', 'administration'];
export const EVENT_STATUS_VALUES = ['error', 'success'];

// Filter structures are stored as JSON strings, legacy activity indices can map them as text.
const SERIALIZED_FILTERS_PROPS = ['filters', 'dynamicFrom', 'dynamicTo'];

const isPlainObject = (value: any) => {
  if (value === null || typeof value !== 'object') {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
};

// Special case to clean inputs given as a list of { key, value } patches
const redactInputElements = (elements: any[]) => elements.map((element) => {
  if (element?.key && element.value && LOGS_SENSITIVE_FIELDS.includes(element.key)) {
    return { [element.key]: REDACTED_INFORMATION };
  }
  return element;
});

// Build a cleaned copy of the data, the original object can still be used by the caller (resolver args for example).
const sanitizeActivityData = (value: any, serializeFilters: boolean): any => {
  if (Array.isArray(value)) {
    return value.map((element) => sanitizeActivityData(element, serializeFilters));
  }
  if (!isPlainObject(value)) {
    return value;
  }
  const sanitized: Record<string, any> = {};
  Object.keys(value).forEach((key) => {
    if (LOGS_SENSITIVE_FIELDS.includes(key)) {
      sanitized[key] = REDACTED_INFORMATION;
      return;
    }
    const isFiltersProp = serializeFilters && SERIALIZED_FILTERS_PROPS.includes(key);
    const element = key === 'input' && Array.isArray(value[key]) ? redactInputElements(value[key]) : value[key];
    // Nested filter groups are part of the serialized structure, they must not be serialized separately.
    const cleanedElement = sanitizeActivityData(element, serializeFilters && !isFiltersProp);
    if (key === 'input' && isPlainObject(cleanedElement)) {
      // remove unsupported props in input like sort, _id that cause errors for old databases.
      UNSUPPORTED_INTPUT_PROPS.forEach((prop) => {
        delete cleanedElement[prop];
      });
    }
    if (isFiltersProp && typeof cleanedElement === 'object' && cleanedElement !== null) {
      try {
        sanitized[key] = JSON.stringify(cleanedElement);
      } catch {
        // Unserializable filters are not kept in the activity
      }
      return;
    }
    sanitized[key] = cleanedElement;
  });
  return sanitized;
};

export const cleanInputData = (obj: any) => sanitizeActivityData(obj, true);

const initActivityManager = () => {
  const activityReadCache = new LRUCache({ ttl: 60 * 60 * 1000, max: 5000 }); // Read lifetime is 1 hour
  const buildActivityStreamEvent = (action: UserAction, message: string): ActivityStreamEvent => {
    const data = cleanInputData(action.context_data ?? {});
    return {
      version: EVENT_ACTIVITY_VERSION,
      type: action.event_type,
      event_access: action.event_access,
      event_scope: action.event_scope,
      prevent_indexing: action.prevent_indexing ?? false,
      status: action.status ?? 'success',
      origin: action.user.origin,
      message,
      data,
    };
  };
  const activityLogger = async (action: UserAction, message: string): Promise<boolean> => {
    const level = action.status === 'error' ? 'error' : 'info';
    // If standard action, log and push to activity stream.
    const event = buildActivityStreamEvent(action, message);
    const meta = {
      version: event.version,
      type: event.type,
      event_scope: event.event_scope,
      event_access: event.event_access,
      data: event.data,
    };
    // In admin case put that to logs/console
    if (auditLogTypes.includes(action.event_access)) {
      logAudit._log(level, action.user, message, meta);
    }
    // In all case, store in history
    await storeActivityEvent(event);
    return true;
  };
  const readActivity = async (action: UserReadAction) => {
    const { id, entity_type, entity_name } = action.context_data;
    const identifier = `${id}-${action.user.id}`;
    // Auto read only for stix knowledge, for other internal elements, it must be
    if (!activityReadCache.has(identifier)) {
      const message = `reads \`${entity_name}\` (${entity_type})`;
      const published = await activityLogger(action, message);
      if (published) {
        activityReadCache.set(identifier, 'published');
      }
    }
  };
  const activityHandler: ActionListener = {
    id: 'ACTIVITY_MANAGER',
    next: async (action: UserAction) => {
      const context = executionContext('activity_listener');
      const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
      // 01. Check activity authorization
      if (!['query', 'internal'].includes(action.user.origin?.socket ?? '')) { // Subscription is not part of the listening
        return;
      }
      if (!isEnterpriseEditionFromSettings(settings)) { // If enterprise edition is not activated
        return;
      }
      const isUserListening = (settings.activity_listeners_users ?? []).includes(action.user.id);
      if (action.event_access === 'extended' && !isUserListening) { // If extended actions, is action is not for listened user
        return;
      }
      // 02. Handle activities
      if (action.event_type === 'authentication') {
        if (action.event_scope === 'login') {
          const { session_kill, context_data } = action;
          const { provider, username } = context_data;
          const isFailLogin = action.status === 'error';
          const message = isFailLogin ? `detects \`login failure\` for \`${username}\``
            : `login from provider \`${provider}\` ${(session_kill ?? 0) > 0 ? `(killing ${session_kill} sessions)` : ''}`;
          await activityLogger(action, message);
        }
        if (action.event_scope === 'logout') {
          await activityLogger(action, 'logout');
        }
        if (action.event_scope === 'forgot') {
          await activityLogger(action, action.message);
        }
      }
      if (action.event_type === 'read') {
        if (action.event_scope === 'unauthorized') {
          const message = `tries an \`unauthorized ${action.event_type}\``;
          await activityLogger(action, message);
        }
        if (action.event_scope === 'read') {
          const { entity_type } = action.context_data;
          const isKnowledgeListening = isStixCoreObject(entity_type) || isStixCoreRelationship(entity_type);
          const isInternalListening = isInternalObject(entity_type) && INTERNAL_READ_ENTITIES.includes(entity_type);
          if (isKnowledgeListening || isInternalListening) {
            await readActivity(action);
          }
        }
      }
      if (action.event_type === 'file') {
        const isFailAction = action.status === 'error';
        const prefixMessage = isFailAction ? 'failure ' : '';
        if (action.event_scope === 'read') {
          const { file_name, entity_name } = action.context_data;
          const message = `${prefixMessage} reads from \`${entity_name}\` the file \`${file_name}\``;
          await activityLogger(action, message);
        }
        if (action.event_scope === 'download') {
          const { file_name, entity_name } = action.context_data;
          const message = `${prefixMessage}  downloads from \`${entity_name}\` the file \`${file_name}\``;
          await activityLogger(action, message);
        }
        if (action.event_scope === 'create') {
          const { file_name, entity_name, entity_type, path, input } = action.context_data;
          // @ts-expect-error input type unknown
          let message = input?.is_upsert
            ? `adds a new version of \`${file_name}\` in \`files\` for \`${entity_name}\` (${entity_type})`
            : `adds \`${file_name}\` in \`files\` for \`${entity_name}\` (${entity_type})`;
          if (path.includes('import/pending')) {
            message = `creates Analyst Workbench \`${file_name}\` for \`${entity_name}\` (${entity_type})`;
          }
          await activityLogger(action, message);
        }
        if (action.event_scope === 'delete') { // General upload
          const { file_name, entity_name, entity_type, path } = action.context_data;
          let message = `removes \`${file_name}\` in \`files\` for \`${entity_name}\` (${entity_type})`;
          if (path.includes('import/pending')) {
            message = `removes Analyst Workbench \`${file_name}\` for \`${entity_name}\` (${entity_type})`;
          }
          await activityLogger(action, message);
        }
        if (action.event_scope === 'disseminate') {
          const { entity_name, entity_type, input } = action.context_data;
          // @ts-expect-error input type unknown
          const message = `disseminate \`${input.files.map((f) => f.name).join(',')}\` to \`${input.dissemination}\` from \`${entity_name}\` (${entity_type})`;
          await activityLogger(action, message);
        }
      }
      if (action.event_type === 'command') {
        if (action.event_scope === 'search') {
          const message = 'asks for `global search`';
          await activityLogger(action, message);
        }
        if (action.event_scope === 'export') {
          if ('format' in action.context_data) {
            const { format, entity_name } = action.context_data;
            const message = `asks for \`${format}\` export in \`${entity_name}\``;
            await activityLogger(action, message);
          } else {
            await activityLogger(action, buildConfigPresetExportMessage(action.context_data));
          }
        }
        if (action.event_scope === 'send') {
          const { entity_name, entity_type, input } = action.context_data;
          // @ts-expect-error input type unknown
          const message = `send an email about \`${entity_name}\` (${entity_type}) to \`${input.to}\``;
          await activityLogger(action, message);
        }
        if (action.event_scope === 'import') {
          if ('file_mime' in action.context_data) {
            const { file_name, file_mime, entity_name } = action.context_data;
            const message = `asks for \`${file_mime}\` import of \`${file_name}\` in \`${entity_name}\``;
            await activityLogger(action, message);
          } else {
            await activityLogger(action, buildConfigPresetImportMessage(action.context_data));
          }
        }
        if (action.event_scope === 'enrich') {
          const { entity_name, connector_name } = action.context_data;
          const message = `asks for \`${entity_name}\` enrichment with connector \`${connector_name}\``;
          await activityLogger(action, message);
        }
        if (action.event_scope === 'analyze') {
          const { entity_name, connector_name } = action.context_data;
          const message = `asks for \`${entity_name}\` analysis with connector \`${connector_name}\``;
          await activityLogger(action, message);
        }
      }
      if (action.event_type === 'mutation') {
        if (action.event_scope === 'unauthorized') {
          const message = `tries an \`unauthorized ${action.event_type}\``;
          await activityLogger(action, message);
        }
        if (action.event_scope === 'create') {
          await activityLogger(action, action.message);
        }
        if (action.event_scope === 'update') {
          await activityLogger(action, action.message);
        }
        if (action.event_scope === 'delete') {
          await activityLogger(action, action.message);
        }
      }
      if (action.event_type === 'ingestion_health') {
        await activityLogger(action, action.message);
      }
    },
  };
  let handler: ActionHandler;
  return {
    start: async () => {
      handler = registerUserActionListener(activityHandler);
    },
    status: () => {
      return {
        id: 'ACTIVITY_MANAGER',
        enable: true,
        running: true,
      };
    },
    shutdown: async () => {
      if (handler) {
        handler.unregister();
      }
      return true;
    },
  };
};
const activityListener = initActivityManager();
export default activityListener;
