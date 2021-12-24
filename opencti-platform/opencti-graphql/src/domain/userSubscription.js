/* eslint-disable camelcase */
import * as R from 'ramda';
import { elIndex } from '../database/elasticSearch';
import { INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { generateInternalId, generateStandardId } from '../schema/identifier';
import { ENTITY_TYPE_USER_SUBSCRIPTION } from '../schema/internalObject';
import {
  deleteElementById,
  fullLoadById,
  internalLoadById,
  listEntities,
  loadById,
  updateAttribute,
} from '../database/middleware';
import { delEditContext, notify, setEditContext } from '../database/redis';
import { baseUrl, BUS_TOPICS } from '../config/conf';
import { FROM_START_STR, hoursAgo, minutesAgo, prepareDate } from '../utils/format';
import { SYSTEM_USER } from '../utils/access';
import { findAll as findAllStixCoreRelationships } from './stixCoreRelationship';
import { findAll as findAllStixMetaRelationships } from './stixMetaRelationship';
import { findAll as findAllContainers } from './container';
import {
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_COURSE_OF_ACTION,
  ENTITY_TYPE_INCIDENT,
  ENTITY_TYPE_INDICATOR,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_THREAT_ACTOR,
  ENTITY_TYPE_TOOL,
  ENTITY_TYPE_VULNERABILITY,
} from '../schema/stixDomainObject';
import { convertFiltersToQueryOptions } from './taxii';
import { resolveUserById } from './user';
import {
  ABSTRACT_STIX_CORE_RELATIONSHIP,
  ABSTRACT_STIX_CYBER_OBSERVABLE,
  BASE_TYPE_ENTITY,
  ENTITY_TYPE_IDENTITY,
  ENTITY_TYPE_LOCATION,
} from '../schema/general';
import {
  containerToHtml,
  footer,
  header,
  relationshipToHtml,
  sectionFooter,
  sectionHeader,
  technicalElementToHtml,
} from '../utils/mailData';
import { getParentTypes } from '../schema/schemaUtils';

// Stream graphQL handlers
export const createUserSubscription = async (user, input) => {
  const userSubscriptionId = generateInternalId();
  const data = {
    id: userSubscriptionId,
    internal_id: userSubscriptionId,
    standard_id: generateStandardId(ENTITY_TYPE_USER_SUBSCRIPTION, input),
    entity_type: ENTITY_TYPE_USER_SUBSCRIPTION,
    parent_types: getParentTypes(ENTITY_TYPE_USER_SUBSCRIPTION),
    base_type: BASE_TYPE_ENTITY,
    user_id: user.id,
    last_run: FROM_START_STR,
    ...input,
  };
  await elIndex(INDEX_INTERNAL_OBJECTS, data);
  return data;
};
export const findById = async (user, subscriptionId) => {
  return loadById(user, subscriptionId, ENTITY_TYPE_USER_SUBSCRIPTION);
};
export const findAll = (user, args) => {
  return listEntities(user, [ENTITY_TYPE_USER_SUBSCRIPTION], args);
};
export const getUserSubscriptions = async (user, userId) => {
  const args = { filters: [{ key: 'user_id', values: [userId] }] };
  return findAll(user, args);
};
export const userSubscriptionEditField = async (user, subscriptionId, input) => {
  const { element } = await updateAttribute(user, subscriptionId, ENTITY_TYPE_USER_SUBSCRIPTION, input);
  return notify(BUS_TOPICS[ENTITY_TYPE_USER_SUBSCRIPTION].EDIT_TOPIC, element, user);
};
export const userSubscriptionDelete = async (user, subscriptionId) => {
  await deleteElementById(user, subscriptionId, ENTITY_TYPE_USER_SUBSCRIPTION);
  return subscriptionId;
};
export const userSubscriptionCleanContext = async (user, subscriptionId) => {
  await delEditContext(user, subscriptionId);
  return loadById(user, subscriptionId, ENTITY_TYPE_USER_SUBSCRIPTION).then((subscriptionToReturn) =>
    notify(BUS_TOPICS[ENTITY_TYPE_USER_SUBSCRIPTION].EDIT_TOPIC, subscriptionToReturn, user)
  );
};
export const userSubscriptionEditContext = async (user, subscriptionId, input) => {
  await setEditContext(user, subscriptionId, input);
  return loadById(user, subscriptionId, ENTITY_TYPE_USER_SUBSCRIPTION).then((collectionToReturn) =>
    notify(BUS_TOPICS[ENTITY_TYPE_USER_SUBSCRIPTION].EDIT_TOPIC, collectionToReturn, user)
  );
};

export const generateDigestForSubscription = async (subscription) => {
  // Resolve the user
  const rawUser = await resolveUserById(subscription.user_id);
  if (!rawUser) {
    await userSubscriptionDelete(SYSTEM_USER, subscription.id);
    return null;
  }
  const user = { ...rawUser, origin: { user_id: rawUser.id, referer: 'background_task' } };
  // Get the data
  const filters = subscription.filters ? JSON.parse(subscription.filters) : undefined;
  const queryOptions = convertFiltersToQueryOptions(filters);
  let date = subscription.last_run;
  if (date === FROM_START_STR) {
    const [number, unit] = subscription.cron.split('-');
    if (unit === 'minutes') {
      date = minutesAgo(number);
    } else if (unit === 'hours') {
      date = hoursAgo(number);
    }
  }
  const data = { knowledgeData: [], containersData: [], technicalData: [] };
  if (subscription.options.includes('KNOWLEDGE')) {
    const knowledgeParamsFrom = {
      first: 1000,
      orderBy: 'created_at',
      orderMode: 'desc',
      filters: [...queryOptions.filters, { key: 'created_at', values: [prepareDate(date)], operator: 'gt' }],
      connectionFormat: false,
    };
    const knowledgeParamsTo = {
      first: 1000,
      orderBy: 'created_at',
      orderMode: 'desc',
      filters: [...queryOptions.filters, { key: 'created_at', values: [prepareDate(date)], operator: 'gt' }],
      connectionFormat: false,
    };
    let knowledgeData = [];
    if (subscription.entities_ids && subscription.entities_ids.length > 0) {
      // eslint-disable-next-line no-restricted-syntax
      for (const entityId of subscription.entities_ids) {
        const resultFrom = await findAllStixCoreRelationships(user, {
          ...knowledgeParamsFrom,
          fromId: entityId,
          toTypes: [
            ENTITY_TYPE_THREAT_ACTOR,
            ENTITY_TYPE_INTRUSION_SET,
            ENTITY_TYPE_CAMPAIGN,
            ENTITY_TYPE_INCIDENT,
            ENTITY_TYPE_MALWARE,
            ENTITY_TYPE_TOOL,
            ENTITY_TYPE_VULNERABILITY,
            ENTITY_TYPE_ATTACK_PATTERN,
            ENTITY_TYPE_COURSE_OF_ACTION,
            ENTITY_TYPE_IDENTITY,
            ENTITY_TYPE_LOCATION,
          ],
        });
        knowledgeData = [...knowledgeData, ...resultFrom];
        const resultTo = await findAllStixCoreRelationships(user, {
          ...knowledgeParamsTo,
          toId: entityId,
          fromTypes: [
            ENTITY_TYPE_THREAT_ACTOR,
            ENTITY_TYPE_INTRUSION_SET,
            ENTITY_TYPE_CAMPAIGN,
            ENTITY_TYPE_INCIDENT,
            ENTITY_TYPE_MALWARE,
            ENTITY_TYPE_TOOL,
            ENTITY_TYPE_VULNERABILITY,
            ENTITY_TYPE_ATTACK_PATTERN,
            ENTITY_TYPE_COURSE_OF_ACTION,
            ENTITY_TYPE_IDENTITY,
            ENTITY_TYPE_LOCATION,
          ],
        });
        knowledgeData = [...knowledgeData, ...resultTo];
      }
    } else {
      const result = await findAllStixCoreRelationships(user, {
        ...knowledgeParamsFrom,
        fromTypes: [
          ENTITY_TYPE_THREAT_ACTOR,
          ENTITY_TYPE_INTRUSION_SET,
          ENTITY_TYPE_CAMPAIGN,
          ENTITY_TYPE_INCIDENT,
          ENTITY_TYPE_MALWARE,
          ENTITY_TYPE_TOOL,
          ENTITY_TYPE_VULNERABILITY,
          ENTITY_TYPE_ATTACK_PATTERN,
          ENTITY_TYPE_COURSE_OF_ACTION,
          ENTITY_TYPE_IDENTITY,
          ENTITY_TYPE_LOCATION,
        ],
        toTypes: [
          ENTITY_TYPE_THREAT_ACTOR,
          ENTITY_TYPE_INTRUSION_SET,
          ENTITY_TYPE_CAMPAIGN,
          ENTITY_TYPE_INCIDENT,
          ENTITY_TYPE_MALWARE,
          ENTITY_TYPE_TOOL,
          ENTITY_TYPE_VULNERABILITY,
          ENTITY_TYPE_ATTACK_PATTERN,
          ENTITY_TYPE_COURSE_OF_ACTION,
          ENTITY_TYPE_IDENTITY,
          ENTITY_TYPE_LOCATION,
        ],
      });
      knowledgeData = [...knowledgeData, ...result];
    }
    data.knowledgeData = knowledgeData;
  }
  if (subscription.options.includes('CONTAINERS')) {
    const containersParams = {
      first: 1000,
      orderBy: 'created_at',
      orderMode: 'desc',
      filters: [...queryOptions.filters, { key: 'created_at', values: [prepareDate(date)], operator: 'gt' }],
      connectionFormat: false,
    };
    let containersData = [];
    if (subscription.entities_ids && subscription.entities_ids.length > 0) {
      // eslint-disable-next-line no-restricted-syntax
      for (const entityId of subscription.entities_ids) {
        const result = await findAllStixMetaRelationships(user, {
          ...containersParams,
          toId: entityId,
          relationship_type: 'object',
        });
        containersData = [...containersData, ...result];
      }
    } else {
      const result = await findAllContainers(user, containersParams);
      containersData = [...containersData, ...result];
    }
    data.containersData = containersData;
  }
  if (subscription.options.includes('TECHNICAL')) {
    const technicalParams = {
      first: 1000,
      orderBy: 'created_at',
      orderMode: 'desc',
      filters: [...queryOptions.filters, { key: 'created_at', values: [prepareDate(date)], operator: 'gt' }],
      connectionFormat: false,
    };
    let technicalData = [];
    if (subscription.entities_ids && subscription.entities_ids.length > 0) {
      // eslint-disable-next-line no-restricted-syntax
      for (const entityId of subscription.entities_ids) {
        const result = await findAllStixCoreRelationships(user, {
          ...technicalParams,
          elementId: entityId,
          elementWithTargetTypes: [ENTITY_TYPE_INDICATOR, ABSTRACT_STIX_CYBER_OBSERVABLE],
        });
        technicalData = [...technicalData, ...result];
      }
    } else {
      const result = await findAllStixCoreRelationships(user, {
        ...technicalParams,
        elementWithTargetTypes: [ENTITY_TYPE_INDICATOR, ABSTRACT_STIX_CYBER_OBSERVABLE],
      });
      technicalData = [...technicalData, ...result];
    }
    data.technicalData = technicalData;
  }
  if (data.containersData.length === 0 && data.knowledgeData.length === 0 && data.technicalData.length === 0) {
    return null;
  }
  // Prepare HTML data
  let htmlData = '';
  const entities =
    subscription.entities_ids && subscription.entities_ids.length > 0
      ? await Promise.all(subscription.entities_ids.map((n) => internalLoadById(user, n)))
      : [];
  const entitiesNames = entities.map((n) => n.name);
  htmlData += header(baseUrl, entitiesNames);
  if (data.containersData.length > 0) {
    const number = data.containersData.length;
    htmlData += sectionHeader('Containers', number);
    let footerNumber = 0;
    if (number > 10) {
      footerNumber = number - 10;
    }
    // eslint-disable-next-line no-restricted-syntax
    for (const containerEntry of R.take(10, data.containersData)) {
      const fullContainer = await fullLoadById(
        user,
        containerEntry.fromId ? containerEntry.fromId : containerEntry.id,
        containerEntry.fromType ? containerEntry.fromType : containerEntry.entity_type
      );
      htmlData += containerToHtml(baseUrl, fullContainer);
    }
    htmlData += sectionFooter(footerNumber, 'containers');
  }
  if (data.knowledgeData.length > 0) {
    const number = data.knowledgeData.length;
    htmlData += sectionHeader('Knowledge', number);
    let footerNumber = 0;
    if (number > 10) {
      footerNumber = number - 10;
    }
    // eslint-disable-next-line no-restricted-syntax
    for (const relationship of R.take(10, data.knowledgeData)) {
      const fullRelationship = await fullLoadById(user, relationship.id, ABSTRACT_STIX_CORE_RELATIONSHIP);
      htmlData += relationshipToHtml(baseUrl, fullRelationship);
    }
    htmlData += sectionFooter(footerNumber, 'relationships');
  }
  if (data.technicalData.length > 0) {
    const number = data.technicalData.length;
    htmlData += sectionHeader('Technical data', number);
    let footerNumber = 0;
    if (number > 10) {
      footerNumber = number - 10;
    }
    htmlData += `
        <table cellpadding="0" cellspacing="0" style="width: 100%;border-collapse: collapse; font-size: 10pt;">
    `;
    // eslint-disable-next-line no-restricted-syntax
    for (const technicalRelationship of R.take(10, data.technicalData)) {
      const fullTechnicalRelationship = await fullLoadById(
        user,
        technicalRelationship.id,
        ABSTRACT_STIX_CORE_RELATIONSHIP
      );
      htmlData += technicalElementToHtml(baseUrl, fullTechnicalRelationship);
    }
    htmlData += `
         </table>
         <hr style="margin:15pt 0 10pt 0; color: #f6f6f6; border-top: #f6f6f6 1px solid; background: #f6f6f6">
    `;
    htmlData += sectionFooter(footerNumber, 'technical elements');
  }
  htmlData += footer;
  return { to: user.user_email, subject: `[OpenCTI digest] ${subscription.name}`, html: htmlData };
};
