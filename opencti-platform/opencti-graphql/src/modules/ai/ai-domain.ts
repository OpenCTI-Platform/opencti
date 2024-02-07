/*
Copyright (c) 2021-2024 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Non-Commercial License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import * as R from 'ramda';
import { listAllToEntitiesThroughRelations, storeLoadById } from '../../database/middleware-loader';
import { ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_CORE_RELATIONSHIP, ENTITY_TYPE_CONTAINER } from '../../schema/general';
import { RELATION_OBJECT } from '../../schema/stixRefRelationship';
import { extractEntityRepresentativeName, extractRepresentativeDescription } from '../../database/entity-representative';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntity, BasicStoreRelation } from '../../types/store';
import type { InputMaybe, MutationAiContainerGenerateReportArgs, MutationAiSummarizeFilesArgs } from '../../generated/graphql';
import { isNotEmptyField } from '../../database/utils';
import { FROM_START_STR, UNTIL_END_STR } from '../../utils/format';
import { compute } from '../../database/ai-llm';
import {
  RELATION_AMPLIFIES,
  RELATION_ATTRIBUTED_TO,
  RELATION_COMPROMISES,
  RELATION_COOPERATES_WITH,
  RELATION_HAS,
  RELATION_LOCATED_AT,
  RELATION_TARGETS,
  RELATION_USES
} from '../../schema/stixCoreRelationship';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../schema/stixDomainObject';
import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT } from '../case/case-incident/case-incident-types';
import { getEntityFromCache } from '../../database/cache';
import type { BasicStoreSettings } from '../../types/settings';
import { SYSTEM_USER } from '../../utils/access';
import { ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';
import { UnsupportedError } from '../../config/errors';
import { Format, Tone } from '../../generated/graphql';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { AI_BUS } from './ai-types';
import { findById, paginatedForPathWithEnrichment } from '../internal/document/document-domain';

const RESOLUTION_LIMIT = 200;

export const checkEnterpriseEdition = async (context: AuthContext) => {
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const enterpriseEditionEnabled = isNotEmptyField(settings?.enterprise_edition);
  if (!enterpriseEditionEnabled) {
    throw UnsupportedError('Enterprise edition is not enabled');
  }
};

export const fixSpelling = async (context: AuthContext, user: AuthUser, id: string, content: string, format: InputMaybe<Format> = Format.Text) => {
  await checkEnterpriseEdition(context);
  if (content.length < 5) {
    const message = `Content is too short${content.length}`;
    await notify(BUS_TOPICS[AI_BUS].EDIT_TOPIC, { bus_id: id, content: message }, user);
    return message;
  }
  const prompt = `
  # Instructions
  - Examine the provided English text for any spelling mistakes and correct them accordingly.
  - Ensure that all words are accurately spelled and that the grammar is correct.
  - If no mistake is detected, just return the original text without anything else.
  - Do NOT change the length of the text.
  - Your response should match the provided content format which is ${format}, be sure to respect this format.

  # Content
  ${content}
  `;
  const response = await compute(id, prompt, user);
  return response;
};

export const makeShorter = async (context: AuthContext, user: AuthUser, id: string, content: string, format: InputMaybe<Format> = Format.Text) => {
  await checkEnterpriseEdition(context);
  if (content.length < 5) {
    const message = `Content is too short${content.length}`;
    await notify(BUS_TOPICS[AI_BUS].EDIT_TOPIC, { bus_id: id, content: message }, user);
    return message;
  }
  const prompt = `
  # Instructions
  - Examine the provided English text related to cybersecurity and cyber threat intelligence and make it shorter by dividing by 2 the size / length of the text.
  - Make it shorter by dividing by 2 the number of lines but you should keep the main ideas and concepts.
  - Do NOT summarize or enumerate points.
  - Do NOT change the length of the text.
  - Ensure that all words are accurately spelled and that the grammar is correct. 
  - Your response should match the provided content format which is ${format}, be sure to respect this format.

  # Content
  ${content}
  `;
  const response = await compute(id, prompt, user);
  return response;
};

export const makeLonger = async (context: AuthContext, user: AuthUser, id: string, content: string, format: InputMaybe<Format> = Format.Text) => {
  await checkEnterpriseEdition(context);
  if (content.length < 5) {
    const message = `Content is too short${content.length}`;
    await notify(BUS_TOPICS[AI_BUS].EDIT_TOPIC, { bus_id: id, content: message }, user);
    return message;
  }
  const prompt = `
  # Instructions
  - Examine the provided English text related to cybersecurity and cyber threat intelligence and make it longer by doubling the size / length of the text.
  - Make it longer by doubling the number of lines by explaining concepts and developing the ideas. 
  - Do NOT summarize or enumerate points. 
  - Ensure that all words are accurately spelled and that the grammar is correct. 
  - Your response should match the provided content format which is ${format}, be sure to respect this format.

  # Content
  ${content}
  `;
  const response = await compute(id, prompt, user);
  return response;
};

// eslint-disable-next-line max-len
export const changeTone = async (context: AuthContext, user: AuthUser, id: string, content: string, format: InputMaybe<Format> = Format.Text, tone: InputMaybe<Tone> = Tone.Technical) => {
  await checkEnterpriseEdition(context);
  if (content.length < 5) {
    const message = `Content is too short${content.length}`;
    await notify(BUS_TOPICS[AI_BUS].EDIT_TOPIC, { bus_id: id, content: message }, user);
    return message;
  }
  const prompt = `
  # Instructions
  - Examine the provided English text related to cybersecurity and cyber threat intelligence and change its tone to be more ${tone}.
  - Do NOT change the length of the text. 
  - Do NOT summarize or enumerate points. 
  - Ensure that all words are accurately spelled and that the grammar is correct. 
  - Your response should match the provided content in the same format which is ${format}.

  # Content
  ${content}
  `;
  const response = await compute(id, prompt, user);
  return response;
};

export const summarize = async (context: AuthContext, user: AuthUser, id: string, content: string, format: InputMaybe<Format> = Format.Text) => {
  await checkEnterpriseEdition(context);
  if (content.length < 5) {
    const message = `Content is too short${content.length}`;
    await notify(BUS_TOPICS[AI_BUS].EDIT_TOPIC, { bus_id: id, content: message }, user);
    return message;
  }
  const prompt = `
  # Instructions
  - Examine the provided English text related to cybersecurity and cyber threat intelligence and summarize it with main ideas and concepts.
  - Make it shorter and summarize key points highlighting the deep meaning of the text.
  - Ensure that all words are accurately spelled and that the grammar is correct. 
  - Your response should match the provided content format which is ${format}, be sure to respect this format.

  # Content
  ${content}
  `;
  const response = await compute(id, prompt, user);
  return response;
};

export const explain = async (context: AuthContext, user: AuthUser, id: string, content: string) => {
  await checkEnterpriseEdition(context);
  if (content.length < 5) {
    const message = `Content is too short${content.length}`;
    await notify(BUS_TOPICS[AI_BUS].EDIT_TOPIC, { bus_id: id, content: message }, user);
    return message;
  }
  const prompt = `
  # Instructions
  - Examine the provided English text related to cybersecurity and cyber threat intelligence and explain it.
  - Popularize the text to enlighten non-specialist by explaining key concepts and overall meaning.
  - Ensure that all words are accurately spelled and that the grammar is correct. 
  - Your response should be done in plain text english regardless of the original format.

  # Content
  ${content}
  `;
  const response = await compute(id, prompt, user);
  return response;
};

export const generateContainerReport = async (context: AuthContext, user: AuthUser, args: MutationAiContainerGenerateReportArgs) => {
  await checkEnterpriseEdition(context);
  const { id, containerId, paragraphs = 10, tone = 'technical', format = 'HTML' } = args;
  const paragraphsNumber = !paragraphs || paragraphs > 20 ? 20 : paragraphs;
  const container = await storeLoadById(context, user, containerId, ENTITY_TYPE_CONTAINER) as BasicStoreEntity;
  const elements = await listAllToEntitiesThroughRelations(context, user, containerId, RELATION_OBJECT, [ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_CORE_RELATIONSHIP]);
  // generate mappings
  const relationships = R.take(RESOLUTION_LIMIT, elements.filter((n) => n.parent_types.includes(ABSTRACT_STIX_CORE_RELATIONSHIP))) as Array<BasicStoreRelation>;
  const entities = R.take(RESOLUTION_LIMIT, elements.filter((n) => n.parent_types.includes(ABSTRACT_STIX_CORE_OBJECT))) as Array<BasicStoreEntity>;
  const indexedEntities = R.indexBy(R.prop('id'), entities);
  if (entities.length < 3) {
    const message = 'AI model unable to generate a report for containers with less than 3 entities.';
    await notify(BUS_TOPICS[AI_BUS].EDIT_TOPIC, { bus_id: id, content: message }, user);
    return message;
  }
  // generate entities involved
  const entitiesInvolved = R.values(indexedEntities).map((n) => {
    return `
      -------------------
      - The ${n.entity_type} ${extractEntityRepresentativeName(n)} described / detailed with the description: ${extractRepresentativeDescription(n)}.
      -------------------
    `;
  });
  // generate relationships sentences
  const meaningfulRelationships = [
    RELATION_TARGETS,
    RELATION_USES,
    RELATION_ATTRIBUTED_TO,
    RELATION_AMPLIFIES,
    RELATION_COMPROMISES,
    RELATION_COOPERATES_WITH,
    RELATION_LOCATED_AT,
    RELATION_HAS
  ];
  const relationshipsSentences = relationships.filter((n) => meaningfulRelationships.includes(n.relationship_type)).map((n) => {
    const from = indexedEntities[n.fromId];
    const to = indexedEntities[n.toId];
    if (isNotEmptyField(from) && isNotEmptyField(to)) {
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-expect-error
      const startTime = n.start_time === FROM_START_STR ? 'unknown date' : n.start_time;
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-expect-error
      const stopTime = n.stop_time === UNTIL_END_STR ? 'unknown date' : n.stop_time;
      return `
        -------------------
        - The ${from.entity_type} ${extractEntityRepresentativeName(from)} ${n.relationship_type} the ${to.entity_type} ${extractEntityRepresentativeName(to)} from ${startTime} to ${stopTime} (${n.description}).
        -------------------
      `;
    }
    return '';
  });
  // Meaningful type
  let meaningfulType = '';
  if (container.entity_type === ENTITY_TYPE_CONTAINER_REPORT) {
    meaningfulType = `cyber threat intelligence report published on ${container.published}`;
  } else if (container.entity_type === ENTITY_TYPE_CONTAINER_CASE_INCIDENT) {
    meaningfulType = `case related to an incident response most likely internal and containing alerts, cyber observables and behaviours and created on${container.created}`;
  }
  // build sentences
  const prompt = `
    # Instructions
    - We are in a context of a ${meaningfulType}.
    - You must generate a cyber threat intelligence report in ${format} with a title and a content of ${paragraphsNumber} paragraphs of approximately 5 lines each without using bullet points.
    - The cyber threat intelligence report should be focused on ${tone} aspects and should be divided into meaningful parts such as: victims, techniques or vulnerabilities used for intrusion, then execution, then persistence and then infrastructure. 
    - You should take examples of well-known cyber threat intelligence reports available everywhere. The report is about ${container.name}. Details are: ${container.description}.
    
    # Formatting
    - The report should be in ${format?.toUpperCase() ?? 'TEXT'} format.
    - For all found technical indicators of compromise and or observables, you must generate a table with all of them at the end of the report, including file hashes, IP addresses, domain names, etc.
    
    # Facts
    ${relationshipsSentences.join('')}
    
    # Contextual information about the above facts
    ${entitiesInvolved.join('')}
  `;
  const response = await compute(id, prompt, user);
  return response;
};

export const summarizeFiles = async (context: AuthContext, user: AuthUser, args: MutationAiSummarizeFilesArgs) => {
  await checkEnterpriseEdition(context);
  const { id, elementId, paragraphs = 10, tone = 'technical', format = 'HTML' } = args;
  const paragraphsNumber = !paragraphs || paragraphs > 20 ? 20 : paragraphs;
  const stixCoreObject = await storeLoadById(context, user, elementId, ABSTRACT_STIX_CORE_OBJECT) as BasicStoreEntity;
  const opts = { first: 20, prefixMimeTypes: undefined, entity_id: stixCoreObject.id, entity_type: stixCoreObject.entity_type };
  const importFiles = await paginatedForPathWithEnrichment(context, user, `import/${stixCoreObject.entity_type}/${stixCoreObject.id}`, stixCoreObject.id, opts);
  const filesContent = await Promise.all(importFiles.edges.map((n) => findById(context, user, n.node.id)));
  const files = filesContent.map((n) => {
    return `
    -------------------
    ${n.content}
    -------------------
    `;
  });
  const prompt = `
  # Instructions
  - Examine the one or multiple cyber threat intelligence reports below and summarize them with main ideas and concepts in ${format} format.
  - Make a lot more shorter and summarize key points highlighting the deep meaning of the text.
  - The cyber threat intelligence summary should be focused on ${tone} aspects
  - The summary should have ${paragraphsNumber} of approximately 5 lines each.
  - Ensure that all words are accurately spelled and that the grammar is correct. 
  - Your response should in the given format which is ${format}, be sure to respect this format.
  
  # Content
  ${files.join('')}
  `;
  const response = await compute(id, prompt, user);
  return response;
};
