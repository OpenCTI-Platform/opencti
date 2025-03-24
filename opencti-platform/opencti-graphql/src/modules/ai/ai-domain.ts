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

import { callWithTimeout } from '@opentelemetry/sdk-metrics/build/esnext/utils';
import { logApp } from '../../config/conf';
import { FunctionalError, UnknownError } from '../../config/errors';
import { queryAi, queryNLQAi } from '../../database/ai-llm';
import { elSearchFiles } from '../../database/file-search';
import { storeLoadById } from '../../database/middleware-loader';
import { isEmptyField } from '../../database/utils';
import { generateFilterKeysSchema } from '../../domain/filterKeysSchema';
import { findAll as findAllScos } from '../../domain/stixCoreObject';
import { findAll as findAllSmos } from '../../domain/stixMetaObject';
import { findAll as findAllUsers } from '../../domain/user';
import { checkEnterpriseEdition } from '../../enterprise-edition/ee';
import type {
  FilterGroup,
  InputMaybe,
  MutationAiContainerGenerateReportArgs,
  MutationAiNlqArgs,
  MutationAiSummarizeFilesArgs,
  StixMetaObjectConnection,
  UserConnection
} from '../../generated/graphql';
import { Format, Tone } from '../../generated/graphql';
import { ABSTRACT_STIX_CORE_OBJECT, ENTITY_TYPE_CONTAINER } from '../../schema/general';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import { isStixCoreObject } from '../../schema/stixCoreObject';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../schema/stixDomainObject';
import { ENTITY_TYPE_MARKING_DEFINITION, isStixMetaObject } from '../../schema/stixMetaObject';
import { RELATION_EXTERNAL_REFERENCE } from '../../schema/stixRefRelationship';
import type { BasicStoreEntity } from '../../types/store';
import type { AuthContext, AuthUser } from '../../types/user';
import { getContainerKnowledge } from '../../utils/ai/dataResolutionHelpers';
import { INSTANCE_REGARDING_OF } from '../../utils/filtering/filtering-constants';
import { addFilter, checkFiltersValidity, extractFilterGroupValues, filtersEntityIdsMappingResult } from '../../utils/filtering/filtering-utils';
import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT } from '../case/case-incident/case-incident-types';
import { paginatedForPathWithEnrichment } from '../internal/document/document-domain';
import type { BasicStoreEntityDocument } from '../internal/document/document-types';
import { NLQPromptTemplate } from './ai-nlq-utils';

const SYSTEM_PROMPT = 'You are an assistant helping cyber threat intelligence analysts to generate text about cyber threat intelligence information or from a cyber threat intelligence knowledge graph based on the STIX 2.1 model.';

export const fixSpelling = async (context: AuthContext, user: AuthUser, id: string, content: string, format: InputMaybe<Format> = Format.Text) => {
  await checkEnterpriseEdition(context);
  if (content.length < 5) {
    return `Content is too short (${content.length})`;
  }
  const prompt = `
  # Instructions
  - Examine the provided text for any spelling mistakes and correct them accordingly in the original language of the text.
  - Ensure that all words are accurately spelled and that the grammar is correct.
  - If no mistake is detected, just return the original text without anything else.
  - Do NOT change the length of the text.
  - Your response should match the provided content format which is ${format}. Be sure to respect this format and to NOT output anything else than the format and the intended content.

  # Content
  ${content}
  `;
  const response = await queryAi(id, SYSTEM_PROMPT, prompt, user);
  return response;
};

export const makeShorter = async (context: AuthContext, user: AuthUser, id: string, content: string, format: InputMaybe<Format> = Format.Text) => {
  await checkEnterpriseEdition(context);
  if (content.length < 5) {
    return `Content is too short (${content.length})`;
  }
  const prompt = `
  # Instructions
  - Examine the provided text related to cybersecurity and cyber threat intelligence and make it shorter by dividing by 2 the size / length of the text or the number of paragraphs.
  - Make it shorter by dividing by 2 the number of lines but you should keep the main ideas and concepts as well as original language of the text.
  - Do NOT summarize nor enumerate points.
  - Ensure that all words are accurately spelled and that the grammar is correct. 
  - Your response should match the provided content format which is ${format}. Be sure to respect this format and to NOT output anything else than the format.

  # Content
  ${content}
  `;
  const response = await queryAi(id, SYSTEM_PROMPT, prompt, user);
  return response;
};

export const makeLonger = async (context: AuthContext, user: AuthUser, id: string, content: string, format: InputMaybe<Format> = Format.Text) => {
  await checkEnterpriseEdition(context);
  if (content.length < 5) {
    return `Content is too short (${content.length})`;
  }
  const prompt = `
  # Instructions
  - Examine the provided text related to cybersecurity and cyber threat intelligence and make it longer by doubling the size / length of the text or the number of paragraphs.
  - Make it longer by doubling the number of lines by explaining concepts and developing the ideas but NOT too long, the final size should be twice the initial one.
  - Respect the original language of the text.
  - Do NOT summarize nor enumerate points. 
  - Ensure that all words are accurately spelled and that the grammar is correct. 
  - Your response should match the provided content format which is ${format}. Be sure to respect this format and to NOT output anything else than the format.

  # Content
  ${content}
  `;
  const response = await queryAi(id, SYSTEM_PROMPT, prompt, user);
  return response;
};

// eslint-disable-next-line max-len
export const changeTone = async (context: AuthContext, user: AuthUser, id: string, content: string, format: InputMaybe<Format> = Format.Text, tone: InputMaybe<Tone> = Tone.Tactical) => {
  await checkEnterpriseEdition(context);
  if (content.length < 5) {
    return `Content is too short (${content.length})`;
  }
  const prompt = `
  # Instructions
  - Examine the provided text related to cybersecurity and cyber threat intelligence and change its tone to be more ${tone}.
  - Do NOT change the length of the text, the size of the output should be the same as the input.
  - Do NOT summarize nor enumerate points. 
  - Ensure that all words are accurately spelled and that the grammar is correct. 
  - Your response should match the provided content in the same format which is ${format}. Be sure to respect this format and to NOT output anything else than the format.

  # Content
  ${content}
  `;
  const response = await queryAi(id, SYSTEM_PROMPT, prompt, user);
  return response;
};

export const summarize = async (context: AuthContext, user: AuthUser, id: string, content: string, format: InputMaybe<Format> = Format.Text) => {
  await checkEnterpriseEdition(context);
  if (content.length < 5) {
    return `Content is too short (${content.length})`;
  }
  const prompt = `
  # Instructions
  - Examine the provided text related to cybersecurity and cyber threat intelligence and summarize it with main ideas and concepts.
  - Make it shorter and summarize key points highlighting the deep meaning of the text.
  - Ensure that all words are accurately spelled and that the grammar is correct. 
  - Your response should match the provided content format which is ${format}. Be sure to respect this format and to NOT output anything else than the format.

  # Content
  ${content}
  `;
  const response = await queryAi(id, SYSTEM_PROMPT, prompt, user);
  return response;
};

export const explain = async (context: AuthContext, user: AuthUser, id: string, content: string) => {
  await checkEnterpriseEdition(context);
  if (content.length < 5) {
    return `Content is too short (${content.length})`;
  }
  const prompt = `
  # Instructions
  - Examine the provided text related to cybersecurity and cyber threat intelligence and explain it.
  - Popularize the text to enlighten non-specialist by explaining key concepts and overall meaning.
  - Ensure that all words are accurately spelled and that the grammar is correct. 
  - Your response should be done in plain text regardless of the original format.

  # Content
  ${content}
  `;
  const response = await queryAi(id, SYSTEM_PROMPT, prompt, user);
  return response;
};

export const generateContainerReport = async (context: AuthContext, user: AuthUser, args: MutationAiContainerGenerateReportArgs) => {
  await checkEnterpriseEdition(context);
  const { id, containerId, paragraphs = 10, tone = 'technical', format = 'HTML', language = 'en-us' } = args;
  const paragraphsNumber = !paragraphs || paragraphs > 20 ? 20 : paragraphs;
  const container = await storeLoadById(context, user, containerId, ENTITY_TYPE_CONTAINER) as BasicStoreEntity;
  const { relationshipsSentences, entitiesInvolved } = await getContainerKnowledge(context, user, containerId);
  // Meaningful type
  let meaningfulType = '';
  if (container.entity_type === ENTITY_TYPE_CONTAINER_REPORT) {
    meaningfulType = `cyber threat intelligence report published on ${container.published}`;
  } else if (container.entity_type === ENTITY_TYPE_CONTAINER_CASE_INCIDENT) {
    meaningfulType = `case related to an incident response most likely internal and containing alerts, cyber observables and behaviours and created on${container.created}`;
  } else {
    meaningfulType = `cyber threat intelligence report published on ${container.created}`;
  }
  // build sentences
  const prompt = `
    # Instructions
    - We are in a context of a ${meaningfulType}.
    - You must generate a cyber threat intelligence report in ${format} with a title and a content without using bullet points.
    - The report should be ${paragraphsNumber} paragraphs long. Each paragraph must be 30 words.
    - The cyber threat intelligence report should be focused on ${tone} aspects and should be divided into meaningful parts such as: victims, techniques or vulnerabilities used for intrusion, then execution, then persistence and then infrastructure. 
    - You should take examples of well-known cyber threat intelligence reports available everywhere. The report is about ${container.name}. Details are: ${container.description}.
    
    # Formatting
    - The report should be in ${format?.toUpperCase() ?? 'TEXT'} format.
    - The report should be in ${language} language.
    - Just output the report without anything else.
    - For all found technical indicators of compromise and or observables, you must generate a table with all of them at the end of the report, including file hashes, IP addresses, domain names, etc.
    
    # Facts
    ${relationshipsSentences}
    
    # Contextual information about the above facts
    ${entitiesInvolved}
  `;
  const response = await queryAi(id, SYSTEM_PROMPT, prompt, user);
  return response.replace('```html', '').replace('```markdown', '').replace('```', '').trim();
};

// TODO This function is deprecated (AI Insights)
export const summarizeFiles = async (context: AuthContext, user: AuthUser, args: MutationAiSummarizeFilesArgs) => {
  await checkEnterpriseEdition(context);
  const { id, elementId, paragraphs = 10, fileIds, tone = 'technical', format = 'HTML', language = 'en-us' } = args;
  const paragraphsNumber = !paragraphs || paragraphs > 20 ? 20 : paragraphs;
  const stixCoreObject = await storeLoadById(context, user, elementId, ABSTRACT_STIX_CORE_OBJECT) as BasicStoreEntity;
  let finalFilesIds = fileIds ?? [];
  if (isEmptyField(fileIds)) {
    // get content files
    const opts = {
      first: 20,
      prefixMimeTypes: undefined,
      entity_id: stixCoreObject.id,
      entity_type: stixCoreObject.entity_type
    };
    const importFiles = await paginatedForPathWithEnrichment(context, user, `import/${stixCoreObject.entity_type}/${stixCoreObject.id}`, stixCoreObject.id, opts);
    finalFilesIds = importFiles.edges.map((n) => n.node.id);
    // get external ref files
    const refs = stixCoreObject[RELATION_EXTERNAL_REFERENCE] ?? [];
    await Promise.all(refs.map(async (ref) => {
      const optsRef = {
        first: 20,
        prefixMimeTypes: undefined,
        entity_id: ref,
        entity_type: 'External-Reference'
      };
      const importRefFiles = await paginatedForPathWithEnrichment(context, user, `import/External-Reference/${ref}`, ref, optsRef);
      const refFilesIds = importRefFiles.edges.map((n) => n.node.id);
      refFilesIds.forEach((refFileId) => finalFilesIds.push(refFileId));
    }));
  }
  if (isEmptyField(finalFilesIds) || finalFilesIds?.length === 0) {
    return 'Unable to summarize files as no file is associated to this entity.';
  }
  const files = await elSearchFiles(context, user, {
    first: 10,
    fileIds: finalFilesIds,
    connectionFormat: false,
    excludeFields: [],
    includeContent: true
  });
  const filesContent = files.map((n: BasicStoreEntityDocument) => n.content);
  const prompt = `
  # Instructions
  - Examine the one or multiple cyber threat intelligence reports below and summarize them with main ideas and concepts in ${format} format.
  - Make a lot more shorter and summarize key points highlighting the deep meaning of the text.
  - The cyber threat intelligence summary should be focused on ${tone} aspects
  - The summary should have ${paragraphsNumber} of approximately 5 lines each.
  - Ensure that all words are accurately spelled and that the grammar is correct. 
  - Your response should in the given format which is ${format}, be sure to respect this format.
  - Your response should be in ${language} language.
  
  # Content
  ${filesContent.join('')}
  `;
  const response = await queryAi(id, SYSTEM_PROMPT, prompt, user);
  return response;
};

// TODO This function is deprecated (NLP)
export const convertFilesToStix = async (context: AuthContext, user: AuthUser, args: MutationAiSummarizeFilesArgs) => {
  await checkEnterpriseEdition(context);
  const { id, elementId, fileIds } = args;
  const stixCoreObject = await storeLoadById(context, user, elementId, ABSTRACT_STIX_CORE_OBJECT) as BasicStoreEntity;
  let finalFilesIds = fileIds;
  if (isEmptyField(fileIds)) {
    const opts = {
      first: 20,
      prefixMimeTypes: undefined,
      entity_id: stixCoreObject.id,
      entity_type: stixCoreObject.entity_type
    };
    const importFiles = await paginatedForPathWithEnrichment(context, user, `import/${stixCoreObject.entity_type}/${stixCoreObject.id}`, stixCoreObject.id, opts);
    finalFilesIds = importFiles.edges.map((n) => n.node.id);
  }
  if (isEmptyField(finalFilesIds) || finalFilesIds?.length === 0) {
    return 'Unable to summarize files as no file is associated to this entity.';
  }
  const files = await elSearchFiles(context, user, {
    first: 10,
    fileIds: finalFilesIds,
    connectionFormat: false,
    excludeFields: [],
    includeContent: true
  });
  const filesContent = files.map((n: BasicStoreEntityDocument) => n.content);
  const prompt = `
  # Instructions
  - Examine the one or multiple cyber threat intelligence reports below and convert them to Oasis Open STIX 2.1 JSON format.
  - You should recognize the STIX entities such as intrusion sets, malware, locations, identities in the reports and convert them.
  - You should analyze the grammar and the syntax of the reports to create meaningful STIX 2.1 relationships such as targets, attributed-to, uses, etc.
  - Do your best to convert even if it is challenging and not accurate.
  - Your response should be in JSON STIX 2.1 format. Just output the JSON and nothing else.
  - Always consider threat actors as intrusion sets, the bundle should not contain any threat actor.
  - Response should only contain the JSON output with no other sentences nor explanation.
  
  # Content
  ${filesContent.join('')}
  `;
  const response = await queryAi(id, SYSTEM_PROMPT, prompt, user);
  return response;
};

const resolveValuesIdsMapForEntityTypes = async (context: AuthContext, user: AuthUser, valuesIdsToResolve: string[], entityTypes: string[]) => {
  const notResolvedValues: string[] = [];
  const mapContent = await Promise.all(valuesIdsToResolve.map(async (value): Promise<[string, string | null]> => {
    const entityTypesFilter = addFilter(undefined, 'entity_type', entityTypes);
    let resultIds: string[] = [];
    // case Stix-Core-Object
    if (entityTypes.every((type) => isStixCoreObject(type))) {
      const result = await findAllScos(context, user, {
        filters: entityTypesFilter,
        search: value,
        orderBy: '_score',
        orderMode: 'desc',
      });
      resultIds = result.edges.map((n) => n.node.id);
    } else if (entityTypes.length === 1 && entityTypes.includes(ENTITY_TYPE_USER)) { // case User
      const result = await findAllUsers(context, user, {
        filters: entityTypesFilter,
        search: value,
        orderBy: '_score',
        orderMode: 'desc',
      });
      resultIds = (result as UserConnection).edges.map((n) => n.node.id);
    } else if (entityTypes.every((type) => isStixMetaObject(type))) { // case Stix-Meta-Object
      const result = await findAllSmos(context, user, {
        filters: entityTypesFilter,
        search: value,
        orderBy: '_score',
        orderMode: 'desc',
        useWildcardPrefix: !!(entityTypes.length === 1 && entityTypes.includes(ENTITY_TYPE_MARKING_DEFINITION)),
      });
      resultIds = ((result as unknown as StixMetaObjectConnection).edges ?? [])
        .map((n) => n?.node.id)
        .filter((n) => !!n) as string[];
    }
    // keep only the first result
    if (resultIds.length > 0) {
      return [value, resultIds[0]];
    }
    // if no results, the value is not resolved
    notResolvedValues.push(value);
    return [value, null];
  }));
  return { mapContent, notResolvedValues };
};

export const filtersEntityIdsMapping = async (context: AuthContext, user: AuthUser, filters: FilterGroup) => {
  // 01. fetch the filter keys corresponding to an id
  const filterDefinitions = await generateFilterKeysSchema();
  const stixCoreObjectsFilterDefinitions = filterDefinitions
    .find((f) => f.entity_type === ABSTRACT_STIX_CORE_OBJECT)?.filters_schema
    .map((f) => f.filterDefinition) ?? [];
  const idsFiltersDefinitions = stixCoreObjectsFilterDefinitions.filter((f) => f.type === 'id');
  // 02. separate stix core objects ids from other entity types ids, and fetch the values to resolve
  // for stix core objects ids
  const scoIdsFilterKeys = idsFiltersDefinitions
    .filter((f) => f.elementsForFilterValuesSearch.every((type) => isStixCoreObject(type)))
    .map((f) => f.filterKey)
    .concat([INSTANCE_REGARDING_OF]);
  const scoValuesIdsToResolve = extractFilterGroupValues(filters, scoIdsFilterKeys);
  // for other ids
  const idsFilterResolutionsForOtherTypes = idsFiltersDefinitions
    .filter((f) => f.elementsForFilterValuesSearch.some((type) => !isStixCoreObject(type)))
    .map((f) => ({
      filterKey: f.filterKey,
      entityTypes: f.elementsForFilterValuesSearch,
      valuesToResolve: extractFilterGroupValues(filters, f.filterKey)
    }))
    .filter((f) => f.valuesToResolve.length > 0);
  const idsFilterKeys = scoIdsFilterKeys.concat(
    idsFilterResolutionsForOtherTypes.map((n) => n.filterKey)
  );
  // 03. create a map of the values to resolve and their potential corresponding id, and list the not resolved values
  const { mapContent: scosMapContent, notResolvedValues: notResolvedScos } = await resolveValuesIdsMapForEntityTypes(
    context,
    user,
    scoValuesIdsToResolve,
    [ABSTRACT_STIX_CORE_OBJECT]
  );
  const otherIdsResolution = await Promise.all(idsFilterResolutionsForOtherTypes.map((n) => resolveValuesIdsMapForEntityTypes(
    context,
    user,
    n.valuesToResolve,
    n.entityTypes,
  )));
  const valuesIdsMap = new Map(scosMapContent.concat(otherIdsResolution.flatMap((n) => n.mapContent)));
  const notResolvedValues = notResolvedScos.concat(otherIdsResolution.flatMap((n) => n.notResolvedValues));
  // 04. replace the values in filters with their corresponding ids
  return {
    filters: filtersEntityIdsMappingResult(filters, idsFilterKeys, valuesIdsMap),
    notResolvedValues,
  };
};

export const generateNLQresponse = async (context: AuthContext, user: AuthUser, args: MutationAiNlqArgs) => {
  await checkEnterpriseEdition(context);
  const { search } = args;
  const promptValue = await NLQPromptTemplate.formatPromptValue({ text: search });

  // 01. query the model
  logApp.debug('[AI] Querying NLQ with prompt', { questionStart: search.substring(0, 100) });
  const NLQ_TIMEOUT = 30 * 1000; // timeout: 30s
  let rawResponse;
  try {
    rawResponse = await callWithTimeout(queryNLQAi(promptValue), NLQ_TIMEOUT);
  } catch (error) {
    throw UnknownError('Error when calling the NLQ model', { error, promptValue });
  }
  const parsedResponse = { ...rawResponse, filterGroups: [] } as unknown as FilterGroup;

  // 02. check the filters validity
  try {
    checkFiltersValidity(parsedResponse);
  } catch (error) {
    throw FunctionalError(`The NLQ filters response format is not correct: ${JSON.stringify(parsedResponse)}`, { error, data: parsedResponse });
  }

  // 03. map entities ids
  const { filters: filtersResult, notResolvedValues } = await filtersEntityIdsMapping(context, user, parsedResponse);

  // return the stringified filters
  return { filters: JSON.stringify(filtersResult), notResolvedValues };
};
