/* eslint-disable no-useless-escape */
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


import { ChatPromptTemplate, FewShotChatMessagePromptTemplate } from "@langchain/core/prompts";
import { ChatOpenAI } from "@langchain/openai";
import { z } from "zod";
import { queryAi } from '../../database/ai-llm';
import { elSearchFiles } from '../../database/file-search';
import { storeLoadById } from '../../database/middleware-loader';
import { isEmptyField } from '../../database/utils';
import { checkEnterpriseEdition } from '../../enterprise-edition/ee';
import type { InputMaybe, MutationAiContainerGenerateReportArgs, MutationAiNlqArgs, MutationAiSummarizeFilesArgs } from '../../generated/graphql';
import { Format, Tone } from '../../generated/graphql';
import { FilterMode, FilterOperator } from "../../generated/graphql.js";
import { ABSTRACT_STIX_CORE_OBJECT, ENTITY_TYPE_CONTAINER } from '../../schema/general';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../schema/stixDomainObject';
import { RELATION_EXTERNAL_REFERENCE } from '../../schema/stixRefRelationship';
import type { BasicStoreEntity } from '../../types/store';
import type { AuthContext, AuthUser } from '../../types/user';
import { getContainerKnowledge } from '../../utils/ai/dataResolutionHelpers';
import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT } from '../case/case-incident/case-incident-types';
import { paginatedForPathWithEnrichment } from '../internal/document/document-domain';
import type { BasicStoreEntityDocument } from '../internal/document/document-types';

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

// filter.js



// =======================
// Filter Values
// =======================

// "entity_type",
// "objectAssignee",
// "regardingOf",


const FilterTypeEnum = z.enum([
  "created_at",
  "updated_at",
  "creator_id",
  "opinions_metrics.mean",
  "opinions_metrics.max",
  "opinions_metrics.min",
  "opinions_metrics.total",
  "createdBy",
  "objectMarking",
  "objectLabel",
  "externalReferences",
  "computed_reliability",
  "objects",
  "workflow_id",
  "created",
  "confidence",
  "name",
  "description",
  "x_mitre_platforms",
  "x_mitre_permissions_required",
  "x_mitre_detection",
  "killChainPhases",
  "alias",
  "first_seen",
  "last_seen",
  "objective",
  "objectOrganization",
  "attribute_abstract",
  "content",
  "note_types",
  "likelihood",
  "first_observed",
  "last_observed",
  "number_observed",
  "explanation",
  "opinion",
  "report_types",
  "published",
  "objectParticipant",
  "x_mitre_id",
  "x_opencti_threat_hunting",
  "x_opencti_log_sources",
  "contact_information",
  "infrastructure_types",
  "goals",
  "resource_level",
  "primary_motivation",
  "secondary_motivations",
  "postal_code",
  "street_address",
  "malware_types",
  "is_family",
  "architecture_execution_envs",
  "implementation_languages",
  "capabilities",
  "samples",
  "operatingSystems",
  "threat_actor_types",
  "roles",
  "sophistication",
  "tool_types",
  "tool_version",
  "x_opencti_cvss_base_score",
  "x_opencti_cvss_base_severity",
  "x_opencti_cvss_attack_vector",
  "x_opencti_cvss_integrity_impact",
  "x_opencti_cvss_availability_impact",
  "x_opencti_cvss_confidentiality_impact",
  "x_opencti_cisa_kev",
  "x_opencti_epss_score",
  "x_opencti_epss_percentile",
  "incident_type",
  "severity",
  "source",
  "channel_types",
  "event_types",
  "start_time",
  "stop_time",
  "context",
  "narrative_types",
  "dataSource",
  "collection_layers",
  "due_date",
  "priority",
  "response_types",
  "information_types",
  "takedown_types",
  "rating",
  "product",
  "version",
  "configuration_version",
  "modules",
  "analysis_engine_version",
  "analysis_definition_version",
  "submitted",
  "analysis_started",
  "analysis_ended",
  "result",
  "hostVm",
  "operatingSystem",
  "installedSoftware",
  "analysisSco",
  "analysisSample",
  "revoked",
  "personal_motivations",
  "date_of_birth",
  "gender",
  "job_title",
  "marital_status",
  "eye_color",
  "hair_color",
  "bornIn",
  "ethnicity",
  "pattern_type",
  "pattern",
  "indicator_types",
  "valid_from",
  "valid_until",
  "x_opencti_score",
  "x_opencti_detection",
  "x_opencti_main_observable_type",
  "x_opencti_organization_type",
  "x_opencti_description",
  "number",
  "rir",
  "path",
  "path_enc",
  "ctime",
  "mtime",
  "atime",
  "containsObservable",
  "value",
  "resolvesTo",
  "display_name",
  "belongsTo",
  "is_multipart",
  "attribute_date",
  "content_type",
  "message_id",
  "subject",
  "received_lines",
  "body",
  "emailFrom",
  "emailSender",
  "emailTo",
  "emailCc",
  "emailBcc",
  "bodyMultipart",
  "rawEmail",
  "content_disposition",
  "bodyRaw",
  "hashes.MD5",
  "hashes.SHA-1",
  "hashes.SHA-256",
  "hashes.SHA-512",
  "hashes.SSDEEP",
  "mime_type",
  "payload_bin",
  "url",
  "encryption_algorithm",
  "decryption_key",
  "x_opencti_additional_names",
  "extensions",
  "size",
  "name_enc",
  "magic_number_hex",
  "parentDirectory",
  "obsContent",
  "is_self_signed",
  "serial_number",
  "signature_algorithm",
  "issuer",
  "validity_not_before",
  "validity_not_after",
  "subject_public_key_algorithm",
  "subject_public_key_modulus",
  "subject_public_key_exponent",
  "basic_constraints",
  "name_constraints",
  "policy_constraints",
  "key_usage",
  "extended_key_usage",
  "subject_key_identifier",
  "authority_key_identifier",
  "subject_alternative_name",
  "issuer_alternative_name",
  "subject_directory_attributes",
  "crl_distribution_points",
  "inhibit_any_policy",
  "private_key_usage_period_not_before",
  "private_key_usage_period_not_after",
  "certificate_policies",
  "policy_mappings",
  "start",
  "end",
  "is_active",
  "src_port",
  "dst_port",
  "protocols",
  "src_byte_count",
  "dst_byte_count",
  "src_packets",
  "dst_packets",
  "networkSrc",
  "networkDst",
  "srcPayload",
  "dstPayload",
  "networkEncapsulates",
  "encapsulatedBy",
  "is_hidden",
  "pid",
  "created_time",
  "cwd",
  "command_line",
  "environment_variables",
  "aslr_enabled",
  "dep_enabled",
  "owner_sid",
  "window_title",
  "integrity_level",
  "service_name",
  "descriptions",
  "group_name",
  "start_type",
  "service_type",
  "service_status",
  "openedConnections",
  "creatorUser",
  "processImage",
  "processParent",
  "processChild",
  "serviceDlls",
  "cpe",
  "swid",
  "languages",
  "vendor",
  "user_id",
  "credential",
  "account_login",
  "account_type",
  "is_service_account",
  "is_privileged",
  "can_escalate_privs",
  "is_disabled",
  "account_created",
  "account_expires",
  "credential_last_changed",
  "account_first_login",
  "account_last_login",
  "attribute_key",
  "modified_time",
  "number_of_subkeys",
  "winRegValues",
  "data",
  "data_type",
  "iban",
  "bic",
  "account_number",
  "card_number",
  "expiration_date",
  "cvv",
  "holder_name",
  "title",
  "media_category",
  "publication_date",
  "persona_name",
  "persona_type",
  "relationship_type", 
  // "id"
]);

const RelationshipTypeEnum = z.enum([
  "attributed-to",
  "exploits",
  "has",
  "indicates",
  "located-at",
  "originates-from",
  "part-of",
  "related-to",
  "subtechnique-of",
  "targets",
  "uses",
]);


const EntityTypeEnum = z.enum([
  "Administrative-Area",
  "Attack-Pattern",
  "Campaign",
  "Channel",
  "City",
  "Country",
  "Course-Of-Action",
  "Data-Component",
  "Data-Source",
  "Event",
  "Feedback",
  "Grouping",
  "Incident",
  "Case-Incident",
  "Indicator",
  "Individual",
  "Infrastructure",
  "Intrusion-Set",
  "Language",
  "Malware",
  "Malware-Analysis",
  "Narrative",
  "Note",
  "Observed-Data",
  "Opinion",
  "Organization",
  "Position",
  "Region",
  "Report",
  "Stix-Cyber-Observable",
  "Case-Rfi",
  "Case-Rft",
  "Sector",
  "System",
  "Task",
  "Threat-Actor-Group",
  "Threat-Actor-Individual",
  "Tool",
  "Vulnerability",
]);

// =======================
// Classes
// =======================

const RegardingOfRelationshipTypeItem = z.object({
  key: z.literal("relationship_type")
    .describe("The key of a 'regardingOf' relationship type filter, always 'relationship_type'."),
  values: z.array(RelationshipTypeEnum)
    .describe("A list of relationship type filter values."),
});

const RegardingOfEntityNameItem = z.object({
  key: z.literal("id")
    .describe("The key of a 'regardingOf' entity name filter, always 'id'."),
  values: z.array(z.string())
    .describe("A list of entity name filter values."),
});

export const RegardingOfFilterItem = z.object({
  key: z.literal("regardingOf")
    .describe("The key of the 'regardingOf' filter, always 'regardingOf'."),
  values: z.array(z.union([RegardingOfEntityNameItem, RegardingOfRelationshipTypeItem]))
    .describe("A list of entity name or relationship type filter values."),
  operator: z.literal("eq")
    .describe("The logic operator used for the 'regardingOf' filter, always 'eq'."),
  mode: z.literal("or")
    .describe("The combination mode used between the 'regardingOf' filter values, always 'or'."),
}).describe("A filter used to further refine entity filtering based on associated entities and/or relationships.");


export const EntityTypeFilterItem = z.object({
  key: z.literal("entity_type")
    .describe("The key of the entity type filter, always 'entity_type'."),
  values: z.array(EntityTypeEnum)
    .describe("A list of entity type filter values."),
  operator: z.literal("eq")
    .describe("The logic operator used for the entity type filter, always 'eq'."),
  mode: z.literal("or")
    .describe("The combination mode used between the entity type filter values, always 'or'."),
}).describe("A filter used to filter entities by their type as defined by the STIX standard.");


export const ObjectAssigneeFilterItem = z.object({
  key: z.literal("objectAssignee")
    .describe("The key of the assignee filter, always 'objectAssignee'."),
  values: z.array(z.string())
    .describe("A list of assignees."),
  operator: z.literal("eq")
    .describe("The logic operator used for the assignee filter, always 'eq'."),
  mode: z.literal("or")
    .describe("The combination mode between the assignee filter values, always 'or'."),
}).describe("A filter used to filter entities by the name of their assignees.");

export const GenericFilterItem = z.object({
  key: FilterTypeEnum
    .describe("The key of the filter."),
  values: z.array(z.string())
    .describe("A list of filter values."),
  operator: z.literal("eq")
    .describe("The logic operator used for the filter, always 'eq'."),
  mode: z.literal("or")
    .describe("The combination mode between the filter values, always 'or'."),
});


export const OpenCTIFiltersOutput = z.object({
  filters: z.array(z.union([EntityTypeFilterItem, ObjectAssigneeFilterItem, RegardingOfFilterItem, GenericFilterItem]))
    .describe("The list of filters"),
  mode: z.literal("and")
    .describe("The combination mode between the filters, always 'and'."),
  filterGroups: z.array(z.any()).default([]),
});


// create a zod enums
const FilterModeEnum = z.nativeEnum(FilterMode);
const FilterOperatorEnum = z.nativeEnum(FilterOperator);

const FilterSchema = z.object({
  key: FilterTypeEnum
  .describe("The key of the filter."), //z.array(z.string()), // TODO how to validate key (generateFilterKeysSchema)
  mode: FilterModeEnum.optional(),
  operator: FilterOperatorEnum.optional(),
  values: z.array(z.any()),
});

const FilterGroupSchema: z.ZodType<any> = z.lazy(() =>
  z.object({
    filterGroups: z.array(FilterGroupSchema),
    filters: z.array(z.union([EntityTypeFilterItem, ObjectAssigneeFilterItem, RegardingOfFilterItem, FilterSchema])),
    mode: FilterModeEnum,
  })
);

const examples = [
  {
      "input": "Who's is behind this T1497?",
      "output": {
          "mode": "and",
          "filters": [
              {
                  "key": "regardingOf",
                  "operator": "eq",
                  "values": [
                      {
                          "key": "id",
                          "values": [
                              "T1497"
                          ]
                      }
                  ],
                  "mode": "or"
              },
              {
                  "key": "entity_type",
                  "operator": "eq",
                  "values": [
                      "Threat-Actor-Group",
                      "Threat-Actor-Individual",
                      "Intrusion-Set"
                  ],
                  "mode": "or"
              }
          ],
          "filterGroups": []
      }
  },
  {
      "input": "Which threats actors are invovled with T1497?",
      "output": {
          "mode": "and",
          "filters": [
              {
                  "key": "regardingOf",
                  "operator": "eq",
                  "values": [
                      {
                          "key": "id",
                          "values": [
                              "T1497"
                          ]
                      }
                  ],
                  "mode": "or"
              },
              {
                  "key": "entity_type",
                  "operator": "eq",
                  "values": [
                      "Threat-Actor-Group",
                      "Threat-Actor-Individual",
                      "Intrusion-Set"
                  ],
                  "mode": "or"
              }
          ],
          "filterGroups": []
      }
  },
  {
      "input": "T1497に関与している脅威アクターは誰ですか？",
      "output": {
          "mode": "and",
          "filters": [
              {
                  "key": "regardingOf",
                  "operator": "eq",
                  "values": [
                      {
                          "key": "id",
                          "values": [
                              "T1497"
                          ]
                      }
                  ],
                  "mode": "or"
              },
              {
                  "key": "entity_type",
                  "operator": "eq",
                  "values": [
                      "Threat-Actor-Group",
                      "Threat-Actor-Individual",
                      "Intrusion-Set"
                  ],
                  "mode": "or"
              }
          ],
          "filterGroups": []
      }
  },
  {
      "input": "Google TAG COLDRIVER 2024年1月のレポートに含まれている脅威アクターは誰ですか？",
      "output": {
          "mode": "and",
          "filters": [
              {
                  "key": "regardingOf",
                  "operator": "eq",
                  "values": [
                      {
                          "key": "id",
                          "values": [
                              "Google TAG COLDRIVER January 2024"
                          ]
                      }
                  ],
                  "mode": "or"
              },
              {
                  "key": "entity_type",
                  "operator": "eq",
                  "values": [
                      "Intrusion-Set",
                      "Threat-Actor-Group",
                      "Threat-Actor-Individual"
                  ],
                  "mode": "or"
              }
          ],
          "filterGroups": []
      }
  },
  {
      "input": "Who are the actors responsible for T1497 attack?",
      "output": {
          "mode": "and",
          "filters": [
              {
                  "key": "regardingOf",
                  "operator": "eq",
                  "values": [
                      {
                          "key": "id",
                          "values": [
                              "T1497"
                          ]
                      }
                  ],
                  "mode": "or"
              },
              {
                  "key": "entity_type",
                  "operator": "eq",
                  "values": [
                      "Threat-Actor-Group",
                      "Threat-Actor-Individual",
                      "Intrusion-Set"
                  ],
                  "mode": "or"
              }
          ],
          "filterGroups": []
      }
  },
  {
      "input": "Which threats are most likely to target me?",
      "output": {
          "mode": "and",
          "filters": [
              {
                  "key": "regardingOf",
                  "operator": "eq",
                  "values": [
                      {
                          "key": "relationship_type",
                          "values": [
                              "targets"
                          ]
                      }
                  ],
                  "mode": "or"
              },
              {
                  "key": "entity_type",
                  "operator": "eq",
                  "values": [
                      "Threat-Actor-Group",
                      "Threat-Actor-Individual",
                      "Intrusion-Set"
                  ],
                  "mode": "or"
              }
          ],
          "filterGroups": []
      }
  },
  {
      "input": "Agendaによって標的にされた被害者とその業界セクターは何ですか？",
      "output": {
          "mode": "and",
          "filters": [
              {
                  "key": "regardingOf",
                  "operator": "eq",
                  "values": [
                      {
                          "key": "relationship_type",
                          "values": [
                              "targets"
                          ]
                      },
                      {
                          "key": "id",
                          "values": [
                              "Agenda"
                          ]
                      }
                  ],
                  "mode": "or"
              }
          ],
          "filterGroups": []
      }
  },
  {
      "input": "If Russian cybercrime group attacks me, how will they do?",
      "output": {
          "mode": "and",
          "filters": [
              {
                  "key": "regardingOf",
                  "operator": "eq",
                  "values": [
                      {
                          "key": "id",
                          "values": [
                              "Russian cybercrime group"
                          ]
                      },
                      {
                          "key": "relationship_type",
                          "values": [
                              "uses"
                          ]
                      }
                  ],
                  "mode": "or"
              },
              {
                  "key": "entity_type",
                  "operator": "eq",
                  "values": [
                      "Attack-Pattern"
                  ],
                  "mode": "or"
              }
          ],
          "filterGroups": []
      }
  },
  {
      "input": "ロシアのサイバー犯罪グループが私を攻撃する場合、どのように行いますか？",
      "output": {
          "mode": "and",
          "filters": [
              {
                  "key": "regardingOf",
                  "operator": "eq",
                  "values": [
                      {
                          "key": "id",
                          "values": [
                              "Russian cybercrime group"
                          ]
                      },
                      {
                          "key": "relationship_type",
                          "values": [
                              "uses"
                          ]
                      }
                  ],
                  "mode": "or"
              },
              {
                  "key": "entity_type",
                  "operator": "eq",
                  "values": [
                      "Attack-Pattern"
                  ],
                  "mode": "or"
              }
          ],
          "filterGroups": []
      }
  },
  {
      "input": "APT28が使用したマルウェアのリストを教えてください。",
      "output": {
          "mode": "and",
          "filters": [
              {
                  "key": "regardingOf",
                  "operator": "eq",
                  "values": [
                      {
                          "key": "id",
                          "values": [
                              "APT28"
                          ]
                      },
                      {
                          "key": "relationship_type",
                          "values": [
                              "uses"
                          ]
                      }
                  ],
                  "mode": "or"
              },
              {
                  "key": "entity_type",
                  "operator": "eq",
                  "values": [
                      "Malware"
                  ],
                  "mode": "or"
              }
          ],
          "filterGroups": []
      }
  },
  {
      "input": "APT-C-01 (Poison Ivy)に関連するIOCのリストを教えてください。",
      "output": {
          "mode": "and",
          "filters": [
              {
                  "key": "regardingOf",
                  "operator": "eq",
                  "values": [
                      {
                          "key": "id",
                          "values": [
                              "APT-C-01 (Poison Ivy)"
                          ]
                      }
                  ],
                  "mode": "or"
              },
              {
                  "key": "entity_type",
                  "operator": "eq",
                  "values": [
                      "Indicator"
                  ],
                  "mode": "or"
              }
          ],
          "filterGroups": []
      }
  },
  {
      "input": "Does the file named 'example_file' have any associations with known threat actors or cyber threats?",
      "output": {
          "mode": "and",
          "filters": [
              {
                  "key": "entity_type",
                  "operator": "eq",
                  "values": [
                      "Threat-Actor-Group",
                      "Threat-Actor-Individual",
                      "Intrusion-Set"
                  ],
                  "mode": "or"
              },
              {
                  "key": "regardingOf",
                  "operator": "eq",
                  "values": [
                      {
                          "key": "relationship_type",
                          "values": [
                              "related-to"
                          ]
                      },
                      {
                          "key": "id",
                          "values": [
                              "example_file"
                          ]
                      }
                  ],
                  "mode": "or"
              }
          ],
          "filterGroups": []
      }
  },
  {
      "input": "Has there been any historical involvement of XYZ in known cybersecurity incidents?",
      "output": {
          "mode": "and",
          "filters": [
              {
                  "key": "entity_type",
                  "operator": "eq",
                  "values": [
                      "Incident"
                  ],
                  "mode": "or"
              },
              {
                  "key": "regardingOf",
                  "operator": "eq",
                  "values": [
                      {
                          "key": "relationship_type",
                          "values": [
                              "related-to"
                          ]
                      },
                      {
                          "key": "id",
                          "values": [
                              "XYZ"
                          ]
                      }
                  ],
                  "mode": "or"
              }
          ],
          "filterGroups": []
      }
  },
  {
      "input": "List all intelligence reports released by Recorded Future.",
      "output": {
          "mode": "and",
          "filters": [
              {
                  "key": "creator_id",
                  "operator": "eq",
                  "values": [
                      "Recorded Future"
                  ],
                  "mode": "or"
              },
              {
                  "key": "entity_type",
                  "operator": "eq",
                  "values": [
                      "Report"
                  ],
                  "mode": "or"
              }
          ],
          "filterGroups": []
      }
  },
  {
      "input": "List all cybersecurity incidents assigned to John Doe.",
      "output": {
          "mode": "and",
          "filters": [
              {
                  "key": "entity_type",
                  "operator": "eq",
                  "values": [
                      "Incident"
                  ],
                  "mode": "or"
              },
              {
                  "key": "objectAssignee",
                  "operator": "eq",
                  "values": [
                      "John Doe"
                  ],
                  "mode": "or"
              }
          ],
          "filterGroups": []
      }
  },
  {
      "input": "The sun, a radiant beacon in the sky, spread its golden warmth across the horizon, igniting the dawn with an explosion of brilliant color.",
      "output": {"mode": "and", "filters": [], "filterGroups": []}
  }
];

const examplePrompt = ChatPromptTemplate.fromMessages([
  ["human", "{input}"],
  ["ai", "{output}"],
]);

const fewShotPrompt = new FewShotChatMessagePromptTemplate({
  examplePrompt,
  examples,
  inputVariables: [],
});


const systemPrompt = `You are an expert in cybersecurity and OpenCTI query filters. 
    Your task is to extract OpenCTI filters from a given user input,
    which will be used to search for specific entities in the OpenCTI database.

    If the user input is not related to Cyber Threat Intelligence (CTI),
    return: {{"mode":"and","filters":[],"filterGroups":[]}}

    Output the result as valid JSON (strictly matching our FilterGroup schema).
    Do not add any extra text outside the JSON object.
  `;

const promptTemplate = ChatPromptTemplate.fromMessages([
  ["system", systemPrompt],
  fewShotPrompt,
  ["human", "{text}"],
]);


export const generateNLQresponse = async (context: AuthContext, user: AuthUser, args: MutationAiNlqArgs) => {
  await checkEnterpriseEdition(context);
  const { search } = args;

  const llm = new ChatOpenAI({
    modelName: "mistral",
    apiKey: "toekn",
    temperature: 0,
    configuration: {
      baseURL: "https://ai.filigran.io/v1",
    },
    responseFormat: OpenCTIFiltersOutput,
  });

  // const llm = new ChatOpenAI(
  //   Object.assign(llmConfig, { responseFormat: FilterGroupSchema, })
  // );

  const promptValue = await promptTemplate.formatPromptValue({ text: search });

  const rawResponse = await llm.invoke(promptValue)

  let parsedResponse;
  try {
    parsedResponse = JSON.parse(rawResponse.content.toString().replace(/'/g, '"'));
  } catch (error) {
    console.error("Erreur de parsing JSON:", error);
    console.error("Réponse brute:", rawResponse.content);
    return JSON.stringify({ mode: "and", filters: [], filterGroups: [] });
  }

  return JSON.stringify(parsedResponse);
};
