import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import {
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CONTAINER_NOTE,
  ENTITY_TYPE_CONTAINER_OPINION,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_DATA_SOURCE,
  ENTITY_TYPE_IDENTITY_INDIVIDUAL,
  ENTITY_TYPE_IDENTITY_SYSTEM,
  ENTITY_TYPE_INCIDENT,
  ENTITY_TYPE_INFRASTRUCTURE,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_THREAT_ACTOR_GROUP,
  ENTITY_TYPE_TOOL
} from '../../schema/stixDomainObject';
import { ENTITY_PERSONA, ENTITY_PROCESS, ENTITY_USER_ACCOUNT } from '../../schema/stixCyberObservable';
import { ENTITY_TYPE_CONTAINER_GROUPING } from '../grouping/grouping-types';
import { ENTITY_TYPE_EVENT } from '../event/event-types';
import { ENTITY_TYPE_CHANNEL } from '../channel/channel-types';
import type { StixObject } from '../../types/stix-common';
import type { VocabularyCategory } from '../../generated/graphql';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../case/case-rfi/case-rfi-types';
import { ENTITY_TYPE_CONTAINER_CASE_RFT } from '../case/case-rft/case-rft-types';
import { ENTITY_TYPE_MALWARE_ANALYSIS } from '../malwareAnalysis/malwareAnalysis-types';
import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT } from '../case/case-incident/case-incident-types';
import { ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL } from '../threatActorIndividual/threatActorIndividual-types';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../organization/organization-types';
import { ENTITY_TYPE_INDICATOR } from '../indicator/indicator-types';

export const ENTITY_TYPE_VOCABULARY = 'Vocabulary';

interface VocabularyDefinition {
  description?: string,
  entity_types: string[],
  fields: {
    key: string,
    required: boolean,
    multiple: boolean,
  }[]
}

export const vocabularyDefinitions: Record<VocabularyCategory, VocabularyDefinition> = {
  // A
  account_type_ov: {
    description: 'An open vocabulary of User Account types',
    entity_types: [ENTITY_USER_ACCOUNT],
    fields: [{
      key: 'account_type',
      required: false,
      multiple: false,
    }]
  },
  attack_motivation_ov: {
    description: `Knowing a Threat Actor or Intrusion Set's motivation may allow an analyst or defender to better understand likely targets and behaviors.
      Motivation shapes the intensity and the persistence of an attack. Threat Actors and Intrusion Sets usually act in a manner that reflects their underlying emotion or situation, and this informs defenders of the manner of attack. For example, a spy motivated by nationalism (ideology) likely has the patience to achieve long-term goals and work quietly for years, whereas a cyber-vandal out for notoriety can create an intense and attention-grabbing attack but may quickly lose interest and move on. Understanding these differences allows defenders to implement controls tailored to each type of attack for greatest efficiency`,
    entity_types: [ENTITY_TYPE_THREAT_ACTOR_GROUP, ENTITY_TYPE_INTRUSION_SET],
    fields: [{
      key: 'primary_motivation',
      required: false,
      multiple: false,
    }, {
      key: 'secondary_motivations',
      required: false,
      multiple: true,
    }, {
      key: 'personal_motivations',
      required: false,
      multiple: true,
    }]
  },
  attack_resource_level_ov: {
    description: 'Attack Resource Level is an open vocabulary that captures the general level of resources that a threat actor, intrusion set, or campaign might have access to. It ranges from individual, a person acting alone, to government, the resources of a national government',
    entity_types: [ENTITY_TYPE_THREAT_ACTOR_GROUP, ENTITY_TYPE_INTRUSION_SET],
    fields: [{
      key: 'resource_level',
      required: false,
      multiple: false,
    }]
  },
  // C
  case_severity_ov: {
    entity_types: [ENTITY_TYPE_CONTAINER_CASE_INCIDENT, ENTITY_TYPE_CONTAINER_CASE_RFI, ENTITY_TYPE_CONTAINER_CASE_RFT], // Fill entire list
    fields: [{
      key: 'severity',
      required: false,
      multiple: false,
    }]
  },
  case_priority_ov: {
    entity_types: [ENTITY_TYPE_CONTAINER_CASE_INCIDENT, ENTITY_TYPE_CONTAINER_CASE_RFI, ENTITY_TYPE_CONTAINER_CASE_RFT], // Fill entire list
    fields: [{
      key: 'priority',
      required: false,
      multiple: false,
    }]
  },
  channel_types_ov: {
    entity_types: [ENTITY_TYPE_CHANNEL],
    fields: [{
      key: 'channel_types',
      required: false,
      multiple: true,
    }]
  },
  collection_layers_ov: {
    entity_types: [ENTITY_TYPE_DATA_SOURCE],
    fields: [{
      key: 'collection_layers',
      required: false,
      multiple: true,
    }]
  },
  // E
  event_type_ov: {
    entity_types: [ENTITY_TYPE_EVENT],
    fields: [{
      key: 'event_types',
      required: false,
      multiple: true,
    }]
  },
  // G
  grouping_context_ov: {
    description: 'While the majority of this vocabulary is undefined (producers may use custom vocabulary entries), it has been added specifically to capture the suspicious-activity-event value. That value indicates that the information contained in the Grouping relates to a suspicious event',
    entity_types: [ENTITY_TYPE_CONTAINER_GROUPING],
    fields: [{
      key: 'context',
      required: true,
      multiple: false,
    }]
  },
  // I
  implementation_language_ov: {
    description: 'This is a non-exhaustive, open vocabulary that covers common programming languages and is intended to characterize the languages that may have been used to implement a malware instance or family',
    entity_types: [ENTITY_TYPE_MALWARE],
    fields: [{
      key: 'implementation_languages',
      required: false,
      multiple: true,
    }]
  },
  incident_response_types_ov: {
    entity_types: [ENTITY_TYPE_CONTAINER_CASE_INCIDENT],
    fields: [{
      key: 'response_types',
      required: false,
      multiple: true,
    }]
  },
  incident_type_ov: {
    entity_types: [ENTITY_TYPE_INCIDENT],
    fields: [{
      key: 'incident_type',
      required: false,
      multiple: false,
    }],
  },
  incident_severity_ov: {
    entity_types: [ENTITY_TYPE_INCIDENT],
    fields: [{
      key: 'severity',
      required: false,
      multiple: false,
    }],
  },
  indicator_type_ov: {
    description: 'Indicator type is an open vocabulary used to categorize Indicators. It is intended to be high-level to promote consistent practices. Indicator types should not be used to capture information that can be better captured via related Malware or Attack Pattern objects. It is better to link an Indicator to a Malware object describing Poison Ivy rather than simply providing a type or label of "poison-ivy"',
    entity_types: [ENTITY_TYPE_INDICATOR],
    fields: [{
      key: 'indicator_types',
      required: false,
      multiple: true,
    }]
  },
  infrastructure_type_ov: {
    description: 'A non-exhaustive enumeration of infrastructure types',
    entity_types: [ENTITY_TYPE_INFRASTRUCTURE],
    fields: [{
      key: 'infrastructure_types',
      required: false,
      multiple: true,
    }]
  },
  integrity_level_ov: {
    description: 'Windows integrity levels are a security feature and represent the trustworthiness of an object',
    entity_types: [ENTITY_PROCESS],
    fields: [{
      key: 'integrity_level',
      required: false,
      multiple: false,
    }],
  },
  // M
  malware_capabilities_ov: {
    description: 'This is an open vocabulary that covers common capabilities that may be exhibited by a malware instance or family',
    entity_types: [ENTITY_TYPE_MALWARE],
    fields: [{
      key: 'capabilities',
      required: false,
      multiple: true,
    }]
  },
  malware_result_ov: {
    description: 'This is a non-exhaustive, open vocabulary that captures common types of scanner or tool analysis process results.',
    entity_types: [ENTITY_TYPE_MALWARE_ANALYSIS],
    fields: [{
      key: 'result',
      required: false,
      multiple: false,
    }]
  },
  malware_type_ov: {
    description: 'Malware type is an open vocabulary that represents different types and functions of malware. Malware types are not mutually exclusive; for example, a malware instance can be both spyware and a screen capture tool',
    entity_types: [ENTITY_TYPE_MALWARE],
    fields: [{
      key: 'malware_types',
      required: false,
      multiple: true,
    }]
  },
  // N
  note_types_ov: {
    entity_types: [ENTITY_TYPE_CONTAINER_NOTE],
    fields: [{
      key: 'note_types',
      required: false,
      multiple: true,
    }]
  },
  // O
  opinion_ov: {
    description: 'This enumeration captures a degree of agreement with the information in a STIX Object. It is an ordered enumeration, with the earlier terms representing disagreement, the middle term neutral, and the later terms representing agreement',
    entity_types: [ENTITY_TYPE_CONTAINER_OPINION],
    fields: [{
      key: 'opinion',
      required: true,
      multiple: false,
    }]
  },
  organization_type_ov: {
    description: 'The various types of organizations playing a role in CTI, whether as a source of information or as a victim or source of attack, or even a way t segregate users in the platform.',
    entity_types: [ENTITY_TYPE_IDENTITY_ORGANIZATION],
    fields: [{
      key: 'x_opencti_organization_type',
      required: false,
      multiple: false,
    }]
  },
  // P
  platforms_ov: {
    entity_types: [ENTITY_TYPE_DATA_SOURCE, ENTITY_TYPE_INDICATOR, ENTITY_TYPE_ATTACK_PATTERN],
    fields: [{
      key: 'x_mitre_platforms',
      required: false,
      multiple: true,
    }]
  },
  pattern_type_ov: {
    description: 'This is a non-exhaustive, open vocabulary that covers common pattern languages and is intended to characterize the pattern language that the indicator pattern is expressed in',
    entity_types: [ENTITY_TYPE_INDICATOR],
    fields: [{
      key: 'pattern_type',
      required: true,
      multiple: false,
    }]
  },
  processor_architecture_ov: {
    description: 'This is a non-exhaustive, open vocabulary that covers common processor architectures and is intended to characterize the architectures that a malware instance or family may be able to execute on',
    entity_types: [ENTITY_TYPE_MALWARE],
    fields: [{
      key: 'architecture_execution_envs',
      required: false,
      multiple: true,
    }]
  },
  permissions_ov: {
    entity_types: [ENTITY_TYPE_ATTACK_PATTERN],
    fields: [{
      key: 'x_mitre_permissions_required',
      required: false,
      multiple: true,
    }]
  },
  persona_type_ov: {
    entity_types: [ENTITY_PERSONA],
    fields: [{
      key: 'persona_type',
      required: false,
      multiple: false,
    }],
  },
  // R
  reliability_ov: {
    description: 'Reliability is an open vocabulary based on Admiralty code used to assess the reliability of a source.',
    entity_types: [ENTITY_TYPE_CONTAINER_REPORT, ENTITY_TYPE_IDENTITY_ORGANIZATION, ENTITY_TYPE_IDENTITY_INDIVIDUAL, ENTITY_TYPE_IDENTITY_SYSTEM],
    fields: [{
      key: 'x_opencti_reliability',
      required: false,
      multiple: false,
    }]
  },
  report_types_ov: {
    description: 'Report type is an open vocabulary to describe the primary purpose or subject of a report. For example, a report that contains malware and indicators for that malware should have a report type of malware to capture that the malware is the primary purpose. Report types are not mutually exclusive: a Report can be both a malware report and a tool report. Just because a report contains objects of a type does not mean that the report should include that type. If the objects are there to simply provide evidence or context for other objects, it is not necessary to include them in the type',
    entity_types: [ENTITY_TYPE_CONTAINER_REPORT],
    fields: [{
      key: 'report_types',
      required: false,
      multiple: true,
    }]
  },
  request_for_information_types_ov: {
    description: '',
    entity_types: [ENTITY_TYPE_CONTAINER_CASE_RFI],
    fields: [{
      key: 'information_types',
      required: false,
      multiple: true,
    }]
  },
  request_for_takedown_types_ov: {
    description: '',
    entity_types: [ENTITY_TYPE_CONTAINER_CASE_RFT],
    fields: [{
      key: 'takedown_types',
      required: false,
      multiple: true,
    }]
  },
  // S
  service_status_ov: {
    description: 'An enumeration of Windows service statuses',
    entity_types: [ENTITY_PROCESS],
    fields: [{
      key: 'service_status',
      required: false,
      multiple: false,
    }],
  },
  service_type_ov: {
    description: 'An enumeration of Windows service types',
    entity_types: [ENTITY_PROCESS],
    fields: [{
      key: 'service_type',
      required: false,
      multiple: false,
    }],
  },
  start_type_ov: {
    description: 'An enumeration of Windows service start types',
    entity_types: [ENTITY_PROCESS],
    fields: [{
      key: 'start_type',
      required: false,
      multiple: false,
    }],
  },
  // T
  threat_actor_group_type_ov: {
    description: 'Threat actor type is an open vocabulary used to describe what type of threat actor group is. For example, some threat actors groups are competitors who try to steal information, while others are activists who act in support of a social or political cause. Actor types are not mutually exclusive: a threat actor group can be both a disgruntled insider and a spy. [Casey 2007])',
    entity_types: [ENTITY_TYPE_THREAT_ACTOR_GROUP],
    fields: [{
      key: 'threat_actor_types',
      required: false,
      multiple: true,
    }]
  },
  threat_actor_group_role_ov: {
    description: `Threat actor group role is an open vocabulary that is used to describe the different roles that a threat actor group can play. For example, some threat actors groups author malware or operate botnets while other actors actually carry out attacks directly
      Threat actor group roles are not mutually exclusive. For example, an actor can be both a financial backer for attacks and also direct attacks`,
    entity_types: [ENTITY_TYPE_THREAT_ACTOR_GROUP],
    fields: [{
      key: 'roles',
      required: false,
      multiple: true,
    }]
  },
  threat_actor_group_sophistication_ov: {
    description: 'Threat actor group sophistication vocabulary captures the skill level of a threat actor group. It ranges from "none", which describes a complete novice, to "strategic", which describes an attacker who is able to influence supply chains to introduce vulnerabilities. This vocabulary is separate from resource level because an innovative, highly-skilled threat actor group may have access to very few resources while a minimal-level actor might have the resources of an organized crime ring',
    entity_types: [ENTITY_TYPE_THREAT_ACTOR_GROUP],
    fields: [{
      key: 'sophistication',
      required: false,
      multiple: false,
    }]
  },
  threat_actor_individual_type_ov: {
    description: 'Threat actor individual type is an open vocabulary used to describe what type of threat actor the individual is. For example, some threat actors individuals are competitors who try to steal information, while others are activists who act in support of a social or political cause. Actor types are not mutually exclusive: a threat actor individual can be both a disgruntled insider and a spy. [Casey 2007])',
    entity_types: [ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL],
    fields: [{
      key: 'threat_actor_types',
      required: false,
      multiple: true,
    }]
  },
  threat_actor_individual_role_ov: {
    description: `Threat actor individual role is an open vocabulary that is used to describe the different roles that a threat actor individual can play. For example, some threat actors individuals author malware or operate botnets while other actors actually carry out attacks directly
      Threat actor individual roles are not mutually exclusive. For example, an actor can be both a financial backer for attacks and also direct attacks`,
    entity_types: [ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL],
    fields: [{
      key: 'roles',
      required: false,
      multiple: true,
    }]
  },
  threat_actor_individual_sophistication_ov: {
    description: 'Threat actor individual sophistication vocabulary captures the skill level of a threat actor individual. It ranges from "none", which describes a complete novice, to "strategic", which describes an attacker who is able to influence supply chains to introduce vulnerabilities. This vocabulary is separate from resource level because an innovative, highly-skilled threat actor individual may have access to very few resources while a minimal-level actor might have the resources of an organized crime ring',
    entity_types: [ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL],
    fields: [{
      key: 'sophistication',
      required: false,
      multiple: false,
    }]
  },
  tool_types_ov: {
    description: 'Tool types describe the categories of tools that can be used to perform attacks',
    entity_types: [ENTITY_TYPE_TOOL],
    fields: [{
      key: 'tool_types',
      required: false,
      multiple: true,
    }]
  },
  gender_ov: {
    description: 'Gender describes the characteristics of men and women that are socially constructed. The definition of gender varies from society to society and can change over time.',
    entity_types: [ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL],
    fields: [{
      key: 'gender',
      required: false,
      multiple: false,
    }],
  },
  marital_status_ov: {
    description: 'Marital status describes the state of an intimate relationship a person has with one or more people, or none at all.',
    entity_types: [ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL],
    fields: [{
      key: 'marital_status',
      required: false,
      multiple: false,
    }],
  },
  hair_color_ov: {
    description: 'The color of a person\'s hair.',
    entity_types: [ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL],
    fields: [{
      key: 'hair_color',
      required: false,
      multiple: false,
    }],
  },
  eye_color_ov: {
    description: 'The color of a person\'s eyes.',
    entity_types: [ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL],
    fields: [{
      key: 'eye_color',
      required: false,
      multiple: false,
    }],
  },
};

// region Database types
export interface BasicStoreEntityVocabulary extends BasicStoreEntity {
  name: string;
  description: string;
  category: VocabularyCategory;
  builtIn?: boolean;
}

export interface StoreEntityVocabulary extends StoreEntity {
  name: string;
  description: string;
  category: VocabularyCategory;
  builtIn?: boolean;
}

// region Stix type
export interface StixVocabulary extends StixObject {
  name: string
  aliases: string[]
  description?: string
  category: VocabularyCategory
}

// endregion
