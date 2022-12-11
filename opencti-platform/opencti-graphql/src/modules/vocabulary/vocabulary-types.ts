import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import {
  ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_CONTAINER_OPINION,
  ENTITY_TYPE_CONTAINER_REPORT, ENTITY_TYPE_DATA_SOURCE,
  ENTITY_TYPE_INDICATOR,
  ENTITY_TYPE_INFRASTRUCTURE,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_THREAT_ACTOR,
  ENTITY_TYPE_TOOL
} from '../../schema/stixDomainObject';
import { ENTITY_PROCESS, ENTITY_USER_ACCOUNT } from '../../schema/stixCyberObservable';
import { ENTITY_TYPE_CONTAINER_GROUPING } from '../grouping/grouping-types';
import { ENTITY_TYPE_EVENT } from '../event/event-types';
import { ENTITY_TYPE_CHANNEL } from '../channel/channel-types';
import type { StixObject } from '../../types/stix-common';
import type { VocabularyCategory } from '../../generated/graphql';

export const ENTITY_TYPE_VOCABULARY = 'Vocabulary';

interface VocabularyDefinition {
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
    entity_types: [ENTITY_USER_ACCOUNT],
    fields: [{
      key: 'account_type',
      required: false,
      multiple: false,
    }]
  },
  attack_resource_level_ov: {
    entity_types: [ENTITY_TYPE_THREAT_ACTOR, ENTITY_TYPE_INTRUSION_SET],
    fields: [{
      key: 'resource_level',
      required: false,
      multiple: false,
    }]
  },
  attack_motivation_ov: {
    entity_types: [ENTITY_TYPE_THREAT_ACTOR, ENTITY_TYPE_INTRUSION_SET],
    fields: [{
      key: 'primary_motivation',
      required: false,
      multiple: false,
    }, {
      key: 'secondary_motivations',
      required: false,
      multiple: true,
    }, {
      key: 'personnal_motivations',
      required: false,
      multiple: true,
    }]
  },
  // C
  channel_types_ov: {
    entity_types: [ENTITY_TYPE_CHANNEL],
    fields: [{
      key: 'channel_types',
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
    entity_types: [ENTITY_TYPE_CONTAINER_GROUPING],
    fields: [{
      key: 'context',
      required: true,
      multiple: false,
    }]
  },
  // I
  implementation_language_ov: {
    entity_types: [ENTITY_TYPE_MALWARE],
    fields: [{
      key: 'implementation_languages',
      required: false,
      multiple: true,
    }]
  },
  indicator_type_ov: {
    entity_types: [ENTITY_TYPE_INDICATOR],
    fields: [{
      key: 'indicator_types',
      required: false,
      multiple: true,
    }]
  },
  infrastructure_type_ov: {
    entity_types: [ENTITY_TYPE_INFRASTRUCTURE],
    fields: [{
      key: 'infrastructure_types',
      required: false,
      multiple: true,
    }]
  },
  integrity_level_ov: {
    entity_types: [ENTITY_PROCESS],
    fields: [{
      key: 'integrity_level',
      required: false,
      multiple: false,
    }],
  },
  // M
  malware_capabilities_ov: {
    entity_types: [ENTITY_TYPE_MALWARE],
    fields: [{
      key: 'capabilities',
      required: false,
      multiple: true,
    }]
  },
  malware_type_ov: {
    entity_types: [ENTITY_TYPE_MALWARE],
    fields: [{
      key: 'malware_types',
      required: false,
      multiple: true,
    }]
  },
  // O
  opinion_ov: {
    entity_types: [ENTITY_TYPE_CONTAINER_OPINION],
    fields: [{
      key: 'opinion',
      required: true,
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
  collection_layers_ov: {
    entity_types: [ENTITY_TYPE_DATA_SOURCE],
    fields: [{
      key: 'collection_layers',
      required: false,
      multiple: true,
    },
    { // For backward compatibility in python
      key: 'x_mitre_collection_layers',
      required: false,
      multiple: true,
    }]
  },
  pattern_type_ov: {
    entity_types: [ENTITY_TYPE_INDICATOR],
    fields: [{
      key: 'pattern_type',
      required: true,
      multiple: false,
    }]
  },
  processor_architecture_ov: {
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
  // R
  report_types_ov: {
    entity_types: [ENTITY_TYPE_CONTAINER_REPORT],
    fields: [{
      key: 'report_types',
      required: false,
      multiple: true,
    }]
  },
  // S
  service_status_ov: {
    entity_types: [ENTITY_PROCESS],
    fields: [{
      key: 'service_status',
      required: false,
      multiple: false,
    }],
  },
  service_type_ov: {
    entity_types: [ENTITY_PROCESS],
    fields: [{
      key: 'service_type',
      required: false,
      multiple: false,
    }],
  },
  start_type_ov: {
    entity_types: [ENTITY_PROCESS],
    fields: [{
      key: 'start_type',
      required: false,
      multiple: false,
    }],
  },
  // T
  threat_actor_type_ov: {
    entity_types: [ENTITY_TYPE_THREAT_ACTOR],
    fields: [{
      key: 'threat_actor_types',
      required: false,
      multiple: true,
    }]
  },
  threat_actor_role_ov: {
    entity_types: [ENTITY_TYPE_THREAT_ACTOR],
    fields: [{
      key: 'roles',
      required: false,
      multiple: true,
    }]
  },
  threat_actor_sophistication_ov: {
    entity_types: [ENTITY_TYPE_THREAT_ACTOR],
    fields: [{
      key: 'sophistication',
      required: false,
      multiple: false,
    }]
  },
  tool_types_ov: {
    entity_types: [ENTITY_TYPE_TOOL],
    fields: [{
      key: 'tool_types',
      required: false,
      multiple: true,
    }]
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
  builtIn: boolean;
}

// endregion
