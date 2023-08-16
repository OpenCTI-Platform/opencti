import type { JSONSchemaType } from 'ajv';
import type { StixObject, StixCoreObject, StixOpenctiExtensionSDO } from '../../types/stix-common';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import type { BasicStoreEntity, StoreEntity } from '../../types/store';

export const ENTITY_TYPE_PLAYBOOK = 'Playbook';

export interface BasicStoreEntityPlaybook extends BasicStoreEntity {
  internal_id: string
  name: string
  description: string
  playbook_start: string
  playbook_definition: string
  playbook_variables: string[]
}

export interface StoreEntityPlaybook extends StoreEntity {
  name: string
  description: string
}

export interface StixPlaybook extends StixObject {
  name: string
  description: string
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO
  }
}

export interface PlaybookComponentConfiguration {}

export interface NodeInstance<T> {
  id: string
  component_id: string
  configuration: T
}

export interface PlaybookExecution { output_port: string | undefined, data: StixCoreObject }

export interface ExecutorParameters<T> { playbookRunId: string, instance: NodeInstance<T>, data: StixCoreObject }

export interface PlaybookComponent<T extends PlaybookComponentConfiguration> {
  id: string
  name: string
  description: string
  is_entry_point: boolean
  is_internal: boolean
  ports: PortDefinition[]
  configuration_schema: JSONSchemaType<T> | undefined
  executor: (parameters: ExecutorParameters<T>) => Promise<PlaybookExecution>
}

export interface PortDefinition {
  id: string
  type: 'in' | 'out' | 'empty'
}

export interface ComponentDefinition {
  nodes: {
    id: string,
    component_id: string,
    configuration: object
  }[]
  links: {
    from: {
      port: string,
      id: string
    },
    to: {
      id: string
    }
  }[]
}

export const PlayComponentDefinition: JSONSchemaType<ComponentDefinition> = {
  type: 'object',
  properties: {
    nodes: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          component_id: { type: 'string' },
          configuration: { type: 'object' },
        },
        required: ['id', 'component_id', 'configuration'],
      },
    },
    links: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          from: {
            type: 'object',
            properties: {
              id: { type: 'string' },
              port: { type: 'string' },
            },
            required: ['id', 'port']
          },
          to: {
            type: 'object',
            properties: {
              id: { type: 'string' },
            },
            required: ['id']
          },
        },
        required: ['from', 'to'],
      },
    },
  },
  required: ['nodes', 'links'],
};
