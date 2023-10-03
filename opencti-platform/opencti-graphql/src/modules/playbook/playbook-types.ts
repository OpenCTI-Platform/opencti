/*
Copyright (c) 2021-2023 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Non-Commercial License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

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
  playbook_running: boolean
  playbook_definition: string
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
  icon: string
  is_entry_point: boolean
  is_internal: boolean
  ports: PortDefinition[]
  configuration_schema: JSONSchemaType<T> | undefined
  executor: (parameters: ExecutorParameters<T>) => Promise<PlaybookExecution>
}

export interface PortDefinition {
  id: string
  type: 'in' | 'out'
}

export interface NodeDefinition {
  id: string,
  name: string,
  position: { x: number, y: number },
  component_id: string,
  configuration: string // json
}

export interface LinkDefinition {
  id: string,
  from: {
    port: string,
    id: string
  },
  to: {
    id: string
  }
}

export interface ComponentDefinition {
  nodes: NodeDefinition[]
  links: LinkDefinition[]
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
          name: { type: 'string' },
          position: {
            type: 'object',
            properties: {
              x: { type: 'number' },
              y: { type: 'number' }
            },
            required: ['x', 'y']
          },
          component_id: { type: 'string' },
          configuration: { type: 'string' },
        },
        required: ['id', 'name', 'position', 'component_id', 'configuration'],
      },
    },
    links: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string' },
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
        required: ['id', 'from', 'to'],
      },
    },
  },
  required: ['nodes', 'links'],
};
