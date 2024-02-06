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
import { STIX_EXT_OCTI } from '../../types/stix-extensions';
export const ENTITY_TYPE_PLAYBOOK = 'Playbook';
export const PlayComponentDefinition = {
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
