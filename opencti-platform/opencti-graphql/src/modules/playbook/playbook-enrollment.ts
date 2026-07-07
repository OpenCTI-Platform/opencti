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

import type { FilterGroup } from '../../generated/graphql';
import type { StixObject as Stix21Object } from '../../types/stix-2-1-common';
import type { StixObject as Stix20Object } from '../../types/stix-2-0-common';
import type { BasicStoreEntityPlaybook, ComponentDefinition } from './playbook-types';
import type { StreamConfiguration } from './playbook-components';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';

export type StixEntity = Stix21Object | Stix20Object;

export const ENROLLMENT_PLAYBOOK_EVALUATION_LIMIT = 5000;

export interface EligiblePlaybook {
  playbook: BasicStoreEntityPlaybook;
  jsonFilters: FilterGroup | null;
}

export type StixFilterMatchFn = (
  stixEntity: StixEntity,
  filters: FilterGroup,
) => Promise<boolean>;

const MANUAL_ENROLLMENT_TRIGGERS = new Set([
  'PLAYBOOK_INTERNAL_DATA_STREAM',
  'PLAYBOOK_INTERNAL_MANUAL_TRIGGER',
]);

export const getEnrollmentEligibility = (
  playbook: BasicStoreEntityPlaybook,
): EligiblePlaybook | null => {
  if (!playbook.playbook_definition) return null;

  const def = JSON.parse(playbook.playbook_definition) as ComponentDefinition;
  const startNode = def.nodes.find((n) => n.id === playbook.playbook_start);
  if (!startNode) return null;

  if (!MANUAL_ENROLLMENT_TRIGGERS.has(startNode.component_id)) return null;

  const config = JSON.parse(startNode.configuration ?? '{}') as StreamConfiguration;
  if (!(config.canEnrollManually ?? true)) return null;

  const jsonFilters: FilterGroup | null = config.filters
    ? JSON.parse(config.filters) as FilterGroup
    : null;

  if (jsonFilters === null) return { playbook, jsonFilters: null };
  return { playbook, jsonFilters };
};

export const allEntitiesMatchFilters = async (
  stixEntities: StixEntity[],
  filters: FilterGroup,
  isEntityMatchingFilterGroup: StixFilterMatchFn,
): Promise<boolean> => {
  for (const entity of stixEntities) {
    const matches = await isEntityMatchingFilterGroup(entity, filters);
    if (!matches) return false;
  }
  return true;
};

export const matchPlaybooksToEntities = async (
  eligiblePlaybooks: EligiblePlaybook[],
  stixEntities: StixEntity[],
  isEntityMatchingFilterGroup: StixFilterMatchFn,
): Promise<BasicStoreEntityPlaybook[]> => {
  const result: BasicStoreEntityPlaybook[] = [];
  for (const { playbook, jsonFilters } of eligiblePlaybooks) {
    if (jsonFilters === null) {
      result.push(playbook);
      continue;
    }
    const allMatch = await allEntitiesMatchFilters(stixEntities, jsonFilters, isEntityMatchingFilterGroup);
    if (allMatch) result.push(playbook);
  }
  return result;
};

export const excludeEntitiesByIds = (entities: Stix21Object[], excludedIds: string[]): Stix21Object[] => {
  if (excludedIds.length === 0) return entities;
  return entities.filter((entity) => {
    const internalId = entity.extensions[STIX_EXT_OCTI]?.id;
    return internalId ? !excludedIds.includes(internalId) : true;
  });
};
