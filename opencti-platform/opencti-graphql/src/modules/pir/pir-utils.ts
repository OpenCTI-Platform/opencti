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

import { now } from 'moment';
import { type BasicStoreEntityPir, type BasicStoreRelationPir, ENTITY_TYPE_PIR, type ParsedPir, type PirExplanation } from './pir-types';
import type { AuthContext, AuthUser } from '../../types/user';
import { listRelationsPaginated, storeLoadById } from '../../database/middleware-loader';
import { RELATION_IN_PIR } from '../../schema/stixRefRelationship';
import { FunctionalError } from '../../config/errors';
import { createRelation, patchAttribute } from '../../database/middleware';
import { type FilterGroup, type PirAddInput, PirType } from '../../generated/graphql';
import { addFilter } from '../../utils/filtering/filtering-utils';
import { ENTITY_TYPE_CAMPAIGN, ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_MALWARE } from '../../schema/stixDomainObject';
import { ABSTRACT_STIX_DOMAIN_OBJECT, ENTITY_TYPE_THREAT_ACTOR } from '../../schema/general';
import { RELATION_FROM_TYPES_FILTER } from '../../utils/filtering/filtering-constants';
import { elUpdate } from '../../database/engine';
import { INDEX_STIX_DOMAIN_OBJECTS } from '../../database/utils';
import type { BasicStoreEntity } from '../../types/store';

/**
 * Helper function to parse filters that are saved as string in elastic.
 *
 * @param pir The Pir to parse.
 * @returns Pir with parsed filters.
 */
export const parsePir = (pir: BasicStoreEntityPir): ParsedPir => {
  return {
    ...pir,
    pir_filters: JSON.parse(pir.pir_filters),
    pir_criteria: pir.pir_criteria.map((c) => ({
      ...c,
      filters: JSON.parse(c.filters),
    })),
  };
};

/**
 * Helper function to parse filters that are saved as string in elastic.
 *
 * @param pir The Pir to parse.
 * @returns Pir with parsed filters.
 */
export const serializePir = (pir: PirAddInput) => {
  return {
    ...pir,
    pir_filters: JSON.stringify(pir.pir_filters),
    pir_criteria: pir.pir_criteria.map((c) => ({
      ...c,
      filters: JSON.stringify(c.filters),
    })),
  };
};

/**
 * Helper function to construct final pir filters that the entity of the stream events should match.
 *
 * @param pirType The PIR type
 * @params pirFilters the PIR filters
 * @returns filters applied on the entity of the stream events
 */
export const constructFinalPirFilters = (pirType: PirType, pirFilters: FilterGroup) => {
  if (pirType === PirType.ThreatLandscape) {
    return addFilter(
      pirFilters,
      RELATION_FROM_TYPES_FILTER,
      [ENTITY_TYPE_CAMPAIGN, ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_THREAT_ACTOR, ENTITY_TYPE_MALWARE],
    );
  }
  return pirFilters;
};

/**
 * Determines the score of an array of explanations against a PIR.
 *
 * @param context
 * @param user
 * @param pirId ID of the PIR to check the score.
 * @param explanations List of explanations used to compute score.
 * @returns An integer between 0 and 100.
 */
export const computePirScore = async (context: AuthContext, user: AuthUser, pirId: string, explanations: PirExplanation[]) => {
  const pir = await storeLoadById<BasicStoreEntityPir>(context, user, pirId, ENTITY_TYPE_PIR);
  const maxScore = pir.pir_criteria.reduce((acc, val) => acc + val.weight, 0);
  const depScore = explanations.reduce((acc, val) => acc + val.criterion.weight, 0);
  if (maxScore <= 0) return 0;
  return Math.round((depScore / maxScore) * 100);
};

/**
 * Update directly pir_information on a stix domain object via an elastic query
 *
 * @param context
 * @param user
 * @param entityId ID of the stix domain object
 * @param pirId ID of the PIR whose score should be updated
 * @param score The new information of the entity for the PIR
 * @return a Promise object with PIR information on an entity
 */
export const updatePirInformationOnEntity = async (context: AuthContext, user: AuthUser, entityId: string, pirId: string, score: number) => {
  const stixDomainObject = await storeLoadById<BasicStoreEntity>(context, user, entityId, ABSTRACT_STIX_DOMAIN_OBJECT);
  const initialInformation = stixDomainObject.pir_information ?? [];
  const newInformation = initialInformation.filter((s) => s.pir_id !== pirId);
  if (score > 0) {
    newInformation.push({ pir_id: pirId, pir_score: score, last_pir_score_date: new Date() });
  }
  const params = { pir_information: newInformation };
  const source = 'ctx._source.pir_information = params.pir_information;';
  // call elUpdate directly to avoid generating stream events and modifying the updated_at of the entity
  return elUpdate(INDEX_STIX_DOMAIN_OBJECTS, entityId, { script: { source, lang: 'painless', params } });
};

/**
 * Determines if two explanations are identical or not.
 *
 * @param explanation1 First explanation.
 * @param explanation2 Second explanation.
 * @returns True if they are the same.
 */
export const arePirExplanationsEqual = (
  explanation1: PirExplanation,
  explanation2: PirExplanation
) => {
  const sameRelationships = explanation1.dependencies.map((d1) => d1.element_id)
    .every((d) => explanation2.dependencies.map((d2) => d2.element_id).includes(d));
  const sameRelationshipsAuthors = explanation1.dependencies.map((d1) => d1.author_id)
    .every((d) => explanation2.dependencies.map((d2) => d2.author_id).includes(d));
  const sameCriteriaWeight = explanation1.criterion.weight === explanation2.criterion.weight;
  const sameCriteriaFilters = explanation1.criterion.filters === explanation2.criterion.filters;
  return sameRelationships && sameRelationshipsAuthors && sameCriteriaWeight && sameCriteriaFilters;
};

/**
 * Compare an array of explanations with another array to kept only new explanations.
 *
 * @param explanations Array to filter.
 * @param baseExplanations Base array to make the comparison.
 * @returns A sub-array of the first argument containing only explanations that are not in the base array.
 */
export const diffPirExplanations = (
  explanations: PirExplanation[],
  baseExplanations: PirExplanation[]
) => {
  return explanations.filter((explanation) => {
    // For each explanation, check it is different from all explanations in base.
    return baseExplanations.every((e) => !arePirExplanationsEqual(explanation, e));
  });
};

/**
 * Update an array of pir explanations by adding the new information
 *
 * @param actualExplanations Explanations of the pir meta rel
 * @param newExplanations New explanations information to add
 * @returns an array of pir explanations updated with the new information
 */
export const updatePirExplanationsArray = (
  actualExplanations: PirExplanation[],
  newExplanations: PirExplanation[],
) => {
  return [
    ...actualExplanations.filter((e) => { // remove explanations concerning the same relationship as new explanations
      return newExplanations.every((newE) => {
        const sameRelationships = e.dependencies.map((d1) => d1.element_id)
          .every((d) => newE.dependencies.map((d2) => d2.element_id).includes(d));
        return !sameRelationships;
      });
    }),
    ...newExplanations
  ];
};

/**
 * Find a meta relationship "in-pir" between an entity and a Pir and update
 * its explanations (matching criteria).
 *
 * @param context To be able to make the calls.
 * @param user User calling the request.
 * @param sourceId ID of the source entity matching the Pir.
 * @param pirId The if of the Pir matched by the entity.
 * @param pirExplanations The new explanations
 * @param operation The edit operation (add, replace, ...).
 */
export const updatePirExplanations = async (
  context: AuthContext,
  user: AuthUser,
  sourceId: string,
  pirId: string,
  pirExplanations: PirExplanation[],
  operation?: string, // 'add' to add a new dependency, 'replace' by default
) => {
  const pirMetaRels = await listRelationsPaginated<BasicStoreRelationPir>(context, user, RELATION_IN_PIR, { fromId: sourceId, toId: pirId, });
  if (pirMetaRels.edges.length === 0) {
    // If = 0 then the meta relationship does not exist.
    throw FunctionalError('Relation between the entity and a Pir not found', { sourceId, pirId, pirMetaRels });
  }
  if (pirMetaRels.edges.length > 1) {
    // If > 1, well this case should not be possible at all.
    throw FunctionalError('Find more than one relation between an entity and a Pir', { sourceId, pirId, pirMetaRels });
  }

  const pirMetaRel = pirMetaRels.edges[0].node;
  let explanations = pirExplanations; // Default case : replace the entire array.
  if (operation === 'add') { // Add case: add the new information contained in pirExplanations
    const newExplanations = diffPirExplanations(pirExplanations, pirMetaRel.pir_explanations);
    if (newExplanations.length === 0) {
      // In this case there is nothing to add so skip.
      return;
    }
    explanations = updatePirExplanationsArray(pirMetaRel.pir_explanations, newExplanations);
  }

  // compute score
  const pir_score = await computePirScore(context, user, pirId, explanations);
  // replace pir_explanations
  await patchAttribute(context, user, pirMetaRel.id, RELATION_IN_PIR, { pir_explanations: explanations, pir_score });
  // update pir score on the entity
  await updatePirInformationOnEntity(context, user, sourceId, pirId, pir_score);
};

/**
 * Flag the source of the relationship by creating a meta relationship 'in-pir'
 * between the source and the PIR.
 *
 * @param context To be able to create the relationship.
 * @param user User calling the request.
 * @param sourceId ID of the source of the rel.
 * @param pirId The ID of the PIR.
 * @param pirDependencies Criteria matched by the relationship.
 */
export const createPirRel = async (
  context: AuthContext,
  user: AuthUser,
  sourceId: string,
  pirId: string,
  pirDependencies: PirExplanation[],
) => {
  // compute score
  const pir_score = await computePirScore(context, user, pirId, pirDependencies);
  // create the in-pir meta rel
  const addRefInput = {
    relationship_type: RELATION_IN_PIR,
    fromId: sourceId,
    toId: pirId,
    pir_explanations: pirDependencies,
    pir_score,
  };
  await createRelation(context, user, addRefInput);
  // add pir score on the entity
  await updatePirInformationOnEntity(context, user, sourceId, pirId, pir_score);
};
