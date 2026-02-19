import buildRelationToRelationRule from '../../src/rules/relationToRelationBuilder';
import * as middleware from '../../src/database/middleware';
import * as middlewareLoader from '../../src/database/middleware-loader';
import { describe, expect, it, vi } from 'vitest';
import { STIX_EXT_OCTI } from '../../src/types/stix-2-1-extensions';
import type { BasicStoreRelation } from '../../src/types/store';
import { v4 as uuid } from 'uuid';
import { RELATION_PARTICIPATE_TO } from '../../src/schema/internalRelationship';
import { RELATION_PART_OF } from '../../src/schema/stixCoreRelationship';
import { executionContext, RULE_MANAGER_USER } from '../../src/utils/access';
import { createRuleContent } from '../../src/rules/rules-utils';
import { RELATION_OBJECT_MARKING } from '../../src/schema/stixRefRelationship';

// Mocks
vi.mock('../database/middleware');
vi.mock('../database/middleware-loader');

describe('relationToRelationBuilder applyUpsert function', () => {
  const ruleDefinition = {
    id: uuid(),
    name: 'TestRule',
    description: 'rule to test relationToRelationBuilder',
    category: 'cat',
    display: {
      if: [
        { source: 'User', source_color: '#000' },
      ],
      then: [
        { source: 'Organization', source_color: '#fff' },
      ],
    },
    scan: { types: [] },
    scopes: [],
  };
  const relationTypes = {
    leftType: RELATION_PARTICIPATE_TO,
    rightType: RELATION_PART_OF,
    rightTypesTo: ['Organization'],
    creationType: RELATION_PARTICIPATE_TO,
  };
  const builtRule = buildRelationToRelationRule(ruleDefinition, relationTypes);
  const context = executionContext(ruleDefinition.name, RULE_MANAGER_USER);

  // Prevent createInferredRelation from actually being called and just tack calls to it
  vi.spyOn(middleware, 'createInferredRelation').mockImplementation((() => {}) as any);

  // Create useful ids and dates for the created and the existing relations
  const createdRelationId = uuid();
  const createdRelationSourceId = uuid();
  const createdRelationTargetId = uuid();
  const existingRelationId = uuid();
  const createdRelationStartTime = new Date('2020-01-01').toISOString();
  const createdRelationStopTime = new Date('2020-12-31').toISOString();
  const existingRelationStartTime = new Date('2019-01-01');
  const existingRelationStopTime = new Date('2019-12-31');

  it('should handle creation of a relationship matching the right side of the rule definition and call createInferredRelation', async () => {
    // The created relationship that matches the right side of the rule definition and should lead to an inferred relation creation
    const createdRelationship = {
      extensions: { [STIX_EXT_OCTI]: { id: createdRelationId, source_ref: createdRelationSourceId, target_ref: createdRelationTargetId } },
      relationship_type: RELATION_PART_OF,
      confidence: 30,
      start_time: createdRelationStartTime,
      stop_time: createdRelationStopTime,
    };
    // Mock fullRelationsList to return an existing relation that matches the left side of the rule definition
    const existingRelationSourceId = uuid();
    vi.spyOn(middlewareLoader, 'fullRelationsList').mockImplementation(async (_ctx, _user, _type, args) => {
      if (args && typeof args.callback === 'function') {
        await args.callback([
          {
            internal_id: existingRelationId,
            confidence: 50,
            fromId: existingRelationSourceId,
            start_time: existingRelationStartTime,
            stop_time: existingRelationStopTime,
          } as BasicStoreRelation,
        ]);
      }
      return [];
    });
    // Call the function under test
    await builtRule.insert(createdRelationship);
    // Check createInferredRelation has been called with correct parameters
    const ruleContent = createRuleContent(
      ruleDefinition.id,
      [existingRelationSourceId, existingRelationId, createdRelationSourceId, createdRelationId, createdRelationTargetId],
      [existingRelationId, createdRelationId],
      {
        confidence: 40, // mid value between created relationship (30) and existing relationship (50)
        start_time: existingRelationStartTime.toISOString(),
        stop_time: existingRelationStopTime.toISOString(),
        objectMarking: [], // no markings for both the created and the existing relation
      });
    expect(middleware.createInferredRelation).toHaveBeenCalledWith(
      context,
      { fromId: existingRelationSourceId, toId: createdRelationTargetId, relationship_type: RELATION_PARTICIPATE_TO },
      ruleContent,
    );
  });

  it('should handle creation of a relationship matching left side of the rule and call createInferredRelation', async () => {
    // The created relationship that matches the left side of the rule definition and should lead to an inferred relation creation
    const createdRelationship = {
      extensions: {
        [STIX_EXT_OCTI]: { id: createdRelationId, source_ref: createdRelationSourceId, target_ref: createdRelationTargetId },
      },
      relationship_type: RELATION_PARTICIPATE_TO,
      start_time: createdRelationStartTime,
      stop_time: createdRelationStopTime,
      object_marking_refs: ['markingA', 'markingB'],
    };
    // Mock fullRelationsList to return an existing relation that matches the criteria for the right side of the rule definition
    const existingRelationTargetId = uuid();
    vi.spyOn(middlewareLoader, 'fullRelationsList').mockImplementation(async (_ctx, _user, _type, args) => {
      if (args && typeof args.callback === 'function') {
        await args.callback([
          {
            internal_id: existingRelationId,
            toId: existingRelationTargetId,
            start_time: existingRelationStartTime,
            stop_time: existingRelationStopTime,
            confidence: 50,
            [RELATION_OBJECT_MARKING]: ['markingC'],
          } as BasicStoreRelation,
        ]);
      }
      return [];
    });
    // Call the function under test
    await builtRule.insert(createdRelationship);
    // Check createInferredRelation has been called with correct parameters
    const ruleContent = createRuleContent(
      ruleDefinition.id,
      [createdRelationSourceId, createdRelationId, existingRelationTargetId, existingRelationId, createdRelationTargetId],
      [createdRelationId, existingRelationId],
      {
        confidence: 25, // mid value between created relationship (0 by default) and existing relationship (50)
        start_time: existingRelationStartTime.toISOString(),
        stop_time: existingRelationStopTime.toISOString(),
        objectMarking: ['markingA', 'markingB', 'markingC'], // combination of markings from created and existing relations
      });
    expect(middleware.createInferredRelation).toHaveBeenCalledWith(
      context,
      { fromId: createdRelationSourceId, toId: existingRelationTargetId, relationship_type: RELATION_PARTICIPATE_TO },
      ruleContent,
    );
  });

  it('should handle creation of a relationship matching left side of the rule and call createInferredRelation in case rightTypesTo is specified in the rule definition', async () => {
    // The created relationship that matches the left side of the rule definition and should lead to an inferred relation creation
    const createdRelationship = {
      extensions: { [STIX_EXT_OCTI]: { id: createdRelationId, source_ref: createdRelationSourceId, target_ref: createdRelationTargetId } },
      relationship_type: RELATION_PARTICIPATE_TO,
      start_time: createdRelationStartTime,
      stop_time: createdRelationStopTime,
    };
    // Mock fullRelationsList to return an existing relation that matches the criteria for the right side of the rule definition
    const existingRelationTargetId = uuid();
    const fullRelationsListSpy = vi.spyOn(middlewareLoader, 'fullRelationsList').mockImplementation(async (_ctx, _user, _type, args) => {
      if (args && typeof args.callback === 'function') {
        await args.callback([
          {
            internal_id: existingRelationId,
            toId: existingRelationTargetId,
            start_time: existingRelationStopTime,
            stop_time: existingRelationStopTime,
            fromId: 'dummyId',
          } as BasicStoreRelation,
        ]);
      }
      return [];
    });
    // Call the function under test
    await builtRule.insert(createdRelationship);
    // Check fullRelationsList has been called with correct parameters to check for existing relations matching the right side of the rule definition
    expect(fullRelationsListSpy).toHaveBeenCalledWith(
      context,
      RULE_MANAGER_USER,
      RELATION_PART_OF,
      {
        fromId: createdRelationTargetId,
        toTypes: ['Organization'], // call to rightTypesTo from the rule definition
        callback: expect.any(Function),
      },
    );
    // Check createInferredRelation has been called with correct parameters
    const ruleContent = createRuleContent(
      ruleDefinition.id,
      [createdRelationSourceId, createdRelationId, existingRelationTargetId, existingRelationId, createdRelationTargetId],
      [createdRelationId, existingRelationId],
      {
        confidence: 0, // mid value between created relationship (0 by default) and existing relationship (0 by default)
        start_time: existingRelationStartTime.toISOString(),
        stop_time: existingRelationStopTime.toISOString(),
        objectMarking: [],
      });
    expect(middleware.createInferredRelation).toHaveBeenCalledWith(
      context,
      { fromId: createdRelationSourceId, toId: existingRelationTargetId, relationship_type: RELATION_PARTICIPATE_TO },
      ruleContent,
    );
  });
});
