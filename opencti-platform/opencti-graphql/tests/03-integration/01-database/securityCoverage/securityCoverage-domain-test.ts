import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  addSecurityCoverage,
  findSecurityCoverageByCoveredId,
  getSecurityCoverageResultIds,
  listSecurityCoverageResults,
  securityCoverageDelete,
  securityCoverageStixBundle,
} from '../../../../src/modules/securityCoverage/securityCoverage-domain';
import {
  addSecurityCoverageResult,
  createHasCoveredRelTask,
  editSecurityCoverageResult,
  findById as findSecurityCoverageResultById,
} from '../../../../src/modules/securityCoverage/securityCoverageResult/securityCoverageResult-domain';
import { addAttackPattern } from '../../../../src/domain/attackPattern';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { addReport, reportDeleteWithElements } from '../../../../src/domain/report';
import { stixDomainObjectDelete } from '../../../../src/domain/stixDomainObject';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_CONTAINER_REPORT, ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_MALWARE } from '../../../../src/schema/stixDomainObject';
import { addIntrusionSet } from '../../../../src/domain/intrusionSet';
import { addStixCoreRelationship } from '../../../../src/domain/stixCoreRelationship';
import { RELATION_USES } from '../../../../src/schema/stixCoreRelationship';
import { addMalware } from '../../../../src/domain/malware';
import { addOrganization } from '../../../../src/modules/organization/organization-domain';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../../src/modules/organization/organization-types';
import { addSecurityPlatform } from '../../../../src/modules/securityPlatform/securityPlatform-domain';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from '../../../../src/modules/securityPlatform/securityPlatform-types';
import type { StoreEntity, StoreEntityReport } from '../../../../src/types/store';
import type { StixSecurityCoverage } from '../../../../src/modules/securityCoverage/securityCoverage-types';
import { findBackgroundTaskPaginated } from '../../../../src/domain/backgroundTask';
import { fullRelationsList } from '../../../../src/database/middleware-loader';
import { storeLoadByIdWithRefs } from '../../../../src/database/middleware';
import { isStixRefRelationship, RELATION_OBJECT } from '../../../../src/schema/stixRefRelationship';
import { INPUT_OBJECTS } from '../../../../src/schema/general';
import { addWorkspace, workspaceDelete } from '../../../../src/modules/workspace/workspace-domain';
import { knowledgeAddFromInvestigation } from '../../../../src/domain/container';

describe('SecurityCoverage domain', () => {
  // Creating has-covered relationships from filters spawns a QUERY background task,
  // which counts the impacted entities using the user carried by the context.
  const adminContext = { ...testContext, user: ADMIN_USER };

  let report: StoreEntityReport;
  // Attack pattern contained in the report, so it can be covered by a security coverage of the report.
  let reportAttackPattern: StoreEntity;

  const BASE_INPUT = () => ({
    name: 'sc1',
    objectCovered: report.standard_id,
    auto_enrichment_disable: true,
  });

  beforeAll(async () => {
    reportAttackPattern = await addAttackPattern(testContext, ADMIN_USER, { name: 'SC tests report AP' });
    report = await addReport(testContext, ADMIN_USER, {
      name: 'Report for SC tests',
      published: '2026-04-24T19:15:00.000Z',
      objects: [reportAttackPattern.standard_id],
    });
  });

  afterAll(async () => {
    await reportDeleteWithElements(testContext, ADMIN_USER, report.standard_id);
    await stixDomainObjectDelete(testContext, ADMIN_USER, reportAttackPattern.id, ENTITY_TYPE_ATTACK_PATTERN);
  });

  describe('Function addSecurityCoverage()', () => {
    it('should create coverage result if explicitly asked for', async () => {
      const input = {
        ...BASE_INPUT(),
        add_related_entities: { selected_ids: [reportAttackPattern.standard_id] },
      };
      const securityCoverage = await addSecurityCoverage(adminContext, ADMIN_USER, input);
      const results = await listSecurityCoverageResults(testContext, ADMIN_USER, securityCoverage);
      expect(results.length).toEqual(1);
      // Name should be the external_uri when it is defined
      expect(results[0].name).toEqual('Result of sc1');
      await securityCoverageDelete(testContext, ADMIN_USER, securityCoverage.id);
    });

    it('should create coverage result if add_related_entities.selected_ids is provided', async () => {
      const input = {
        ...BASE_INPUT(),
        add_related_entities: { selected_ids: [reportAttackPattern.standard_id] },
      };
      const securityCoverage = await addSecurityCoverage(testContext, ADMIN_USER, input);
      const results = await listSecurityCoverageResults(testContext, ADMIN_USER, securityCoverage);
      expect(results.length).toEqual(1);
      await securityCoverageDelete(testContext, ADMIN_USER, securityCoverage.id);
    });

    it('should create coverage result if contains eternal uri', async () => {
      const externalUri = 'http://localhost/admin/scenarios/a2166709-be41-48bf-9ce1-51bb2fd3a131';
      const input = {
        ...BASE_INPUT(),
        coverage_information: [{
          coverage_name: 'prevention',
          coverage_score: 10,
        }],
        external_uri: externalUri,
      };
      const securityCoverage = await addSecurityCoverage(testContext, ADMIN_USER, input);
      const results = await listSecurityCoverageResults(testContext, ADMIN_USER, securityCoverage);
      expect(results.length).toEqual(1);
      // Name should be the external_uri when it is defined
      expect(results[0].name).toEqual(`${externalUri} Result of sc1`);
      await securityCoverageDelete(testContext, ADMIN_USER, securityCoverage.id);
    });

    it('should create coverage result if contains external_uri without coverage info', async () => {
      const input = {
        ...BASE_INPUT(),
        tenant_name: 'Super Coverage',
        external_uri: 'http://localhost/admin/scenarios/a2166709-be41-48bf-9ce1-51bb2fd3a132',
      };
      const securityCoverage = await addSecurityCoverage(testContext, ADMIN_USER, input);
      const results = await listSecurityCoverageResults(testContext, ADMIN_USER, securityCoverage);
      expect(results.length).toEqual(1);
      // Name should be the tenant_name when it is defined
      expect(results[0].name).toEqual('Super Coverage Result of sc1');
      await securityCoverageDelete(testContext, ADMIN_USER, securityCoverage.id);
    });

    it('should not create coverage result if no manual neither external_uri', async () => {
      const input = {
        ...BASE_INPUT(),
      };
      const securityCoverage = await addSecurityCoverage(testContext, ADMIN_USER, input);
      const results = await listSecurityCoverageResults(testContext, ADMIN_USER, securityCoverage);
      expect(results.length).toEqual(0);
      await securityCoverageDelete(testContext, ADMIN_USER, securityCoverage.id);
    });

    it('should return all coverage results when upserting with a new external_uri', async () => {
      const firstCoverage = await addSecurityCoverage(testContext, ADMIN_USER, {
        ...BASE_INPUT(),
        external_uri: 'http://localhost/admin/scenarios/a2166709-be41-48bf-9ce1-51bb2fd3a201',
      });
      // Same objectCovered, so the SecurityCoverage is upserted
      const upsertedCoverage = await addSecurityCoverage(testContext, ADMIN_USER, {
        ...BASE_INPUT(),
        external_uri: 'http://localhost/admin/scenarios/a2166709-be41-48bf-9ce1-51bb2fd3a202',
      });
      expect(upsertedCoverage.id).toEqual(firstCoverage.id);

      const results = await listSecurityCoverageResults(testContext, ADMIN_USER, upsertedCoverage);
      expect(results.length).toEqual(2);
      // The returned coverage must reference every result, not only the one just created
      const returnedResultIds = getSecurityCoverageResultIds(upsertedCoverage);
      expect(returnedResultIds.length).toEqual(2);
      expect([...returnedResultIds].sort()).toEqual(results.map((r) => r.id).sort());

      await securityCoverageDelete(testContext, ADMIN_USER, upsertedCoverage.id);
    });

    it('should not duplicate the coverage result when upserting with the same external_uri', async () => {
      const input = {
        ...BASE_INPUT(),
        external_uri: 'http://localhost/admin/scenarios/a2166709-be41-48bf-9ce1-51bb2fd3a203',
      };
      await addSecurityCoverage(testContext, ADMIN_USER, input);
      const upsertedCoverage = await addSecurityCoverage(testContext, ADMIN_USER, input);

      const results = await listSecurityCoverageResults(testContext, ADMIN_USER, upsertedCoverage);
      expect(results.length).toEqual(1);
      expect(getSecurityCoverageResultIds(upsertedCoverage)).toEqual([results[0].id]);

      await securityCoverageDelete(testContext, ADMIN_USER, upsertedCoverage.id);
    });
  });

  describe('Function securityCoverageStixBundle()', () => {
    it('should return a bundle containing the coverage and the covered entity', async () => {
      const input = {
        ...BASE_INPUT(),
        name: 'sc to export',
        coverage_information: [{
          coverage_name: 'prevention',
          coverage_score: 10,
        }],
      };
      const securityCoverage = await addSecurityCoverage(testContext, ADMIN_USER, input);
      const bundle = JSON.parse(await securityCoverageStixBundle(testContext, ADMIN_USER, securityCoverage.id));
      const bundleObjects = bundle.objects as unknown as StixSecurityCoverage[];

      const stixCoverage = bundleObjects.find((o) => o.type === 'security-coverage');
      expect(stixCoverage?.id).toEqual(securityCoverage.standard_id);
      expect(stixCoverage?.covered_ref).toEqual(report.standard_id);
      // The covered entity must be exported as a distinct object of the bundle
      expect(bundleObjects.filter((o) => o.id === report.standard_id).length).toEqual(1);

      await securityCoverageDelete(testContext, ADMIN_USER, securityCoverage.id);
    });

    // Expanding a report in an investigation also brings its "contains" (object) ref relationships,
    // and "Add to a container" stores them in the container objects. Ref relationships have no
    // standalone STIX representation, so building the bundle used to fail with
    // "No relation converter_2_1 available".
    it('should build the bundle when the covered container contains a ref relationship', async () => {
      const attackPattern = await addAttackPattern(testContext, ADMIN_USER, { name: 'SC ref-in-container AP' });
      const innerReport = await addReport(testContext, ADMIN_USER, {
        name: 'SC ref-in-container inner report',
        published: '2026-04-24T19:15:00.000Z',
        objects: [attackPattern.id],
      });
      const [objectRefRelation] = await fullRelationsList(testContext, ADMIN_USER, RELATION_OBJECT, {
        fromId: innerReport.id,
        toId: attackPattern.id,
      });
      expect(objectRefRelation).toBeDefined();
      const container = await addReport(testContext, ADMIN_USER, {
        name: 'SC ref-in-container outer container',
        published: '2026-04-24T19:15:00.000Z',
      });
      // Investigation after expanding the inner report, then "Add to a container"
      const investigation = await addWorkspace(testContext, ADMIN_USER, {
        type: 'investigation',
        name: 'SC ref-in-container investigation',
        investigated_entities_ids: [innerReport.id, attackPattern.id, objectRefRelation.id],
      });
      await knowledgeAddFromInvestigation(testContext, ADMIN_USER, { containerId: container.id, workspaceId: investigation.id });

      // The container now holds the "contains" ref relationship among its objects
      const loadedContainer = await storeLoadByIdWithRefs<StoreEntity>(testContext, ADMIN_USER, container.id) as StoreEntity;
      const refRelationsInContainer = (loadedContainer[INPUT_OBJECTS] ?? []).filter((o) => isStixRefRelationship(o.entity_type));
      expect(refRelationsInContainer.map((o) => o.id)).toEqual([objectRefRelation.id]);

      const securityCoverage = await addSecurityCoverage(testContext, ADMIN_USER, {
        ...BASE_INPUT(),
        name: 'sc on container with ref relationship',
        objectCovered: container.standard_id,
      });
      const bundle = JSON.parse(await securityCoverageStixBundle(testContext, ADMIN_USER, securityCoverage.id));
      const bundleIds = (bundle.objects as { id: string }[]).map((o) => o.id);
      expect(bundleIds).toContain(container.standard_id);
      expect(bundleIds).toContain(attackPattern.standard_id);
      // The "contains" link is never converted, and the nested report is not a has-covered target
      expect(bundleIds).not.toContain(objectRefRelation.standard_id);
      expect(bundleIds).not.toContain(innerReport.standard_id);

      await securityCoverageDelete(testContext, ADMIN_USER, securityCoverage.id);
      await workspaceDelete(testContext, ADMIN_USER, investigation.id);
      await stixDomainObjectDelete(testContext, ADMIN_USER, container.id, ENTITY_TYPE_CONTAINER_REPORT);
      await stixDomainObjectDelete(testContext, ADMIN_USER, innerReport.id, ENTITY_TYPE_CONTAINER_REPORT);
      await stixDomainObjectDelete(testContext, ADMIN_USER, attackPattern.id, ENTITY_TYPE_ATTACK_PATTERN);
    });

    it('should only bundle has-covered target types from the covered container refs', async () => {
      const attackPattern = await addAttackPattern(testContext, ADMIN_USER, { name: 'SC target-types AP' });
      const malware = await addMalware(testContext, ADMIN_USER, { name: 'SC target-types malware' });
      const securityPlatform = await addSecurityPlatform(testContext, ADMIN_USER, { name: 'SC target-types security platform' });
      const author = await addOrganization(testContext, ADMIN_USER, { name: 'SC target-types author' });
      const container = await addReport(testContext, ADMIN_USER, {
        name: 'SC target-types container',
        published: '2026-04-24T19:15:00.000Z',
        createdBy: author.id,
        objects: [attackPattern.id, securityPlatform.id, malware.id],
      });

      const securityCoverage = await addSecurityCoverage(testContext, ADMIN_USER, {
        ...BASE_INPUT(),
        name: 'sc on container with mixed refs',
        objectCovered: container.standard_id,
      });
      const bundle = JSON.parse(await securityCoverageStixBundle(testContext, ADMIN_USER, securityCoverage.id));
      const bundleIds = (bundle.objects as { id: string }[]).map((o) => o.id);
      expect(bundleIds).toContain(container.standard_id);
      // Attack pattern and security platform are has-covered target types
      expect(bundleIds).toContain(attackPattern.standard_id);
      expect(bundleIds).toContain(securityPlatform.standard_id);
      // Contained malware (object_refs) and author (created_by_ref) are not
      expect(bundleIds).not.toContain(malware.standard_id);
      expect(bundleIds).not.toContain(author.standard_id);

      await securityCoverageDelete(testContext, ADMIN_USER, securityCoverage.id);
      await stixDomainObjectDelete(testContext, ADMIN_USER, container.id, ENTITY_TYPE_CONTAINER_REPORT);
      await stixDomainObjectDelete(testContext, ADMIN_USER, attackPattern.id, ENTITY_TYPE_ATTACK_PATTERN);
      await stixDomainObjectDelete(testContext, ADMIN_USER, securityPlatform.id, ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM);
      await stixDomainObjectDelete(testContext, ADMIN_USER, malware.id, ENTITY_TYPE_MALWARE);
      await stixDomainObjectDelete(testContext, ADMIN_USER, author.id, ENTITY_TYPE_IDENTITY_ORGANIZATION);
    });
  });

  describe('Function securityCoverageDelete()', () => {
    it('should delete security coverage results when deleting a security coverage', async () => {
      const input = {
        ...BASE_INPUT(),
        name: 'sc to delete',
        coverage_information: [{
          coverage_name: 'prevention',
          coverage_score: 10,
        }],
        add_related_entities: { selected_ids: [reportAttackPattern.standard_id] },
      };
      const securityCoverage = await addSecurityCoverage(adminContext, ADMIN_USER, input);
      let results = await listSecurityCoverageResults(testContext, ADMIN_USER, securityCoverage);
      expect(results.length).toEqual(1);
      // Name falls back to "Result of <name>" when no external_uri is provided
      expect(results[0].name).toEqual(`Result of ${securityCoverage.name}`);
      await securityCoverageDelete(testContext, ADMIN_USER, securityCoverage.id);
      results = await listSecurityCoverageResults(testContext, ADMIN_USER, securityCoverage);
      expect(results.length).toEqual(0);
    });
  });

  describe('Function createHasCoveredRelTask() with selected_ids', () => {
    it('should only target explicit selected_ids, ignoring the rest of the related entities', async () => {
      const attackPattern1 = await addAttackPattern(testContext, ADMIN_USER, { name: 'SC entities_to_add AP1' });
      const attackPattern2 = await addAttackPattern(testContext, ADMIN_USER, { name: 'SC entities_to_add AP2' });
      const attackPattern3 = await addAttackPattern(testContext, ADMIN_USER, { name: 'SC entities_to_add AP3' });
      const reportWithTargets = await addReport(testContext, ADMIN_USER, {
        name: 'Report for SC entities_to_add test',
        published: '2026-04-24T19:15:00.000Z',
        objects: [attackPattern1.standard_id, attackPattern2.standard_id, attackPattern3.standard_id],
      });

      const input = {
        ...BASE_INPUT(),
        objectCovered: reportWithTargets.standard_id,
        external_uri: 'http://localhost/admin/scenarios/a2166709-be41-48bf-9ce1-51bb2fd3a199',
      };
      const securityCoverage = await addSecurityCoverage(testContext, ADMIN_USER, input);
      const results = await listSecurityCoverageResults(testContext, ADMIN_USER, securityCoverage);
      expect(results.length).toEqual(1);

      const explicitIds = [attackPattern1.standard_id, attackPattern2.standard_id];
      const task = await createHasCoveredRelTask(testContext, ADMIN_USER, results[0].id, reportWithTargets.id, { selected_ids: explicitIds }) as { task_ids: string[] };
      expect(task.task_ids).toEqual(explicitIds);
      expect(task.task_ids.length).toBeLessThan(3);

      await securityCoverageDelete(testContext, ADMIN_USER, securityCoverage.id);
      await reportDeleteWithElements(testContext, ADMIN_USER, reportWithTargets.standard_id);
      for (const attackPattern of [attackPattern1, attackPattern2, attackPattern3]) {
        await stixDomainObjectDelete(testContext, ADMIN_USER, attackPattern.id, ENTITY_TYPE_ATTACK_PATTERN);
      }
    });
  });

  describe('Function createHasCoveredRelTask() without any selection', () => {
    it('should not create a background task when no ids, filters nor search are provided', async () => {
      const securityCoverage = await addSecurityCoverage(adminContext, ADMIN_USER, {
        ...BASE_INPUT(),
        add_related_entities: { selected_ids: [reportAttackPattern.standard_id] },
      });
      const results = await listSecurityCoverageResults(testContext, ADMIN_USER, securityCoverage);
      expect(results.length).toEqual(1);

      const emptySelections = [
        {},
        { selected_ids: [] },
        { filters: JSON.stringify({ mode: 'and', filters: [], filterGroups: [] }), search: '' },
      ];
      for (const selection of emptySelections) {
        await expect(() => createHasCoveredRelTask(testContext, ADMIN_USER, results[0].id, report.internal_id, selection)).rejects.toThrow();
      }

      await securityCoverageDelete(testContext, ADMIN_USER, securityCoverage.id);
    });
  });

  describe('Function addSecurityCoverage() end-to-end wiring with add_related_entities', () => {
    const findHasCoveredRelTask = async (securityCoverageResultId: string) => {
      const taskConnection = await findBackgroundTaskPaginated(testContext, ADMIN_USER, {
        orderBy: 'created_at',
        orderMode: 'desc',
        first: 50,
      });
      const task = taskConnection.edges
        .map((edge: { node: { description?: string; task_ids?: string[] } }) => edge.node)
        .find((node: { description?: string }) => (node.description ?? '').includes(securityCoverageResultId));
      if (!task) {
        throw new Error(`No background task found for security coverage result ${securityCoverageResultId}`);
      }
      return task as { description?: string; task_ids: string[]; task_filters?: string; task_excluded_ids?: string[] };
    };

    const setupReportWithAttackPatterns = async (namePrefix: string) => {
      const attackPattern1 = await addAttackPattern(testContext, ADMIN_USER, { name: `${namePrefix} AP1` });
      const attackPattern2 = await addAttackPattern(testContext, ADMIN_USER, { name: `${namePrefix} AP2` });
      const attackPattern3 = await addAttackPattern(testContext, ADMIN_USER, { name: `${namePrefix} AP3` });
      const reportWithTargets = await addReport(testContext, ADMIN_USER, {
        name: `Report for ${namePrefix}`,
        published: '2026-04-24T19:15:00.000Z',
        objects: [attackPattern1.standard_id, attackPattern2.standard_id, attackPattern3.standard_id],
      });
      return {
        attackPattern1, attackPattern2, attackPattern3, reportWithTargets,
      };
    };

    const cleanup = async (
      securityCoverageId: string,
      reportWithTargets: StoreEntityReport,
      attackPatterns: Array<{ id: string }>,
    ) => {
      await securityCoverageDelete(testContext, ADMIN_USER, securityCoverageId);
      await reportDeleteWithElements(testContext, ADMIN_USER, reportWithTargets.standard_id);
      for (const attackPattern of attackPatterns) {
        await stixDomainObjectDelete(testContext, ADMIN_USER, attackPattern.id, ENTITY_TYPE_ATTACK_PATTERN);
      }
    };

    it('should create a background task targeting only selected_ids when called through addSecurityCoverage', async () => {
      const {
        attackPattern1, attackPattern2, attackPattern3, reportWithTargets,
      } = await setupReportWithAttackPatterns('SC e2e selected_ids');

      const input = {
        ...BASE_INPUT(),
        objectCovered: reportWithTargets.standard_id,
        add_related_entities: { selected_ids: [attackPattern1.standard_id, attackPattern2.standard_id] },
      };
      const securityCoverage = await addSecurityCoverage(testContext, ADMIN_USER, input);
      const results = await listSecurityCoverageResults(testContext, ADMIN_USER, securityCoverage);
      expect(results.length).toEqual(1);

      const task = await findHasCoveredRelTask(results[0].id);
      expect(task.task_ids).toEqual([attackPattern1.standard_id, attackPattern2.standard_id]);

      await cleanup(securityCoverage.id, reportWithTargets, [attackPattern1, attackPattern2, attackPattern3]);
    });

    it('should update a result and create a background task targeting only selected_ids when called through editSecurityCoverageResult', async () => {
      const {
        attackPattern1, attackPattern2, attackPattern3, reportWithTargets,
      } = await setupReportWithAttackPatterns('SCR edit selected_ids');

      const securityCoverage = await addSecurityCoverage(testContext, ADMIN_USER, {
        ...BASE_INPUT(),
        objectCovered: reportWithTargets.standard_id,
        external_uri: 'http://localhost/admin/scenarios/a2166709-be41-48bf-9ce1-51bb2fd3a200',
      });
      const results = await listSecurityCoverageResults(testContext, ADMIN_USER, securityCoverage);
      expect(results.length).toEqual(1);

      const updated = await editSecurityCoverageResult(testContext, ADMIN_USER, results[0].id, {
        name: 'SCR edit updated name',
        add_related_entities: { selected_ids: [attackPattern3.standard_id] },
      });
      expect(updated.name).toEqual('SCR edit updated name');

      const task = await findHasCoveredRelTask(results[0].id);
      expect(task.task_ids).toEqual([attackPattern3.standard_id]);

      await cleanup(securityCoverage.id, reportWithTargets, [attackPattern1, attackPattern2, attackPattern3]);
    });

    it('should create a QUERY background task with filters/search/excluded_ids when no selected_ids is provided', async () => {
      const {
        attackPattern1, attackPattern2, attackPattern3, reportWithTargets,
      } = await setupReportWithAttackPatterns('SC e2e filters');

      const filters = {
        mode: 'and',
        filters: [{ key: ['objects'], values: [reportWithTargets.standard_id], operator: 'eq', mode: 'or' }],
        filterGroups: [],
      };
      const input = {
        ...BASE_INPUT(),
        objectCovered: reportWithTargets.standard_id,
        add_related_entities: {
          filters: JSON.stringify(filters),
          excluded_ids: [attackPattern3.standard_id],
          search: '',
        },
      };
      const securityCoverage = await addSecurityCoverage(adminContext, ADMIN_USER, input);
      const results = await listSecurityCoverageResults(testContext, ADMIN_USER, securityCoverage);
      expect(results.length).toEqual(1);

      const task = await findHasCoveredRelTask(results[0].id);
      // User filters are kept, wrapped with the filters restricting to the covered report objects.
      const taskFilters = JSON.parse(task.task_filters as string);
      expect(taskFilters.filterGroups).toEqual([filters]);
      expect(taskFilters.filters).toContainEqual({ key: ['objects'], values: [reportWithTargets.id] });
      expect(task.task_excluded_ids).toEqual([attackPattern3.standard_id]);

      await cleanup(securityCoverage.id, reportWithTargets, [attackPattern1, attackPattern2, attackPattern3]);
    });
  });

  describe('add_related_entities restricted to the entities linked to the covered entity', () => {
    it('should reject an entity outside the covered report when updating a result', async () => {
      const outsideAttackPattern = await addAttackPattern(testContext, ADMIN_USER, { name: 'SCR scope outside AP' });
      const securityCoverage = await addSecurityCoverage(testContext, ADMIN_USER, {
        ...BASE_INPUT(),
        external_uri: 'http://localhost/admin/scenarios/a2166709-be41-48bf-9ce1-51bb2fd3a300',
      });
      const results = await listSecurityCoverageResults(testContext, ADMIN_USER, securityCoverage);
      expect(results.length).toEqual(1);
      const initialName = results[0].name;

      await expect(() => editSecurityCoverageResult(testContext, ADMIN_USER, results[0].id, {
        name: 'SCR scope should not be renamed',
        add_related_entities: { selected_ids: [reportAttackPattern.standard_id, outsideAttackPattern.standard_id] },
      })).rejects.toThrow('Entities to cover must be linked to the covered entity');
      // Nothing is changed when the selection is rejected
      const result = await findSecurityCoverageResultById(testContext, ADMIN_USER, results[0].id);
      expect(result.name).toEqual(initialName);

      await expect(() => addSecurityCoverageResult(testContext, ADMIN_USER, {
        resultOf: securityCoverage.id,
        name: 'SCR scope rejected result',
        add_related_entities: { selected_ids: [outsideAttackPattern.standard_id] },
      })).rejects.toThrow('Entities to cover must be linked to the covered entity');

      await securityCoverageDelete(testContext, ADMIN_USER, securityCoverage.id);
      await stixDomainObjectDelete(testContext, ADMIN_USER, outsideAttackPattern.id, ENTITY_TYPE_ATTACK_PATTERN);
    });

    it('should only accept the attack patterns used by the covered intrusion set', async () => {
      const usedAttackPattern = await addAttackPattern(testContext, ADMIN_USER, { name: 'SC scope used AP' });
      const unusedAttackPattern = await addAttackPattern(testContext, ADMIN_USER, { name: 'SC scope unused AP' });
      const intrusionSet = await addIntrusionSet(testContext, ADMIN_USER, { name: 'SC scope intrusion set' });
      await addStixCoreRelationship(testContext, ADMIN_USER, {
        fromId: intrusionSet.id,
        toId: usedAttackPattern.id,
        relationship_type: RELATION_USES,
      });
      const input = {
        ...BASE_INPUT(),
        name: 'SC scope intrusion set coverage',
        objectCovered: intrusionSet.standard_id,
      };

      // Rejected before anything is created
      await expect(() => addSecurityCoverage(testContext, ADMIN_USER, {
        ...input,
        add_related_entities: { selected_ids: [unusedAttackPattern.standard_id] },
      })).rejects.toThrow('Entities to cover must be linked to the covered entity');
      const rejectedCoverage = await findSecurityCoverageByCoveredId(testContext, ADMIN_USER, intrusionSet.id);
      expect(rejectedCoverage).toBeUndefined();

      const securityCoverage = await addSecurityCoverage(testContext, ADMIN_USER, {
        ...input,
        add_related_entities: { selected_ids: [usedAttackPattern.id] },
      });
      const results = await listSecurityCoverageResults(testContext, ADMIN_USER, securityCoverage);
      expect(results.length).toEqual(1);

      await securityCoverageDelete(testContext, ADMIN_USER, securityCoverage.id);
      await stixDomainObjectDelete(testContext, ADMIN_USER, intrusionSet.id, ENTITY_TYPE_INTRUSION_SET);
      for (const attackPattern of [usedAttackPattern, unusedAttackPattern]) {
        await stixDomainObjectDelete(testContext, ADMIN_USER, attackPattern.id, ENTITY_TYPE_ATTACK_PATTERN);
      }
    });
  });
});
