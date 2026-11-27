import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  addSecurityCoverage,
  findById,
  findCoveredEntities,
  findCoveredEntitiesDistribution,
  getSecurityCoverageResultIds,
  listSecurityCoverageResults,
  loadSecurityCoverageResults,
  securityCoverageDelete,
  securityCoverageStixBundle,
} from '../../../../src/modules/securityCoverage/securityCoverage-domain';
import {
  addSecurityCoverageResult,
  createHasCoveredRelTask,
  editSecurityCoverageResult,
} from '../../../../src/modules/securityCoverage/securityCoverageResult/securityCoverageResult-domain';
import { addAttackPattern } from '../../../../src/domain/attackPattern';
import { ADMIN_USER, buildStandardUser, testContext } from '../../../utils/testQuery';
import { addReport, reportDeleteWithElements } from '../../../../src/domain/report';
import { stixDomainObjectDelete } from '../../../../src/domain/stixDomainObject';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_CONTAINER_REPORT, ENTITY_TYPE_MALWARE } from '../../../../src/schema/stixDomainObject';
import { addMalware } from '../../../../src/domain/malware';
import { addOrganization } from '../../../../src/modules/organization/organization-domain';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../../src/modules/organization/organization-types';
import { addSecurityPlatform } from '../../../../src/modules/securityPlatform/securityPlatform-domain';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from '../../../../src/modules/securityPlatform/securityPlatform-types';
import type { StoreEntity, StoreEntityReport } from '../../../../src/types/store';
import type { BasicStoreEntitySecurityCoverage, StixSecurityCoverage } from '../../../../src/modules/securityCoverage/securityCoverage-types';
import type { BasicStoreEntitySecurityCoverageResult } from '../../../../src/modules/securityCoverage/securityCoverageResult/securityCoverageResult-types';
import { addStixCoreRelationship } from '../../../../src/domain/stixCoreRelationship';
import { RELATION_HAS_COVERED } from '../../../../src/schema/stixCoreRelationship';
import { findBackgroundTaskPaginated } from '../../../../src/domain/backgroundTask';
import { fullRelationsList } from '../../../../src/database/middleware-loader';
import { storeLoadByIdWithRefs } from '../../../../src/database/middleware';
import { isStixRefRelationship, RELATION_OBJECT } from '../../../../src/schema/stixRefRelationship';
import { INPUT_OBJECTS } from '../../../../src/schema/general';
import { addWorkspace, workspaceDelete } from '../../../../src/modules/workspace/workspace-domain';
import { knowledgeAddFromInvestigation } from '../../../../src/domain/container';
import { FilterMode } from '../../../../src/generated/graphql';
import { MARKING_TLP_AMBER } from '../../../../src/schema/identifier';
import { executionContext } from '../../../../src/utils/access';
import { computeLoaders } from '../../../../src/http/httpAuthenticatedContext';
import type { AuthUser } from '../../../../src/types/user';

describe('SecurityCoverage domain', () => {
  // Creating has-covered relationships from filters spawns a QUERY background task,
  // which counts the impacted entities using the user carried by the context.
  const adminContext = { ...testContext, user: ADMIN_USER };

  let report: StoreEntityReport;

  const BASE_INPUT = () => ({
    name: 'sc1',
    objectCovered: report.standard_id,
    auto_enrichment_disable: true,
  });

  beforeAll(async () => {
    report = await addReport(testContext, ADMIN_USER, {
      name: 'Report for SC tests',
      published: '2026-04-24T19:15:00.000Z',
    });
  });

  afterAll(async () => {
    await reportDeleteWithElements(testContext, ADMIN_USER, report.standard_id);
  });

  describe('Function addSecurityCoverage()', () => {
    it('should create coverage result if explicitly asked for', async () => {
      const input = {
        ...BASE_INPUT(),
        add_related_entities: { selected_ids: ['my-selected-id'] },
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
        add_related_entities: { selected_ids: ['attack-pattern--00000000-0000-0000-0000-000000000001'] },
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
        add_related_entities: { selected_ids: ['my-selected-id'] },
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
      const task = await createHasCoveredRelTask(testContext, ADMIN_USER, results[0].id, { selected_ids: explicitIds }) as { task_ids: string[] };
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
        add_related_entities: { selected_ids: ['attack-pattern--00000000-0000-0000-0000-000000000001'] },
      });
      const results = await listSecurityCoverageResults(testContext, ADMIN_USER, securityCoverage);
      expect(results.length).toEqual(1);

      const emptySelections = [
        {},
        { selected_ids: [] },
        { filters: JSON.stringify({ mode: 'and', filters: [], filterGroups: [] }), search: '' },
      ];
      for (const selection of emptySelections) {
        await expect(() => createHasCoveredRelTask(testContext, ADMIN_USER, results[0].id, selection)).rejects.toThrow();
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
      expect(task.task_filters).toEqual(JSON.stringify(filters));
      expect(task.task_excluded_ids).toEqual([attackPattern3.standard_id]);

      await cleanup(securityCoverage.id, reportWithTargets, [attackPattern1, attackPattern2, attackPattern3]);
    });
  });

  describe('Covered entities scoped to one result', () => {
    let scA: BasicStoreEntitySecurityCoverage;
    let scB: BasicStoreEntitySecurityCoverage;
    let scrParis: BasicStoreEntitySecurityCoverageResult;
    let scrLyon: BasicStoreEntitySecurityCoverageResult;
    let scrOther: BasicStoreEntitySecurityCoverageResult;
    let ap: StoreEntity;
    let otherReport: StoreEntityReport;

    const byResult = (resultId: string) => ({
      mode: FilterMode.And,
      filters: [{ key: ['fromId'], values: [resultId] }],
      filterGroups: [],
    });

    beforeAll(async () => {
      // No external_uri: no SecurityCoverageResult is created automatically
      const createdA = await addSecurityCoverage(adminContext, ADMIN_USER, { ...BASE_INPUT(), name: 'sc-scope' });
      scrParis = await addSecurityCoverageResult(adminContext, ADMIN_USER, { resultOf: createdA.id, name: 'OAEV Paris', external_uri: 'https://paris.oaev.test' });
      scrLyon = await addSecurityCoverageResult(adminContext, ADMIN_USER, { resultOf: createdA.id, name: 'OAEV Lyon', external_uri: 'https://lyon.oaev.test' });
      // The standard id of a SecurityCoverage is built from its covered entity: a second one needs its own covered entity
      otherReport = await addReport(testContext, ADMIN_USER, { name: 'Other report for SC scope tests', published: '2026-04-24T19:15:00.000Z' });
      const createdB = await addSecurityCoverage(adminContext, ADMIN_USER, { ...BASE_INPUT(), name: 'sc-other', objectCovered: otherReport.standard_id });
      scrOther = await addSecurityCoverageResult(adminContext, ADMIN_USER, { resultOf: createdB.id, name: 'OAEV Other', external_uri: 'https://other.oaev.test' });
      ap = await addAttackPattern(testContext, ADMIN_USER, { name: 'AP scope test', x_mitre_id: 'T9999.991' });
      await addStixCoreRelationship(testContext, ADMIN_USER, {
        fromId: scrParis.id,
        toId: ap.id,
        relationship_type: RELATION_HAS_COVERED,
        coverage_information: [{ coverage_name: 'detection', coverage_score: 80 }],
      });
      await addStixCoreRelationship(testContext, ADMIN_USER, {
        fromId: scrLyon.id,
        toId: ap.id,
        relationship_type: RELATION_HAS_COVERED,
        coverage_information: [{ coverage_name: 'detection', coverage_score: 20 }],
      });
      // A has-covered of the other coverage, on the same entity: it must only be excluded by the coverage scope
      await addStixCoreRelationship(testContext, ADMIN_USER, {
        fromId: scrOther.id,
        toId: ap.id,
        relationship_type: RELATION_HAS_COVERED,
        coverage_information: [{ coverage_name: 'detection', coverage_score: 50 }],
      });
      // Reload: findCoveredEntities reads the result ids on the SecurityCoverage entity
      scA = await findById(testContext, ADMIN_USER, createdA.id);
      scB = await findById(testContext, ADMIN_USER, createdB.id);
      expect(scB.id).not.toEqual(scA.id);
    });

    afterAll(async () => {
      await securityCoverageDelete(testContext, ADMIN_USER, scA.id);
      await securityCoverageDelete(testContext, ADMIN_USER, scB.id);
      await stixDomainObjectDelete(testContext, ADMIN_USER, ap.id, ENTITY_TYPE_ATTACK_PATTERN);
      await reportDeleteWithElements(testContext, ADMIN_USER, otherReport.standard_id);
    });

    it('should return the has-covered of every result without filter', async () => {
      const { count, entities } = await findCoveredEntities(testContext, ADMIN_USER, scA, ENTITY_TYPE_ATTACK_PATTERN, {});
      expect(count).toBe(2);
      expect(entities.map((e) => e.coverage_information?.[0].coverage_score).sort((a, b) => (a ?? 0) - (b ?? 0))).toEqual([20, 80]);
    });

    it('should only return the has-covered of the selected result', async () => {
      const { count, entities } = await findCoveredEntities(testContext, ADMIN_USER, scA, ENTITY_TYPE_ATTACK_PATTERN, { filters: byResult(scrParis.id) });
      expect(count).toBe(1);
      expect(entities[0].coverage_information).toEqual([{ coverage_name: 'detection', coverage_score: 80 }]);
    });

    it('should not leak the has-covered of another coverage', async () => {
      const { count } = await findCoveredEntities(testContext, ADMIN_USER, scA, ENTITY_TYPE_ATTACK_PATTERN, { filters: byResult(scrOther.id) });
      expect(count).toBe(0);
      // The data exists on the other coverage: only the coverage scope excludes it
      const other = await findCoveredEntities(testContext, ADMIN_USER, scB, ENTITY_TYPE_ATTACK_PATTERN, {});
      expect(other.count).toBe(1);
      expect(other.entities[0].coverage_information).toEqual([{ coverage_name: 'detection', coverage_score: 50 }]);
    });

    it('should scope the tested entities distribution to the selected result', async () => {
      const args = { field: 'entity_type', operation: 'count', relationship_type: [RELATION_HAS_COVERED] };
      const all = await findCoveredEntitiesDistribution(testContext, ADMIN_USER, scA, args);
      const paris = await findCoveredEntitiesDistribution(testContext, ADMIN_USER, scA, { ...args, fromId: [scrParis.id] });
      expect(all).toEqual([{ label: 'Attack-Pattern', value: 2 }]);
      expect(paris).toEqual([{ label: 'Attack-Pattern', value: 1 }]);
    });

    it('should not widen the scope beyond the coverage when fromId is empty', async () => {
      const args = { field: 'entity_type', operation: 'count', relationship_type: [RELATION_HAS_COVERED], fromId: [] };
      expect(await findCoveredEntitiesDistribution(testContext, ADMIN_USER, scA, args)).toEqual([{ label: 'Attack-Pattern', value: 2 }]);
    });
  });

  describe('Function loadSecurityCoverageResults() with results restricted by marking', () => {
    let securityCoverage: BasicStoreEntitySecurityCoverage;
    let scrFirst: BasicStoreEntitySecurityCoverageResult;
    let scrMarked: BasicStoreEntitySecurityCoverageResult;
    let scrLast: BasicStoreEntitySecurityCoverageResult;

    // The context of a GraphQL resolver, with its batch loaders
    const resolverContext = (user: AuthUser) => {
      const context = executionContext('test', user);
      context.batch = computeLoaders(context, user);
      return context;
    };

    beforeAll(async () => {
      // No external_uri: no SecurityCoverageResult is created automatically
      const created = await addSecurityCoverage(adminContext, ADMIN_USER, { ...BASE_INPUT(), name: 'sc-restricted' });
      // A real result named "Restricted" must stay listed: the filtering never relies on the name
      scrFirst = await addSecurityCoverageResult(adminContext, ADMIN_USER, { resultOf: created.id, name: 'Restricted', external_uri: 'https://first.oaev.test' });
      scrMarked = await addSecurityCoverageResult(adminContext, ADMIN_USER, {
        resultOf: created.id,
        name: 'OAEV Marked',
        external_uri: 'https://marked.oaev.test',
        objectMarking: [MARKING_TLP_AMBER],
      });
      scrLast = await addSecurityCoverageResult(adminContext, ADMIN_USER, { resultOf: created.id, name: 'OAEV Last', external_uri: 'https://last.oaev.test' });
      // Reload: the results are read from the result ids of the SecurityCoverage entity
      securityCoverage = await findById(testContext, ADMIN_USER, created.id);
    });

    afterAll(async () => {
      await securityCoverageDelete(testContext, ADMIN_USER, securityCoverage.id);
    });

    it('should return every result to a user who can access them all, in the order of the result ids', async () => {
      const resultIds = getSecurityCoverageResultIds(securityCoverage);
      expect([...resultIds].sort()).toEqual([scrFirst.id, scrMarked.id, scrLast.id].sort());
      const results = await loadSecurityCoverageResults(resolverContext(ADMIN_USER), ADMIN_USER, securityCoverage);
      expect(results.map((r) => r.id)).toEqual(resultIds);
    });

    it('should not return the results of a marking the user cannot access, nor a placeholder for them', async () => {
      const userWithoutMarking = buildStandardUser([], [], [{ name: 'KNOWLEDGE' }]);
      const resultIds = getSecurityCoverageResultIds(securityCoverage);
      const results = await loadSecurityCoverageResults(resolverContext(userWithoutMarking), userWithoutMarking, securityCoverage);
      // The order of the result ids is kept for the results left
      expect(results.map((r) => r.id)).toEqual(resultIds.filter((id) => id !== scrMarked.id));
      expect(results.map((r) => r.id)).not.toContain(scrMarked.id);
      // The real result named "Restricted" is kept
      expect(results.map((r) => r.name)).toContain('Restricted');
    });
  });
});
