import { expect, it, describe } from 'vitest';
import { ADMIN_USER, FIVE_MINUTES, TEN_SECONDS, testContext } from '../utils/testQuery';
import { shutdownModules, startModules } from '../../src/modules';
import { activateRule, disableRule, getInferences, inferenceLookup } from '../utils/rule-utils';
import {
  createRelation,
  deleteElementById,
  deleteRelationsByFromAndTo, internalDeleteElementById,
  storeLoadByIdWithRefs
} from '../../src/database/middleware';
import { SYSTEM_USER } from '../../src/utils/access';
import { RELATION_PART_OF } from '../../src/schema/stixCoreRelationship';
import { RELATION_OBJECT } from '../../src/schema/stixMetaRelationship';
import ReportRefsIdentityPartOfRule from '../../src/rules/report-refs-identity-part-of/ReportRefIdentityPartOfRule';
import { addReport } from '../../src/domain/report';
import { addOrganization } from '../../src/domain/organization';
import { elDeleteElements } from '../../src/database/engine';
import { wait } from '../../src/database/utils';
import { ABSTRACT_STIX_META_RELATIONSHIP } from '../../src/schema/general';
import { listEntities } from '../../src/database/middleware-loader';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../src/schema/stixDomainObject';

describe('Report refs identity rule', () => {
  it(
    'Should rule successfully activated',
    async () => {
      const createdElements = [];
      // Before rule activation
      // 1. Create the report, the first relation between A and B
      // ---- REPORT - ref - IDENTITY A
      // ---- IDENTITY A - part of (REL01) - IDENTITY B
      // Rule activation
      // -> REPORT - ref - part of (REL01)
      // -> REPORT - ref - IDENTITY B
      // 2. Create new entities and relation
      // ---- IDENTITY C - part of (REL02) - IDENTITY D
      // ---- REPORT - ref - IDENTITY C
      // -> REPORT - ref - part of (REL02)
      // -> REPORT - ref - IDENTITY D
      // 3. Add new part of relation (reverse order) with IDENTITY E and F I(D)- part of - I(E) - part of - I(F)
      // A creation cascade must occurs
      // -> REPORT - ref - part of (DE)
      // -> REPORT - ref - IDENTITY E
      // -> REPORT - ref - part of (EF)
      // -> REPORT - ref - IDENTITY F
      // 4. Remove a ref from report
      // 5. Remove a part of relation
      try { /* R */ await internalDeleteElementById(testContext, ADMIN_USER, 'report--f7c415dc-ad05-5344-a660-8b2a5a7f95a9'); } catch { /* empty */ }
      try { /* A */ await internalDeleteElementById(testContext, ADMIN_USER, 'identity--64205318-75a2-5432-af33-fd23c6674350'); } catch { /* empty */ }
      try { /* B */ await internalDeleteElementById(testContext, ADMIN_USER, 'identity--737fbae1-683b-5f44-8a13-aee74d894f15'); } catch { /* empty */ }
      try { /* C */ await internalDeleteElementById(testContext, ADMIN_USER, 'identity--039e6dd8-7496-5961-999c-ce14babbc365'); } catch { /* empty */ }
      try { /* D */ await internalDeleteElementById(testContext, ADMIN_USER, 'identity--1e93f9b8-94c6-545b-a12b-00bd69362de8'); } catch { /* empty */ }
      try { /* E */ await internalDeleteElementById(testContext, ADMIN_USER, 'identity--685fc232-fb4a-551f-811e-269a30207877'); } catch { /* empty */ }
      try { /* F */ await internalDeleteElementById(testContext, ADMIN_USER, 'identity--c5892349-e5d9-5a3c-a2f9-37e1a0cf01b6'); } catch { /* empty */ }
      // const A = await addOrganization(testContext, SYSTEM_USER, { name: 'Report TEST_RULE - IDENTITY A' });
      // console.log('A', A.standard_id);
      // const B = await addOrganization(testContext, SYSTEM_USER, { name: 'Report TEST_RULE - IDENTITY B' });
      // console.log('B', B.standard_id);
      // const C = await addOrganization(testContext, SYSTEM_USER, { name: 'Report TEST_RULE - IDENTITY C' });
      // console.log('C', C.standard_id);
      // const D = await addOrganization(testContext, SYSTEM_USER, { name: 'Report TEST_RULE - IDENTITY D' });
      // console.log('D', D.standard_id);
      // const E = await addOrganization(testContext, SYSTEM_USER, { name: 'Report TEST_RULE - IDENTITY E' });
      // console.log('E', E.standard_id);
      // const F = await addOrganization(testContext, SYSTEM_USER, { name: 'Report TEST_RULE - IDENTITY F' });
      // console.log('F', F.standard_id);
      // expect(null).not.toBeNull();

      await startModules();
      await wait(2 * TEN_SECONDS); // Wait for all managers to be started
      await disableRule(ReportRefsIdentityPartOfRule.id);

      // Delete all reports
      const reports = await listEntities(testContext, SYSTEM_USER, [ENTITY_TYPE_CONTAINER_REPORT], { connectionFormat: false });
      await elDeleteElements(testContext, SYSTEM_USER, reports, storeLoadByIdWithRefs);

      // Check that no inferences exists
      const beforeActivationRelations = await getInferences(RELATION_OBJECT);
      expect(beforeActivationRelations.length).toBe(0);

      // region 1............................ Create the report, the first relation between A and B
      // IDENTITY A
      const identityA = await addOrganization(testContext, SYSTEM_USER, { name: 'Report TEST_RULE - IDENTITY A' });
      createdElements.push(identityA);
      // IDENTITY B
      const identityB = await addOrganization(testContext, SYSTEM_USER, { name: 'Report TEST_RULE - IDENTITY B' });
      createdElements.push(identityB);
      // IDENTITY A - part of - IDENTITY B
      const identityABParOf = await createRelation(testContext, SYSTEM_USER, {
        fromId: identityA.internal_id,
        toId: identityB.internal_id,
        relationship_type: RELATION_PART_OF
      });
      createdElements.push(identityABParOf);
      // Create Report TEST_RULE
      const report = await addReport(testContext, SYSTEM_USER, {
        name: 'Report TEST_RULE',
        description: 'Report TEST_RULE',
        published: '2022-10-06T22:00:00.000Z',
        objects: [identityA.internal_id],
      });
      createdElements.push(report);
      // Rule............................ activation
      // Activate rules
      await activateRule(ReportRefsIdentityPartOfRule.id);
      // Check database state
      const afterActivationRelations = await getInferences(RELATION_OBJECT);
      expect(afterActivationRelations.length).toBe(2);
      const identityBInReport = await inferenceLookup(afterActivationRelations, report.standard_id, identityB.standard_id, RELATION_OBJECT);
      expect(identityBInReport).not.toBeNull();
      const relationABInReport = await inferenceLookup(afterActivationRelations, report.standard_id, identityABParOf.standard_id, RELATION_OBJECT);
      expect(relationABInReport).not.toBeNull();
      // endregion

      // region 2............................ Create new entities and relation
      // IDENTITY C
      const identityC = await addOrganization(testContext, SYSTEM_USER, { name: 'Report TEST_RULE - IDENTITY C' });
      createdElements.push(identityC);
      // IDENTITY D
      const identityD = await addOrganization(testContext, SYSTEM_USER, { name: 'Report TEST_RULE - IDENTITY D' });
      createdElements.push(identityD);
      // IDENTITY C - part of - IDENTITY D
      const identityCDParOf = await createRelation(testContext, SYSTEM_USER, {
        fromId: identityC.internal_id,
        toId: identityD.internal_id,
        relationship_type: RELATION_PART_OF
      });
      createdElements.push(identityCDParOf);
      // Update report with IDENTITY C
      await addReport(testContext, SYSTEM_USER, {
        name: 'Report TEST_RULE',
        description: 'Report TEST_RULE',
        published: '2022-10-06T22:00:00.000Z',
        objects: [identityC.internal_id],
        update: true
      });
      await wait(TEN_SECONDS); // let some time to rule manager to create the elements
      const afterAddRelations = await getInferences(RELATION_OBJECT);
      expect(afterAddRelations.length).toBe(4);
      const identityDInReport = await inferenceLookup(afterAddRelations, report.standard_id, identityD.standard_id, RELATION_OBJECT);
      expect(identityDInReport).not.toBeNull();
      const relationCDInReport = await inferenceLookup(afterAddRelations, report.standard_id, identityCDParOf.standard_id, RELATION_OBJECT);
      expect(relationCDInReport).not.toBeNull();
      // endregion

      // region 3............................ Add new part of relation with IDENTITY E and F I(D)- part of - I(E) - part of - I(F)
      // Create IDENTITY E/F and the relation from I(D)- part of - I(E) - part of - I(F)
      // D is already inside the report through the inference so E will be also added.
      const identityE = await addOrganization(testContext, SYSTEM_USER, { name: 'Report TEST_RULE - IDENTITY E' });
      createdElements.push(identityE);
      const identityF = await addOrganization(testContext, SYSTEM_USER, { name: 'Report TEST_RULE - IDENTITY F' });
      createdElements.push(identityF);
      const identityEFParOf = await createRelation(testContext, SYSTEM_USER, {
        fromId: identityE.internal_id,
        toId: identityF.internal_id,
        relationship_type: RELATION_PART_OF
      });
      createdElements.push(identityEFParOf);
      const afterCreateEFRelations = await getInferences(RELATION_OBJECT);
      expect(afterCreateEFRelations.length).toBe(4); // Nothing change
      const identityDEParOf = await createRelation(testContext, SYSTEM_USER, {
        fromId: identityD.internal_id,
        toId: identityE.internal_id,
        relationship_type: RELATION_PART_OF
      });
      await wait(TEN_SECONDS); // let some time to rule manager to create the elements
      const afterCreateDERelations = await getInferences(RELATION_OBJECT);
      expect(afterCreateDERelations.length).toBe(8); // I(E) + REL(DE) + I(F) + REL (EF)
      const identityEInReport = await inferenceLookup(afterCreateDERelations, report.standard_id, identityE.standard_id, RELATION_OBJECT);
      expect(identityEInReport).not.toBeNull();
      const relationDEInReport = await inferenceLookup(afterCreateDERelations, report.standard_id, identityDEParOf.standard_id, RELATION_OBJECT);
      expect(relationDEInReport).not.toBeNull();
      const identityFInReport = await inferenceLookup(afterCreateDERelations, report.standard_id, identityF.standard_id, RELATION_OBJECT);
      expect(identityFInReport).not.toBeNull();
      const relationEFInReport = await inferenceLookup(afterCreateDERelations, report.standard_id, identityEFParOf.standard_id, RELATION_OBJECT);
      expect(relationEFInReport).not.toBeNull();
      // endregion

      // region 4............................ Remove a ref from report
      await deleteRelationsByFromAndTo(
        testContext,
        SYSTEM_USER,
        report.internal_id,
        identityA.internal_id,
        RELATION_OBJECT,
        ABSTRACT_STIX_META_RELATIONSHIP
      );
      await wait(TEN_SECONDS); // let some time to rule-manager to delete the elements
      const afterDeleteARelations = await getInferences(RELATION_OBJECT);
      expect(afterDeleteARelations.length).toBe(6); // IdentityB + Rel A-> part-of ->B
      // endregion

      // region 5............................ Remove a part of relation
      await deleteElementById(testContext, SYSTEM_USER, identityDEParOf.internal_id, identityDEParOf.entity_type);
      await wait(TEN_SECONDS); // let some time to rule-manager to delete the elements
      const afterDeleteDERelations = await getInferences(RELATION_OBJECT);
      expect(afterDeleteDERelations.length).toBe(2);
      // endregion

      // Disable the rule
      await disableRule(ReportRefsIdentityPartOfRule.id);
      // Check the number of inferences
      const afterDisableRelations = await getInferences(RELATION_OBJECT);
      expect(afterDisableRelations.length).toBe(0);
      // Delete all creation
      await elDeleteElements(testContext, SYSTEM_USER, createdElements, storeLoadByIdWithRefs);
      // Stop modules
      await shutdownModules();
    },
    FIVE_MINUTES
  );
});
