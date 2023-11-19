import { expect, it, describe } from 'vitest';
import { FIVE_MINUTES, TEN_SECONDS, testContext } from '../utils/testQuery';
import { activateRule, disableRule, getInferences, inferenceLookup } from '../utils/rule-utils';
import {
  createRelation,
  deleteElementById,
  deleteRelationsByFromAndTo,
} from '../../src/database/middleware';
import { SYSTEM_USER } from '../../src/utils/access';
import { RELATION_BASED_ON } from '../../src/schema/stixCoreRelationship';
import { RELATION_OBJECT } from '../../src/schema/stixRefRelationship';
import { addReport } from '../../src/domain/report';
import { elDeleteElements } from '../../src/database/engine';
import { wait } from '../../src/database/utils';
import { ABSTRACT_STIX_REF_RELATIONSHIP } from '../../src/schema/general';
import { listEntities } from '../../src/database/middleware-loader';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../src/schema/stixDomainObject';
import { addStixCyberObservable } from '../../src/domain/stixCyberObservable';
import { ENTITY_IPV4_ADDR } from '../../src/schema/stixCyberObservable';
import { addIndicator } from '../../src/domain/indicator';
import ReportRefsObservableBasedOnRule
  from '../../src/rules/report-refs-observable-based-on/ReportRefObservableBasedOnRule';

describe('Report refs observable rule', () => {
  it(
    'Should rule successfully activated',
    async () => {
      const createdElements = [];
      // Before rule activation
      // 1. Create the report, the first relation between A and B
      // ---- REPORT - ref - OBSERVABLE A
      // ---- INDICATOR B - based-on (REL01) - OBSERVABLE A
      // Rule activation
      // -> REPORT - ref - based-on (REL01)
      // -> REPORT - ref - INDICATOR B
      // 2. Create new entities and relation
      // ---- INDICATOR D - based-on (REL02) - OBSERVABLE C
      // ---- REPORT - ref - OBSERVABLE C
      // -> REPORT - ref - part of (REL02)
      // -> REPORT - ref - INDICATOR D
      // 3. Add new based on relation with INDICATOR E
      // A creation cascade must occurs
      // 4. Remove a ref from report
      // 5. Remove a based ib relation
      // Delete all reports
      const reports = await listEntities(testContext, SYSTEM_USER, [ENTITY_TYPE_CONTAINER_REPORT], { connectionFormat: false });
      await elDeleteElements(testContext, SYSTEM_USER, reports);

      // Check that no inferences exists
      const beforeActivationRelations = await getInferences(RELATION_OBJECT);
      expect(beforeActivationRelations.length).toBe(0);

      // region 1............................ Create the report, the first relation between A and B
      // OBSERVABLE A
      const observableA = await addStixCyberObservable(testContext, SYSTEM_USER, { type: ENTITY_IPV4_ADDR, IPv4Addr: { value: '8.8.8.8' } });
      createdElements.push(observableA);
      // INDICATOR B
      const indicatorB = await addIndicator(testContext, SYSTEM_USER, {
        name: '[ipv4-addr:value = \'8.8.8.8\']',
        pattern_type: 'stix',
        pattern: '[ipv4-addr:value = \'8.8.8.8\']',
        x_opencti_main_observable_type: ENTITY_IPV4_ADDR,
      });
      createdElements.push(indicatorB);
      // INDICATOR B - based on - OBSERVABLE A
      const indicatorBBasedOnObservableA = await createRelation(testContext, SYSTEM_USER, {
        fromId: indicatorB.internal_id,
        toId: observableA.internal_id,
        relationship_type: RELATION_BASED_ON
      });
      createdElements.push(indicatorBBasedOnObservableA);
      // Create Report TEST_RULE
      const report = await addReport(testContext, SYSTEM_USER, {
        name: 'Report TEST_RULE',
        description: 'Report TEST_RULE',
        published: '2022-10-06T22:00:00.000Z',
        objects: [observableA.internal_id],
      });
      createdElements.push(report);
      // Rule............................ activation
      // Activate rules
      await activateRule(ReportRefsObservableBasedOnRule.id);
      // Check database state
      const afterActivationRelations = await getInferences(RELATION_OBJECT);
      expect(afterActivationRelations.length).toBe(2);
      const indicatorBInReport = await inferenceLookup(afterActivationRelations, report.standard_id, indicatorB.standard_id, RELATION_OBJECT);
      expect(indicatorBInReport).not.toBeNull();
      const indicatorBBasedOnObservableAInReport = await inferenceLookup(afterActivationRelations, report.standard_id, indicatorBBasedOnObservableA.standard_id, RELATION_OBJECT);
      expect(indicatorBBasedOnObservableAInReport).not.toBeNull();
      // endregion

      // region 2............................ Create new entities and relation
      // OBSERVABLE C
      const observableC = await addStixCyberObservable(testContext, SYSTEM_USER, { type: ENTITY_IPV4_ADDR, IPv4Addr: { value: '8.8.4.4' } });
      createdElements.push(observableC);
      // INDICATOR D
      const indicatorD = await addIndicator(testContext, SYSTEM_USER, {
        name: '[ipv4-addr:value = \'8.8.4.4\']',
        pattern_type: 'stix',
        pattern: '[ipv4-addr:value = \'8.8.4.4\']',
        x_opencti_main_observable_type: ENTITY_IPV4_ADDR,
      });
      createdElements.push(indicatorD);
      // INDICATOR D - based on - OBSERVABLE C
      const indicatorDBasedOnObservableC = await createRelation(testContext, SYSTEM_USER, {
        fromId: indicatorD.internal_id,
        toId: observableC.internal_id,
        relationship_type: RELATION_BASED_ON
      });
      createdElements.push(indicatorDBasedOnObservableC);
      // Update report with OBSERVABLE C
      await addReport(testContext, SYSTEM_USER, {
        name: 'Report TEST_RULE',
        description: 'Report TEST_RULE',
        published: '2022-10-06T22:00:00.000Z',
        objects: [observableC.internal_id],
        update: true
      });
      await wait(TEN_SECONDS); // let some time to rule manager to create the elements
      const afterAddRelations = await getInferences(RELATION_OBJECT);
      expect(afterAddRelations.length).toBe(4);
      const indicatorDInReport = await inferenceLookup(afterAddRelations, report.standard_id, indicatorD.standard_id, RELATION_OBJECT);
      expect(indicatorDInReport).not.toBeNull();
      const indicatorDBasedOnObservableCInReport = await inferenceLookup(afterAddRelations, report.standard_id, indicatorDBasedOnObservableC.standard_id, RELATION_OBJECT);
      expect(indicatorDBasedOnObservableCInReport).not.toBeNull();
      // endregion

      // region 3............................ Create more entities and relations
      // INDICATOR E
      const indicatorE = await addIndicator(testContext, SYSTEM_USER, {
        name: '[ipv4-addr:value = \'8.8.4.3\']',
        pattern_type: 'stix',
        pattern: '[ipv4-addr:value = \'8.8.4.3\']',
        x_opencti_main_observable_type: ENTITY_IPV4_ADDR,
      });
      createdElements.push(indicatorE);
      const indicatorEBasedOnObservableC = await createRelation(testContext, SYSTEM_USER, {
        fromId: indicatorE.internal_id,
        toId: observableC.internal_id,
        relationship_type: RELATION_BASED_ON
      });
      createdElements.push(indicatorEBasedOnObservableC);
      await wait(TEN_SECONDS); // let some time to rule manager to create the elements
      const afterAddMoreRelations = await getInferences(RELATION_OBJECT);
      expect(afterAddMoreRelations.length).toBe(6);

      // region 4............................ Remove a ref from report
      await deleteRelationsByFromAndTo(
        testContext,
        SYSTEM_USER,
        report.internal_id,
        observableA.internal_id,
        RELATION_OBJECT,
        ABSTRACT_STIX_REF_RELATIONSHIP
      );
      await wait(TEN_SECONDS); // let some time to rule-manager to delete the elements
      const afterDeleteARelations = await getInferences(RELATION_OBJECT);
      expect(afterDeleteARelations.length).toBe(4);
      // endregion

      // region 5............................ Remove a based on relation
      await deleteElementById(testContext, SYSTEM_USER, indicatorDBasedOnObservableC.internal_id, indicatorDBasedOnObservableC.entity_type);
      await wait(TEN_SECONDS); // let some time to rule-manager to delete the elements
      const afterDeleteDERelations = await getInferences(RELATION_OBJECT);
      expect(afterDeleteDERelations.length).toBe(2);
      // endregion

      // Disable the rule
      await disableRule(ReportRefsObservableBasedOnRule.id);
      // Check the number of inferences
      const afterDisableRelations = await getInferences(RELATION_OBJECT);
      expect(afterDisableRelations.length).toBe(0);
      // Delete all creation
      await elDeleteElements(testContext, SYSTEM_USER, createdElements);
    },
    FIVE_MINUTES
  );
});
