import { describe, it, expect } from 'vitest';
import { v4 as uuid } from 'uuid';
import moment from 'moment/moment';
import { findById as findWorkById, worksForConnector } from '../../../src/domain/work';
import { registerConnector } from '../../../src/domain/connector';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import type { RegisterConnectorInput } from '../../../src/generated/graphql';
import { ConnectorType } from '../../../src/generated/graphql';
import { elIndex } from '../../../src/database/engine';
import { ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_WORK } from '../../../src/schema/internalObject';
import { INDEX_HISTORY } from '../../../src/database/utils';
import { deleteCompletedWorks } from '../../../src/manager/connectorManager';
import type { BasicStoreEntityConnector } from '../../../src/types/connector';
import { addCreateInCounter } from '../../utils/testCountHelper';

describe('Old work of connector cleanup test', () => {
  let testConnector: BasicStoreEntityConnector;

  const createConnectorForTest = async () => {
    const connectorData: RegisterConnectorInput = {
      id: uuid(),
      name: 'test-connector-manager-fake-connector',
      type: ConnectorType.ExternalImport
    };
    testConnector = await registerConnector(testContext, ADMIN_USER, connectorData);
    addCreateInCounter(ENTITY_TYPE_CONNECTOR);
    expect(testConnector.id).toBeDefined();
  };

  const createWorkForTest = async (name:string, dateForWork: Date, status: string) => {
    // cheat and create a work in the past in elastic
    const dateForWorkStr = dateForWork.toISOString();
    const workId = `work_${testConnector.id}_${dateForWorkStr}`;

    const eightDaysAgoWork: Partial<Work> = {
      _index: '',
      completed_number: 10,
      completed_time: dateForWorkStr,
      connector_id: testConnector.id,
      entity_type: ENTITY_TYPE_WORK,
      errors: [],
      event_source_id: testConnector.id,
      event_type: '',
      id: workId,
      import_expected_number: 0,
      internal_id: workId,
      messages: [],
      name,
      processed_time: dateForWorkStr,
      received_time: dateForWorkStr,
      status,
      timestamp: dateForWorkStr,
      updated_at: dateForWorkStr,
      user_id: '',
    };

    await elIndex(INDEX_HISTORY, eightDaysAgoWork as Work);
    const workCreated = await findWorkById(testContext, ADMIN_USER, workId) as unknown as Work;
    expect(workCreated.id).toBeDefined();
    expect(workCreated.status).toBe(status);
    expect(workCreated.completed_time).toBeDefined();
    return workCreated;
  };

  it('should cleanup old finished works but not new ones', async () => {
    // GIVEN a connector that has 2 works in database
    // one older than connector_manager.works_day_range (default: 7 days) and one more recent
    await createConnectorForTest();

    await createWorkForTest('Work 8 days old and complete', moment().subtract('8', 'days').toDate(), 'complete');
    await createWorkForTest('Work 9 days old and not complete', moment().subtract('9', 'days').toDate(), 'wait');
    await createWorkForTest('Work 2 days old and complete', moment().subtract('2', 'days').toDate(), 'complete');

    const allWorkBeforeCleanup = await worksForConnector(testContext, ADMIN_USER, testConnector.id);
    expect(allWorkBeforeCleanup.length).toBe(3);
    expect(allWorkBeforeCleanup.some((workItem: Work) => workItem.name === 'Work 2 days old and complete')).toBeTruthy();
    expect(allWorkBeforeCleanup.some((workItem: Work) => workItem.name === 'Work 9 days old and not complete')).toBeTruthy();
    expect(allWorkBeforeCleanup.some((workItem: Work) => workItem.name === 'Work 8 days old and complete')).toBeTruthy();

    // WHEN the cleanup is done by manager
    await deleteCompletedWorks(testContext, testConnector);

    // THEN old complete one should be deleted and others still there
    const allWorkAfterCleanup: Work[] = await worksForConnector(testContext, ADMIN_USER, testConnector.id);
    expect(allWorkAfterCleanup.length).toBe(2);

    expect(allWorkAfterCleanup.some((workItem: Work) => workItem.name === 'Work 2 days old and complete')).toBeTruthy();
    expect(allWorkAfterCleanup.some((workItem: Work) => workItem.name === 'Work 9 days old and not complete')).toBeTruthy();
    expect(allWorkAfterCleanup.some((workItem: Work) => workItem.name === 'Work 8 days old and complete')).toBeFalsy();
  });
});
