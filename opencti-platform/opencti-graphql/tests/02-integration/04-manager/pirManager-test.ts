import { beforeAll, describe, it, vi, expect } from 'vitest';
import type { ParsedPir } from '../../../src/modules/pir/pir-types';
import { FilterMode, FilterOperator, PirType } from '../../../src/generated/graphql';
import * as StixFiltering from '../../../src/utils/filtering/filtering-stix/stix-filtering';
import { isStixMatchFilterGroup_MockableForUnitTests } from '../../../src/utils/filtering/filtering-stix/stix-filtering';
import { checkEventOnPir } from '../../../src/manager/pirManager';
import type { AuthContext } from '../../../src/types/user';
import type { SseEvent } from '../../../src/types/event';
import { STIX_EXT_OCTI } from '../../../src/types/stix-2-1-extensions';

const TEST_PIR_TARGET_1 = 'locations--9b8fd9c3-1ca3-41c2-be13-730f35b166b2';
const TEST_PIR_TARGET_2 = 'locations--9b8fd9c3-1ca3-41c2-be13-730f35b166a3';
const TEST_PIR_CRITERION_1 = {
  weight: 2,
  filters: {
    mode: FilterMode.And,
    filterGroups: [],
    filters: [
      {
        key: ['toId'],
        values: [TEST_PIR_TARGET_1],
        operator: FilterOperator.Eq,
        mode: FilterMode.Or
      }
    ]
  }
};
const TEST_PIR_CRITERION_2 = {
  weight: 1,
  filters: {
    mode: FilterMode.And,
    filterGroups: [],
    filters: [
      {
        key: ['toId'],
        values: [TEST_PIR_TARGET_2],
        operator: FilterOperator.Eq,
        mode: FilterMode.Or
      }
    ]
  }
};

const TEST_PIR = {
  confidence: 100,
  entity_type: 'Pir',
  id: '0b900f85-4b19-4a3e-8092-719dc91d1148',
  internal_id: '0b900f85-4b19-4a3e-8092-719dc91d1148',
  name: 'TEST PIR',
  pir_type: PirType.ThreatLandscape,
  description: 'Super PIR',
  pir_rescan_days: 30,
  lastEventId: '1747916825083-0',
  pir_criteria: [TEST_PIR_CRITERION_1, TEST_PIR_CRITERION_2],
  pir_filters: {
    mode: FilterMode.And,
    filterGroups: [],
    filters: [{
      key: ['confidence'],
      values: [80],
      operator: FilterOperator.Gt,
      mode: FilterMode.Or
    }],
  },
} as ParsedPir;

const buildEvent = ({
  confidence = 100,
  target = '',
}) => {
  return {
    data: {
      type: 'relationship',
      relationship_type: 'targets',
      source_ref: 'malware--bb3bf652-fe46-4e1a-b2a8-d588f114a096',
      target_ref: target,
      confidence,
      extensions: {
        [STIX_EXT_OCTI]: {
          source_type: 'Malware',
        }
      }
    }
  } as SseEvent<any>;
};

const MOCK_RESOLUTION_MAP: Map<string, string> = new Map();

describe('pirManager: checkEventOnPir()', () => {
  const context = {} as AuthContext;

  beforeAll(() => {
    vi.spyOn(StixFiltering, 'isStixMatchFilterGroup')
      .mockImplementation(async (...args) => {
        return isStixMatchFilterGroup_MockableForUnitTests(...args, MOCK_RESOLUTION_MAP);
      });
  });

  it('should return empty array if does not match filters', async () => {
    const event = buildEvent({ confidence: 70, target: TEST_PIR_TARGET_1 });
    const matches = await checkEventOnPir(context, event, TEST_PIR);
    expect(matches).toEqual([]);
  });

  it('should return empty array if does not match criterias', async () => {
    const event = buildEvent({ confidence: 90, target: 'not matching ID' });
    const matches = await checkEventOnPir(context, event, TEST_PIR);
    expect(matches).toEqual([]);
  });

  it('should return target 1 if does match', async () => {
    const event = buildEvent({ confidence: 90, target: TEST_PIR_TARGET_1 });
    const matches = await checkEventOnPir(context, event, TEST_PIR);
    expect(matches).toEqual([TEST_PIR_CRITERION_1]);
  });

  it('should return target 2 if does match', async () => {
    const event = buildEvent({ confidence: 90, target: TEST_PIR_TARGET_2 });
    const matches = await checkEventOnPir(context, event, TEST_PIR);
    expect(matches).toEqual([TEST_PIR_CRITERION_2]);
  });
});
