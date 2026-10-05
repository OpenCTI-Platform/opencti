import { describe, expect, it } from 'vitest';
import '../../../src/modules/index';
import { PLATFORM_LOCAL_HISTORY_TYPES } from '../../../src/database/platform-local-history';
import { isStixExportableInStreamData } from '../../../src/schema/stixCoreObject';
import { ENTITY_TYPE_MALWARE } from '../../../src/schema/stixDomainObject';
import type { StoreObject } from '../../../src/types/store';

const instance = (entity_type: string) => ({ entity_type }) as unknown as StoreObject;

describe('Platform local history', () => {
  it('should publish no stream event for the trash, merge history and curation findings, so no synchronizer receives them', () => {
    expect(PLATFORM_LOCAL_HISTORY_TYPES).toHaveLength(3);
    PLATFORM_LOCAL_HISTORY_TYPES.forEach((type) => {
      expect(isStixExportableInStreamData(instance(type)), type).toBe(false);
    });
  });
  it('should keep publishing the knowledge itself', () => {
    expect(isStixExportableInStreamData(instance(ENTITY_TYPE_MALWARE))).toBe(true);
  });
});
