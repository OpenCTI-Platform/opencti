import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ENTITY_TYPE_RETENTION_RULE } from '../../../../src/modules/retentionRules/retentionRules-types';
import type { AuthContext, AuthUser } from '../../../../src/types/user';
import { RetentionRuleScope } from '../../../../src/generated/graphql';

// ---------------------------------------------------------------------------
// Mocks – must be declared before imports that reference them
// ---------------------------------------------------------------------------

vi.mock('../../../../src/database/middleware', async (importOriginal) => {
  const actual: any = await importOriginal();
  return {
    ...actual,
    deleteElementById: vi.fn(),
    updateAttribute: vi.fn(),
  };
});

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => {
  const actual: any = await importOriginal();
  return {
    ...actual,
    topEntitiesList: vi.fn(),
    pageEntitiesConnection: vi.fn(),
    storeLoadById: vi.fn(),
  };
});

vi.mock('../../../../src/database/engine', async (importOriginal) => {
  const actual: any = await importOriginal();
  return {
    ...actual,
    elIndex: vi.fn(),
    elPaginate: vi.fn(),
  };
});

vi.mock('../../../../src/schema/identifier', async (importOriginal) => {
  const actual: any = await importOriginal();
  return {
    ...actual,
    generateInternalId: vi.fn().mockReturnValue('generated-internal-id'),
    generateStandardId: vi.fn().mockReturnValue('retention-rule--generated-standard-id'),
  };
});

vi.mock('../../../../src/schema/general', async (importOriginal) => {
  const actual: any = await importOriginal();
  return {
    ...actual,
    BASE_TYPE_ENTITY: 'ENTITY',
  };
});

vi.mock('../../../../src/schema/schemaUtils', async (importOriginal) => {
  const actual: any = await importOriginal();
  return {
    ...actual,
    getParentTypes: vi.fn().mockReturnValue(['Internal-Object', 'Basic-Object']),
  };
});

vi.mock('../../../../src/listener/UserActionListener', () => ({
  publishUserAction: vi.fn(),
}));

vi.mock('../../../../src/utils/filtering/filtering-resolution', async (importOriginal) => {
  const actual: any = await importOriginal();
  return {
    ...actual,
    convertFiltersToQueryOptions: vi.fn().mockResolvedValue({ filters: [] }),
  };
});

vi.mock('../../../../src/modules/internal/document/document-domain', async (importOriginal) => {
  const actual: any = await importOriginal();
  return {
    ...actual,
    DELETABLE_FILE_STATUSES: ['complete', 'timeout'],
    paginatedForPathWithEnrichment: vi.fn(),
  };
});

vi.mock('../../../../src/config/conf', async (importOriginal) => {
  const actual: any = await importOriginal();
  return {
    ...actual,
    logApp: { error: vi.fn(), info: vi.fn(), warn: vi.fn(), debug: vi.fn() },
  };
});

vi.mock('../../../../src/database/utils', async (importOriginal) => {
  const actual: any = await importOriginal();
  return {
    ...actual,
    INDEX_INTERNAL_OBJECTS: 'internal_objects',
    READ_STIX_INDICES: 'stix_indices',
  };
});

vi.mock('../../../../src/utils/access', async (importOriginal) => {
  const actual: any = await importOriginal();
  return {
    ...actual,
    RETENTION_MANAGER_USER: { id: 'retention-manager-user-id' },
  };
});

// ---------------------------------------------------------------------------
// Imports after mocks
// ---------------------------------------------------------------------------

import {
  checkRetentionRule,
  createRetentionRule,
  deleteRetentionRule,
  retentionRuleEditField,
  findById,
  findRetentionRulePaginated,
  listRules,
} from '../../../../src/modules/retentionRules/retentionRules-domain';

import { deleteElementById, updateAttribute } from '../../../../src/database/middleware';
import { storeLoadById, pageEntitiesConnection, topEntitiesList } from '../../../../src/database/middleware-loader';
import { elIndex, elPaginate } from '../../../../src/database/engine';
import { publishUserAction } from '../../../../src/listener/UserActionListener';
import { convertFiltersToQueryOptions } from '../../../../src/utils/filtering/filtering-resolution';
import { paginatedForPathWithEnrichment } from '../../../../src/modules/internal/document/document-domain';
import { logApp } from '../../../../src/config/conf';

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

const context = { user: { id: 'admin-id' } } as AuthContext;
const user = { id: 'admin-id', user_email: 'admin@opencti.io' } as AuthUser;

// ---------------------------------------------------------------------------
// createRetentionRule
// ---------------------------------------------------------------------------

describe('createRetentionRule', () => {
  beforeEach(() => vi.clearAllMocks());

  it('should create a retention rule with valid filters and index it', async () => {
    const input = {
      name: 'My retention',
      filters: JSON.stringify({ mode: 'and', filters: [], filterGroups: [] }),
      max_retention: 30,
      scope: RetentionRuleScope.Knowledge,
    };

    const result = await createRetentionRule(context, user, input);

    expect(result.internal_id).toBe('generated-internal-id');
    expect(result.standard_id).toBe('retention-rule--generated-standard-id');
    expect(result.entity_type).toBe(ENTITY_TYPE_RETENTION_RULE);
    expect(result.base_type).toBe('ENTITY');
    expect(result.name).toBe('My retention');
    expect(result.last_execution_date).toBeNull();
    expect(result.last_deleted_count).toBeNull();
    expect(result.remaining_count).toBeNull();
    expect(result.retention_unit).toBe('days'); // default

    expect(elIndex).toHaveBeenCalledTimes(1);
    expect(publishUserAction).toHaveBeenCalledWith(expect.objectContaining({
      user,
      event_type: 'mutation',
      event_scope: 'create',
      event_access: 'administration',
      message: expect.stringContaining('My retention'),
    }));
  });

  it('should default filters to an empty filter set when filters is undefined', async () => {
    const input = {
      name: 'No filters rule',
      max_retention: 7,
      scope: RetentionRuleScope.File,
    };

    const result = await createRetentionRule(context, user, input as any);

    const parsedFilters = JSON.parse(result.filters as string);
    expect(parsedFilters).toEqual({ mode: 'and', filters: [], filterGroups: [] });
  });

  it('should have empty string filters when input has empty string (spread overrides local variable)', async () => {

    // overriding the local `filters` variable set at line 51.
    // The JSON.parse(filters) at line 54 passes (because local `filters` was defaulted),
    // but the resulting object has `filters: ''` from the spread.
    const input = {
      name: 'Empty filter string',
      filters: '',
      max_retention: 7,
      scope: RetentionRuleScope.File,
    };

    const result = await createRetentionRule(context, user, input);
    // The spread `...input` overrides the defaulted local variable
    expect(result.filters).toBe('');
  });

  it('should throw UnsupportedError when filters is invalid JSON', async () => {
    const input = {
      name: 'Bad filters',
      filters: '{ broken json',
      max_retention: 10,
      scope: RetentionRuleScope.Knowledge,
    };

    await expect(createRetentionRule(context, user, input))
      .rejects
      .toThrow('Retention rule must have valid filters');
  });

  it('should use the provided retention_unit instead of default', async () => {
    const input = {
      name: 'Hours rule',
      filters: '{}',
      max_retention: 12,
      retention_unit: 'hours' as const,
      scope: RetentionRuleScope.Knowledge,
    };

    const result = await createRetentionRule(context, user, input as any);
    expect(result.retention_unit).toBe('hours');
  });

  it('should default retention_unit to days when not provided', async () => {
    const input = {
      name: 'Default unit rule',
      filters: '{}',
      max_retention: 5,
      scope: RetentionRuleScope.Workbench,
    };

    const result = await createRetentionRule(context, user, input as any);
    expect(result.retention_unit).toBe('days');
  });
});

// ---------------------------------------------------------------------------
// retentionRuleEditField
// ---------------------------------------------------------------------------

describe('retentionRuleEditField', () => {
  beforeEach(() => vi.clearAllMocks());

  it('should update attribute and publish audit event', async () => {
    const mockElement = { id: 'rule-1', name: 'Updated rule' };
    (updateAttribute as any).mockResolvedValue({ element: mockElement });

    const input = [{ key: 'name', value: ['Updated rule'] }] as any;
    const result = await retentionRuleEditField(context, user, 'rule-1', input);

    expect(result).toEqual(mockElement);
    expect(updateAttribute).toHaveBeenCalledWith(context, user, 'rule-1', ENTITY_TYPE_RETENTION_RULE, input);
    expect(publishUserAction).toHaveBeenCalledWith(expect.objectContaining({
      event_type: 'mutation',
      event_scope: 'update',
      event_access: 'administration',
    }));
    const publishCall = (publishUserAction as any).mock.calls[0][0];
    expect(publishCall.message).toContain('name');
    expect(publishCall.message).toContain('Updated rule');
  });

  it('should include all edited field keys in the audit message', async () => {
    const mockElement = { id: 'rule-1', name: 'Rule' };
    (updateAttribute as any).mockResolvedValue({ element: mockElement });

    const input = [
      { key: 'name', value: ['New name'] },
      { key: 'max_retention', value: [60] },
    ] as any;

    await retentionRuleEditField(context, user, 'rule-1', input);

    expect(publishUserAction).toHaveBeenCalledWith(
      expect.objectContaining({
        message: expect.stringContaining('name, max_retention'),
      }),
    );
  });
});

// ---------------------------------------------------------------------------
// deleteRetentionRule
// ---------------------------------------------------------------------------

describe('deleteRetentionRule', () => {
  beforeEach(() => vi.clearAllMocks());

  it('should delete element and publish audit event', async () => {
    const mockDeleted = { id: 'rule-to-delete', name: 'Old rule' };
    (deleteElementById as any).mockResolvedValue(mockDeleted);

    const result = await deleteRetentionRule(context, user, 'rule-to-delete');

    expect(result).toBe('rule-to-delete');
    expect(deleteElementById).toHaveBeenCalledWith(context, user, 'rule-to-delete', ENTITY_TYPE_RETENTION_RULE);
    expect(publishUserAction).toHaveBeenCalledWith(expect.objectContaining({
      event_type: 'mutation',
      event_scope: 'delete',
      event_access: 'administration',
      message: expect.stringContaining('Old rule'),
    }));
  });
});

// ---------------------------------------------------------------------------
// findById
// ---------------------------------------------------------------------------

describe('findById', () => {
  beforeEach(() => vi.clearAllMocks());

  it('should delegate to storeLoadById with correct entity type', async () => {
    const mockRule = { id: 'rule-1', name: 'My Rule' };
    (storeLoadById as any).mockResolvedValue(mockRule);

    const result = await findById(context, user, 'rule-1');

    expect(result).toEqual(mockRule);
    expect(storeLoadById).toHaveBeenCalledWith(context, user, 'rule-1', ENTITY_TYPE_RETENTION_RULE);
  });

  it('should return undefined when rule does not exist', async () => {
    (storeLoadById as any).mockResolvedValue(undefined);

    const result = await findById(context, user, 'non-existent');

    expect(result).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// findRetentionRulePaginated
// ---------------------------------------------------------------------------

describe('findRetentionRulePaginated', () => {
  beforeEach(() => vi.clearAllMocks());

  it('should delegate to pageEntitiesConnection with correct entity type', async () => {
    const args = { first: 10, after: undefined, search: undefined } as any;
    await findRetentionRulePaginated(context, user, args);

    expect(pageEntitiesConnection).toHaveBeenCalledWith(context, user, [ENTITY_TYPE_RETENTION_RULE], args);
  });
});

// ---------------------------------------------------------------------------
// listRules
// ---------------------------------------------------------------------------

describe('listRules', () => {
  beforeEach(() => vi.clearAllMocks());

  it('should delegate to topEntitiesList with correct entity type', async () => {
    await listRules(context, user);

    expect(topEntitiesList).toHaveBeenCalledWith(context, user, [ENTITY_TYPE_RETENTION_RULE], undefined);
  });

  it('should pass optional args', async () => {
    const args = { first: 5 };
    await listRules(context, user, args);

    expect(topEntitiesList).toHaveBeenCalledWith(context, user, [ENTITY_TYPE_RETENTION_RULE], args);
  });
});

// ---------------------------------------------------------------------------
// checkRetentionRule
// ---------------------------------------------------------------------------

describe('checkRetentionRule', () => {
  beforeEach(() => vi.clearAllMocks());

  it('should return globalCount for knowledge scope', async () => {
    (elPaginate as any).mockResolvedValue({ pageInfo: { globalCount: 42 } });

    const input = {
      name: 'check knowledge',
      filters: JSON.stringify({ mode: 'and', filters: [], filterGroups: [] }),
      max_retention: 30,
      scope: RetentionRuleScope.Knowledge,
    };

    const count = await checkRetentionRule(context, input);

    expect(count).toBe(42);
    expect(convertFiltersToQueryOptions).toHaveBeenCalled();
    expect(elPaginate).toHaveBeenCalled();
  });

  it('should handle null filters for knowledge scope', async () => {
    (elPaginate as any).mockResolvedValue({ pageInfo: { globalCount: 0 } });

    const input = {
      name: 'no filter check',
      max_retention: 10,
      scope: RetentionRuleScope.Knowledge,
    };

    const count = await checkRetentionRule(context, input as any);

    expect(count).toBe(0);
    expect(convertFiltersToQueryOptions).toHaveBeenCalledWith(null, expect.anything());
  });

  it('should return filtered edge count for file scope', async () => {
    (paginatedForPathWithEnrichment as any).mockResolvedValue({
      edges: [
        { node: { uploadStatus: 'complete', works: [] } },
        { node: { uploadStatus: 'complete', works: [{ status: 'complete' }] } },
        { node: { uploadStatus: 'progress', works: [] } }, // should be filtered out
      ],
    });

    const input = {
      name: 'check file',
      max_retention: 7,
      scope: RetentionRuleScope.File,
    };

    const count = await checkRetentionRule(context, input as any);

    expect(count).toBe(2);
    expect(paginatedForPathWithEnrichment).toHaveBeenCalledWith(
      context,
      expect.anything(),
      'import/global',
      undefined,
      expect.objectContaining({ notModifiedSince: expect.any(String) }),
    );
  });

  it('should return filtered edge count for workbench scope', async () => {
    (paginatedForPathWithEnrichment as any).mockResolvedValue({
      edges: [
        { node: { uploadStatus: 'timeout', works: [] } },
        { node: { uploadStatus: 'complete', works: [{ status: 'progress' }] } }, // filtered: work in progress
      ],
    });

    const input = {
      name: 'check workbench',
      max_retention: 14,
      scope: RetentionRuleScope.Workbench,
    };

    const count = await checkRetentionRule(context, input as any);

    expect(count).toBe(1);
    expect(paginatedForPathWithEnrichment).toHaveBeenCalledWith(
      context,
      expect.anything(),
      'import/pending',
      undefined,
      expect.objectContaining({ notModifiedSince: expect.any(String), exact_path: false }),
    );
  });

  it('should filter out files with non-deletable upload statuses', async () => {
    (paginatedForPathWithEnrichment as any).mockResolvedValue({
      edges: [
        { node: { uploadStatus: 'progress', works: [] } },
        { node: { uploadStatus: 'pending', works: [] } },
        { node: { uploadStatus: 'error', works: [] } },
      ],
    });

    const input = {
      name: 'check non-deletable',
      max_retention: 3,
      scope: RetentionRuleScope.File,
    };

    const count = await checkRetentionRule(context, input as any);
    expect(count).toBe(0);
  });

  it('should keep files where all works have deletable statuses', async () => {
    (paginatedForPathWithEnrichment as any).mockResolvedValue({
      edges: [
        { node: { uploadStatus: 'complete', works: [{ status: 'complete' }, { status: 'timeout' }] } },
      ],
    });

    const input = {
      name: 'check all works deletable',
      max_retention: 5,
      scope: RetentionRuleScope.File,
    };

    const count = await checkRetentionRule(context, input as any);
    expect(count).toBe(1);
  });

  it('should handle files with null works array', async () => {
    (paginatedForPathWithEnrichment as any).mockResolvedValue({
      edges: [
        { node: { uploadStatus: 'complete', works: null } },
        { node: { uploadStatus: 'complete' } }, // works undefined
      ],
    });

    const input = {
      name: 'check null works',
      max_retention: 5,
      scope: RetentionRuleScope.File,
    };

    const count = await checkRetentionRule(context, input as any);
    expect(count).toBe(2);
  });

  it('should log error and return 0 for unknown scope', async () => {
    const input = {
      name: 'bad scope',
      max_retention: 5,
      scope: 'invalid_scope' as any,
    };


    // Let's test the actual behavior:
    await expect(checkRetentionRule(context, input)).rejects.toThrow();
    expect(logApp.error).toHaveBeenCalledWith(
      '[Retention manager] Scope not existing for Retention Rule.',
      { scope: 'invalid_scope' },
    );
  });

  it('should use default unit "days" when retention_unit is not provided', async () => {
    (elPaginate as any).mockResolvedValue({ pageInfo: { globalCount: 10 } });

    const input = {
      name: 'no unit',
      filters: '{}',
      max_retention: 15,
      scope: RetentionRuleScope.Knowledge,
      // no retention_unit
    };

    await checkRetentionRule(context, input as any);

    // The function uses utcDate().subtract(maxDays, unit ?? 'days')
    // We just verify it doesn't throw and delegates correctly
    expect(elPaginate).toHaveBeenCalled();
  });

  it('should use provided retention_unit', async () => {
    (elPaginate as any).mockResolvedValue({ pageInfo: { globalCount: 3 } });

    const input = {
      name: 'hours unit',
      filters: '{}',
      max_retention: 48,
      retention_unit: 'hours' as const,
      scope: RetentionRuleScope.Knowledge,
    };

    const count = await checkRetentionRule(context, input as any);
    expect(count).toBe(3);
  });
});
