import { describe, it, expect, vi, beforeEach } from 'vitest';

// Same infrastructure stubs as the sibling middleware unit tests, middleware.ts pulls in a lot at import time
vi.mock('../../../src/database/engine');
vi.mock('../../../src/database/redis', () => ({ notify: vi.fn(), redisAddDeletions: vi.fn() }));
vi.mock('../../../src/database/cache', () => ({
  getEntitiesMapFromCache: vi.fn(),
  getEntityFromCache: vi.fn(),
}));
vi.mock('../../../src/database/stream/stream-handler', () => ({
  storeCreateEntityEvent: vi.fn(),
  storeCreateRelationEvent: vi.fn(),
  storeDeleteEvent: vi.fn(),
  storeMergeEvent: vi.fn(),
  storeUpdateEvent: vi.fn(),
}));
vi.mock('../../../src/database/file-search', () => ({
  elUpdateRemovedFiles: vi.fn(),
}));
vi.mock('../../../src/listener/UserActionListener', () => ({
  publishUserAction: vi.fn(),
}));
vi.mock('../../../src/config/conf', async () => {
  const actual = await vi.importActual('../../../src/config/conf');
  return {
    ...(actual as object),
    logApp: { warn: vi.fn(), error: vi.fn(), info: vi.fn(), debug: vi.fn() },
    extendedErrors: false,
    BUS_TOPICS: {},
  };
});

import * as engine from '../../../src/database/engine';
import { logApp } from '../../../src/config/conf';
import { ALREADY_DELETED_ERROR } from '../../../src/config/errors';
import { deleteInferredRuleElement } from '../../../src/database/middleware';
import { INDEX_INFERRED_RELATIONSHIPS } from '../../../src/database/utils';
import { RULE_PREFIX } from '../../../src/schema/general';

const RULE = 'test_rule';
const DEPENDENCY_ID = 'dependency-id';

// Inference only explained by the deleted dependency, so its cleanup deletes it
const inference = {
  id: 'inference-id',
  entity_type: 'related-to',
  _index: `${INDEX_INFERRED_RELATIONSHIPS}-000001`,
  [`${RULE_PREFIX}${RULE}`]: [{ explanation: [DEPENDENCY_ID], dependencies: [DEPENDENCY_ID] }],
};

describe('deleteInferredRuleElement', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should not log an error when the inference has already been deleted', async () => {
    // The inference is not found anymore, so its deletion throws AlreadyDeletedError
    vi.mocked(engine.elFindByIds).mockResolvedValue([]);
    const deleted = await deleteInferredRuleElement(RULE, inference, [DEPENDENCY_ID]);
    expect(deleted).toBe(false);
    expect(logApp.error).not.toHaveBeenCalled();
    expect(logApp.info).toHaveBeenCalledWith(expect.objectContaining({
      extensions: expect.objectContaining({ code: ALREADY_DELETED_ERROR }),
    }));
  });

  it('should log an error when the inference deletion fails unexpectedly', async () => {
    const failure = new Error('Engine failure');
    vi.mocked(engine.elFindByIds).mockRejectedValue(failure);
    const deleted = await deleteInferredRuleElement(RULE, inference, [DEPENDENCY_ID]);
    expect(deleted).toBe(false);
    expect(logApp.error).toHaveBeenCalledWith('Error handling inference', { cause: failure });
  });
});
