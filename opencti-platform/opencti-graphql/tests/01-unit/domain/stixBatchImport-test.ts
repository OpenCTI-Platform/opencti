import { describe, expect, it, vi, beforeEach } from 'vitest';
import { stixObjectsBatchImport } from '../../../src/domain/stixBatchImport';
import { addMalware } from '../../../src/domain/malware';
import { addTool } from '../../../src/domain/tool';
import { addVulnerability } from '../../../src/domain/vulnerability';
import { addStixCyberObservable } from '../../../src/domain/stixCyberObservable';
import type { AuthContext, AuthUser } from '../../../src/types/user';

// ---------------------------------------------------------------------------
// Module mocks – stixObjectsBatchImport only dispatches to these 4 domain
// functions (see STIX_BATCH_IMPORT_KINDS in src/domain/stixBatchImport.ts).
// Each is mocked so the resolver's own dispatch/catch-and-continue logic is
// tested in isolation from the real create/lock/index side effects, which are
// already covered by the existing single-object mutation tests.
// ---------------------------------------------------------------------------

vi.mock('../../../src/domain/malware', () => ({
  addMalware: vi.fn(),
}));

vi.mock('../../../src/domain/tool', () => ({
  addTool: vi.fn(),
}));

vi.mock('../../../src/domain/vulnerability', () => ({
  addVulnerability: vi.fn(),
}));

vi.mock('../../../src/domain/stixCyberObservable', () => ({
  addStixCyberObservable: vi.fn(),
}));

const testContext = { source: 'test' } as unknown as AuthContext;
const testUser = { id: 'test-user-id' } as unknown as AuthUser;

describe('stixObjectsBatchImport', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('dispatches each item to its corresponding domain create function', async () => {
    vi.mocked(addMalware).mockResolvedValue({ standard_id: 'malware--1' } as never);
    vi.mocked(addTool).mockResolvedValue({ standard_id: 'tool--1' } as never);
    vi.mocked(addVulnerability).mockResolvedValue({ standard_id: 'vulnerability--1' } as never);
    vi.mocked(addStixCyberObservable).mockResolvedValue({ standard_id: 'ipv4-addr--1' } as never);

    const items = [
      { kind: 'malware' as const, input: { name: 'Emotet' } },
      { kind: 'tool' as const, input: { name: 'Mimikatz' } },
      { kind: 'vulnerability' as const, input: { name: 'CVE-2024-0001' } },
      { kind: 'stix_cyber_observable' as const, input: { type: 'IPv4-Addr', value: '1.1.1.1' } },
    ];

    const results = await stixObjectsBatchImport(testContext, testUser, items);

    expect(addMalware).toHaveBeenCalledWith(testContext, testUser, { name: 'Emotet' });
    expect(addTool).toHaveBeenCalledWith(testContext, testUser, { name: 'Mimikatz' });
    expect(addVulnerability).toHaveBeenCalledWith(testContext, testUser, { name: 'CVE-2024-0001' });
    expect(addStixCyberObservable).toHaveBeenCalledWith(testContext, testUser, { type: 'IPv4-Addr', value: '1.1.1.1' });

    expect(results).toEqual([
      { id: 'malware--1', success: true, error: null },
      { id: 'tool--1', success: true, error: null },
      { id: 'vulnerability--1', success: true, error: null },
      { id: 'ipv4-addr--1', success: true, error: null },
    ]);
  });

  it('falls back to internal_id when standard_id is not present on the created element', async () => {
    vi.mocked(addMalware).mockResolvedValue({ internal_id: 'internal-1' } as never);

    const results = await stixObjectsBatchImport(
      testContext,
      testUser,
      [{ kind: 'malware', input: { name: 'Emotet' } }],
    );

    expect(results).toEqual([{ id: 'internal-1', success: true, error: null }]);
  });

  it('isolates a single item failure without aborting the rest of the batch (catch-and-continue)', async () => {
    vi.mocked(addMalware).mockResolvedValue({ standard_id: 'malware--1' } as never);
    vi.mocked(addTool).mockRejectedValue(new Error('Tool creation failed: missing required field'));
    vi.mocked(addVulnerability).mockResolvedValue({ standard_id: 'vulnerability--1' } as never);

    const items = [
      { kind: 'malware' as const, input: { name: 'Emotet' } },
      { kind: 'tool' as const, input: {} },
      { kind: 'vulnerability' as const, input: { name: 'CVE-2024-0001' } },
    ];

    const results = await stixObjectsBatchImport(testContext, testUser, items);

    // Index-aligned with the input items: item 1's failure must not affect items 0/2.
    expect(results).toEqual([
      { id: 'malware--1', success: true, error: null },
      { id: null, success: false, error: 'Tool creation failed: missing required field' },
      { id: 'vulnerability--1', success: true, error: null },
    ]);
    expect(addMalware).toHaveBeenCalledTimes(1);
    expect(addVulnerability).toHaveBeenCalledTimes(1);
  });

  it('stringifies non-Error thrown values into the error field', async () => {
    // eslint-disable-next-line prefer-promise-reject-errors
    vi.mocked(addMalware).mockRejectedValue('raw string rejection');

    const results = await stixObjectsBatchImport(
      testContext,
      testUser,
      [{ kind: 'malware', input: { name: 'Emotet' } }],
    );

    expect(results).toEqual([{ id: null, success: false, error: 'raw string rejection' }]);
  });

  it('returns an empty result array for an empty batch', async () => {
    const results = await stixObjectsBatchImport(testContext, testUser, []);
    expect(results).toEqual([]);
    expect(addMalware).not.toHaveBeenCalled();
  });
});
