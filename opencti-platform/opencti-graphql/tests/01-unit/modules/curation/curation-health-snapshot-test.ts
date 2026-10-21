import { readFileSync } from 'node:fs';
import path from 'node:path';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { type ArgumentNode, type FieldDefinitionNode, Kind, type ObjectTypeDefinitionNode, parse } from 'graphql';
import { createHealthSnapshot } from '../../../../src/modules/curation/curation-health';
import { withHealthSnapshotLock } from '../../../../src/modules/curation/curation-locks';
import { pageEntitiesConnection } from '../../../../src/database/middleware-loader';
import { createEntity } from '../../../../src/database/middleware';
import type { AuthContext } from '../../../../src/types/user';
import type { CurationSettings } from '../../../../src/modules/curation/curation-types';

vi.mock('../../../../src/modules/curation/curation-locks', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/curation/curation-locks')>()),
  withHealthSnapshotLock: vi.fn((fn: () => Promise<unknown>) => fn()),
}));
vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  pageEntitiesConnection: vi.fn(),
}));
vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware')>()),
  createEntity: vi.fn(),
}));

const context = {} as AuthContext;
const settings = {} as CurationSettings;
const latestSnapshot = (snapshotDate: string) => vi.mocked(pageEntitiesConnection).mockResolvedValue({
  edges: [{ node: { id: 'snapshot-latest', snapshot_date: snapshotDate, health_score: 80 } }],
} as never);

describe('Knowledge health snapshot creation', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('reads the latest snapshot under the snapshot lock, and returns one taken while the call waited', async () => {
    latestSnapshot(new Date(Date.now() + 1000).toISOString());
    const snapshot = await createHealthSnapshot(context, settings);
    expect(withHealthSnapshotLock).toHaveBeenCalledTimes(1);
    expect(snapshot.id).toBe('snapshot-latest');
    expect(createEntity).not.toHaveBeenCalled();
  });

  it('returns the latest snapshot when it is recent enough for the caller', async () => {
    latestSnapshot('2026-10-06T12:00:00.000Z');
    const snapshot = await createHealthSnapshot(context, settings, { reuseFrom: '2026-10-06T00:00:00.000Z' });
    expect(snapshot.id).toBe('snapshot-latest');
    expect(createEntity).not.toHaveBeenCalled();
  });
});

describe('Knowledge health refresh access', () => {
  // The refresh returns the snapshot the knowledgeHealth queries serve only with Access knowledge.
  it('requires Access knowledge and Manage customization together', () => {
    const schema = parse(readFileSync(path.join(__dirname, '../../../../src/modules/curation/curation.graphql'), 'utf8'));
    const mutation = schema.definitions.find((definition): definition is ObjectTypeDefinitionNode => (
      definition.kind === Kind.OBJECT_TYPE_DEFINITION && definition.name.value === 'Mutation'
    ));
    const field = mutation?.fields?.find((candidate: FieldDefinitionNode) => candidate.name.value === 'knowledgeHealthRefresh');
    const auth = field?.directives?.find((directive) => directive.name.value === 'auth');
    const argument = (name: string) => auth?.arguments?.find((candidate: ArgumentNode) => candidate.name.value === name)?.value;
    const capabilities = argument('for');
    expect(capabilities?.kind === Kind.LIST ? capabilities.values.map((value) => (value.kind === Kind.ENUM ? value.value : null)) : [])
      .toEqual(['KNOWLEDGE', 'SETTINGS_SETCUSTOMIZATION']);
    const and = argument('and');
    expect(and?.kind === Kind.BOOLEAN && and.value).toBe(true);
  });
});
