import { beforeEach, describe, expect, it, vi } from 'vitest';
import '../../../../src/modules/index';
import { isEnterpriseEdition } from '../../../../src/enterprise-edition/ee';
import { findFiltersRepresentatives } from '../../../../src/domain/basicObject';
import type { FilterGroup } from '../../../../src/generated/graphql';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

const { stored, accessibleIdentities, accessiblePirs } = vi.hoisted(() => ({
  stored: new Map<string, Record<string, unknown>>(),
  accessibleIdentities: new Set<string>(),
  accessiblePirs: new Set<string>(),
}));

vi.mock('../../../../src/enterprise-edition/ee', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/enterprise-edition/ee')>()),
  isEnterpriseEdition: vi.fn(),
}));

vi.mock('../../../../src/database/cache', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/cache')>()),
  getEntitiesMapFromCache: vi.fn(async () => new Map([...stored].filter(([, entity]) => entity.entity_type === 'Source'))),
}));

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  storeLoadByIds: vi.fn(async (_context: unknown, _user: unknown, ids: string[]) => ids.map((id) => stored.get(id))),
  // The PIRs the user can access
  storeLoadById: vi.fn(async (_context: unknown, _user: unknown, id: string) => (accessiblePirs.has(id) ? { internal_id: id } : undefined)),
  internalFindByIds: vi.fn(async (_context: unknown, _user: unknown, ids: string[]) => ids
    .filter((id) => accessibleIdentities.has(id))
    .map((id) => ({ internal_id: id }))),
  fullEntitiesList: vi.fn(async (_context: unknown, _user: unknown, types: string[]) => (types.includes('Pir')
    ? [...accessiblePirs].map((id) => ({ internal_id: id }))
    : [...stored.values()].filter((entity) => entity.entity_type === 'Source'))),
}));

const analyst = { id: 'analyst', capabilities: [{ name: 'KNOWLEDGE' }, { name: 'MODULES_MODMANAGE' }] } as AuthUser;
const editor = { id: 'editor', capabilities: [{ name: 'KNOWLEDGE' }, { name: 'KNOWLEDGE_KNUPDATE' }] } as AuthUser;

const ENTITIES = [
  { internal_id: 'source-1', entity_type: 'Source', source_kind: 'author', ref_id: 'identity-1', name: 'Restricted CERT' },
  { internal_id: 'source-2', entity_type: 'Source', source_kind: 'author', ref_id: 'identity-2', name: 'Acme' },
  { internal_id: 'source-3', entity_type: 'Source', source_kind: 'connector', ref_id: 'connector-1', name: 'MISP' },
  { internal_id: 'rec-1', entity_type: 'SourceRecommendation', source_id: 'source-1', payload: '{}', name: 'Raise the confidence of Restricted CERT' },
  { internal_id: 'rec-2', entity_type: 'SourceRecommendation', source_id: null, pir_id: 'pir-2', payload: '{}', name: 'Deploy MISP for the finance PIR' },
  { internal_id: 'gap-1', entity_type: 'CollectionGap', pir_id: 'pir-1', name: 'Ransomware in Europe' },
  { internal_id: 'gap-2', entity_type: 'CollectionGap', pir_id: 'pir-2', name: 'Phishing in Asia' },
  { internal_id: 'malware-1', entity_type: 'Malware', name: 'Emotet' },
];

const representatives = async (user: AuthUser) => {
  const filters = { mode: 'and', filters: [{ key: ['ids'], values: ENTITIES.map((entity) => entity.internal_id) }], filterGroups: [] } as unknown as FilterGroup;
  const resolved = await findFiltersRepresentatives({} as AuthContext, user, filters);
  return Object.fromEntries(resolved.map((representative) => [representative.id, representative.value]));
};

describe('Source intelligence entities in the filter representatives', () => {
  beforeEach(() => {
    stored.clear();
    ENTITIES.forEach((entity) => stored.set(entity.internal_id, entity));
    accessibleIdentities.clear();
    accessibleIdentities.add('identity-2');
    accessiblePirs.clear();
    accessiblePirs.add('pir-1');
    vi.mocked(isEnterpriseEdition).mockResolvedValue(true);
  });

  it('should name an author the user cannot access Restricted, and serve nothing the Sources queries leave out', async () => {
    expect(await representatives(analyst)).toEqual({
      'source-1': 'Restricted',
      'source-2': 'Acme',
      'source-3': 'MISP',
      'rec-1': 'Raise the confidence of Restricted',
      'rec-2': null,
      'gap-1': 'Ransomware in Europe',
      'gap-2': null,
      'malware-1': 'Emotet',
    });
  });

  it('should serve none of them to a user without the Sources capabilities', async () => {
    expect(await representatives(editor)).toEqual({
      'source-1': null,
      'source-2': null,
      'source-3': null,
      'rec-1': null,
      'rec-2': null,
      'gap-1': null,
      'gap-2': null,
      'malware-1': 'Emotet',
    });
  });

  it('should serve no recommendation and no collection gap outside Enterprise Edition', async () => {
    vi.mocked(isEnterpriseEdition).mockResolvedValue(false);
    const values = await representatives(analyst);
    expect(values).toMatchObject({ 'source-1': 'Restricted', 'source-2': 'Acme', 'rec-1': null, 'gap-1': null, 'malware-1': 'Emotet' });
  });
});
