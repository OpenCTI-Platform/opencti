import { describe, expect, it } from 'vitest';

import { LegacyManifestAdapter } from '../../../../../src/modules/catalog/catalog-adapters';

describe('LegacyManifestAdapter', () => {
  it('returns internal catalog map and image cache matching legacy shape', async () => {
    const adapter = new LegacyManifestAdapter();

    const raw = await adapter.fetch({ kind: 'local', uri: 'embedded' });
    const internal = adapter.toInternalCatalog(raw);

    expect(internal.catalogMap).toBeDefined();
    expect(Object.keys(internal.catalogMap).length).toBeGreaterThan(0);
    expect(internal.contractsByImage).toBeInstanceOf(Map);
    expect(internal.contractsByImage.size).toBeGreaterThan(0);
  });
});
