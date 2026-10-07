import { beforeEach, describe, expect, it, vi } from 'vitest';
import '../../../../src/modules/index';
import { editCurationSettings } from '../../../../src/modules/curation/curation-domain';
import { saveCurationSettings } from '../../../../src/modules/curation/curation-settings';
import type { CurationSettings } from '../../../../src/modules/curation/curation-types';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

vi.mock('../../../../src/modules/curation/curation-settings', async (importOriginal) => {
  const { DEFAULT_CURATION_SETTINGS } = await import('../../../../src/modules/curation/curation-defaults');
  return {
    ...(await importOriginal<typeof import('../../../../src/modules/curation/curation-settings')>()),
    getCurationSettings: vi.fn(async () => DEFAULT_CURATION_SETTINGS),
    getCurationSettingsId: vi.fn(async () => 'settings-id'),
    saveCurationSettings: vi.fn(async () => DEFAULT_CURATION_SETTINGS),
  };
});
vi.mock('../../../../src/modules/curation/curation-adjudication', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/curation/curation-adjudication')>()),
  isAdjudicationAvailable: vi.fn(async () => false),
}));
vi.mock('../../../../src/modules/curation/curation-scan', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/curation/curation-scan')>()),
  isGraphSimilarityAvailable: vi.fn(async () => false),
}));

const context = {} as AuthContext;
const user = { id: 'admin-id' } as AuthUser;

describe('curation settings edit', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('clears the adjudication agent and run-as account with a null, and leaves the other settings a null names as they are', async () => {
    const input = {
      adjudication_agent_slug: null,
      adjudication_run_as_id: null,
      merge_record_retention_days: null,
      ambiguous_band_min: undefined,
      curation_enabled: false,
    } as unknown as Partial<CurationSettings>;
    await editCurationSettings(context, user, input);
    expect(saveCurationSettings).toHaveBeenCalledWith(
      context,
      user,
      { adjudication_agent_slug: null, adjudication_run_as_id: null, curation_enabled: false },
      expect.anything(),
    );
  });
});
