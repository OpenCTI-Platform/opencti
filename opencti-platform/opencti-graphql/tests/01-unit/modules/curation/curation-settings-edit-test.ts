import { beforeEach, describe, expect, it, vi } from 'vitest';
import '../../../../src/modules/index';
import { curationSettingsForApi, editCurationSettings, requestCurationScan } from '../../../../src/modules/curation/curation-domain';
import { getCurationSettings, saveCurationSettings } from '../../../../src/modules/curation/curation-settings';
import { DEFAULT_CURATION_SETTINGS } from '../../../../src/modules/curation/curation-defaults';
import type { CurationSettings } from '../../../../src/modules/curation/curation-types';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

vi.mock('../../../../src/modules/curation/curation-settings', async (importOriginal) => {
  const { DEFAULT_CURATION_SETTINGS: defaults } = await import('../../../../src/modules/curation/curation-defaults');
  return {
    ...(await importOriginal<typeof import('../../../../src/modules/curation/curation-settings')>()),
    getCurationSettings: vi.fn(async () => defaults),
    getCurationSettingsId: vi.fn(async () => 'settings-id'),
    saveCurationSettings: vi.fn(async () => defaults),
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
// The curation manager is switched off in the test configuration: curation runs here whenever its setting is on.
vi.mock('../../../../src/modules/curation/curation-schedule', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/curation/curation-schedule')>()),
  isCurationRunning: vi.fn((curationEnabled: boolean) => curationEnabled),
}));

const context = {} as AuthContext;
const user = { id: 'admin-id' } as AuthUser;
type SaveOptions = { validate?: (merged: CurationSettings) => void };

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
      curation_enabled: true,
    } as unknown as Partial<CurationSettings>;
    await editCurationSettings(context, user, input);
    expect(saveCurationSettings).toHaveBeenCalledWith(
      context,
      user,
      { adjudication_agent_slug: null, adjudication_run_as_id: null, curation_enabled: true },
      expect.anything(),
    );
  });

  it('drops a pending scan request when curation is switched off, as no scan would ever clear it', async () => {
    await editCurationSettings(context, user, { curation_enabled: false });
    expect(saveCurationSettings).toHaveBeenCalledWith(context, user, { curation_enabled: false, force_scan: false }, expect.anything());
  });

  it('refuses staleness overrides the detection would not use', async () => {
    const twice = [{ entity_type: 'Indicator', months: 12 }, { entity_type: 'Indicator', months: 6 }];
    await expect(editCurationSettings(context, user, { stale_overrides: twice })).rejects.toThrow('Only one staleness override per entity type');
    const container = [{ entity_type: 'Report', months: 12 }];
    await expect(editCurationSettings(context, user, { stale_overrides: container })).rejects.toThrow('Staleness overrides only apply to knowledge entity types');
    expect(saveCurationSettings).not.toHaveBeenCalled();
    await editCurationSettings(context, user, { stale_overrides: [{ entity_type: 'Indicator', months: 12 }, { entity_type: 'Campaign', months: 36 }] });
    expect(saveCurationSettings).toHaveBeenCalledTimes(1);
  });

  it('refuses a numeric setting outside its range instead of saving another value', async () => {
    const refused: Array<[Partial<CurationSettings>, string]> = [
      [{ scan_max_entities_per_type: 1 }, 'The scan_max_entities_per_type must be a whole number between 100 and 100000'],
      [{ scan_max_entities_per_type: 100001 }, 'The scan_max_entities_per_type must be a whole number between 100 and 100000'],
      [{ merge_record_retention_days: 0 }, 'The merge_record_retention_days must be a whole number between 1 and 3650'],
      [{ digest_day: 7 }, 'The digest_day must be a whole number between 0 and 6'],
      [{ adjudication_daily_limit: 2.5 }, 'The adjudication_daily_limit must be a whole number between 0 and 10000'],
      [{ similarity_threshold: 0.4 }, 'The similarity_threshold must be a number between 0.5 and 1'],
      [{ behavior_threshold: 1.2 }, 'The behavior_threshold must be a number between 0.1 and 1'],
      [{ proposal_min_confidence: Number.NaN }, 'The proposal_min_confidence must be a number between 0 and 1'],
      [{ stale_overrides: [{ entity_type: 'Indicator', months: 0 }] }, 'The months of a staleness override must be a whole number between 1 and 240'],
    ];
    await Promise.all(refused.map(([input, message]) => expect(editCurationSettings(context, user, input)).rejects.toThrow(message)));
    expect(saveCurationSettings).not.toHaveBeenCalled();
    // The bounds themselves are valid.
    const bounds = { scan_max_entities_per_type: 100, merge_record_retention_days: 3650, digest_day: 0, similarity_threshold: 1, proposal_min_confidence: 0 };
    await editCurationSettings(context, user, bounds);
    expect(saveCurationSettings).toHaveBeenCalledWith(context, user, bounds, expect.anything());
  });
});

describe('curation scan request', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('is accepted only while curation runs, checked on the settings read under the write lock', async () => {
    await requestCurationScan(context, user);
    const [, , patch, options] = vi.mocked(saveCurationSettings).mock.calls[0] as unknown as [AuthContext, AuthUser, Partial<CurationSettings>, SaveOptions];
    expect(patch).toEqual({ force_scan: true });
    expect(() => options.validate?.({ ...DEFAULT_CURATION_SETTINGS, curation_enabled: true })).not.toThrow();
    expect(() => options.validate?.({ ...DEFAULT_CURATION_SETTINGS, curation_enabled: false })).toThrow('A scan runs only while knowledge curation is enabled');
  });

  it('is reported as pending only while curation runs', async () => {
    vi.mocked(getCurationSettings).mockResolvedValueOnce({ ...DEFAULT_CURATION_SETTINGS, force_scan: true, curation_enabled: true });
    expect((await curationSettingsForApi(context)).force_scan).toBe(true);
    vi.mocked(getCurationSettings).mockResolvedValueOnce({ ...DEFAULT_CURATION_SETTINGS, force_scan: true, curation_enabled: false });
    expect((await curationSettingsForApi(context)).force_scan).toBe(false);
  });
});
