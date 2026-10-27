import { logApp } from '../../config/conf';
import { FunctionalError } from '../../config/errors';
import { getSettings, setPlatformBootstrapStatus } from '../../domain/settings';
import { publishUserAction } from '../../listener/UserActionListener';
import type { AuthContext, AuthUser } from '../../types/user';
import type { ConfigPresetSelectionInput } from '../../generated/graphql';
import { resolveUserByIdFromCache } from '../user/user-domain';
import { CONFIG_PRESET_FAMILIES } from './configPreset-registry';
import { checkConfigPresetImportAccess } from './configPreset-import-utils';
import { computeConfigPresetItems, loadConfigPresetImportZip } from './configPreset-import-domain';
import { readConfigPresetBundle, resolveBundleDependencies } from './configPreset-import-bundle';
import { writeConfigPresetImportReport } from './configPreset-import-report';
import { applyConfigPresetImportEvent, applyConfigPresetImportRunEvent, readConfigPresetImportSession, toSessionSelections } from './configPreset-import-session-domain';
import type { ConfigPresetImportCounts, ConfigPresetImportItemResult, ConfigPresetImportResultStatus } from './configPreset-import-session';
import {
  CONFIG_PRESET_REASON_FILE_MISSING,
  type ConfigPresetBundle,
  type ConfigPresetBundleItem,
  type ConfigPresetComputedItem,
  type ConfigPresetImportPlan,
  type ConfigPresetImportStatus,
  configPresetPlanKey,
} from './configPreset-import-types';

export interface ConfigPresetImportOutput {
  results: ConfigPresetImportItemResult[];
  report_id: string | null;
  settings: unknown | null;
}

const toResult = (item: ConfigPresetBundleItem, status: ConfigPresetImportStatus, reason?: string): ConfigPresetImportItemResult => ({
  type: item.type,
  key: item.id,
  status: status.toUpperCase() as ConfigPresetImportResultStatus,
  reason: reason ?? null,
});

const countResults = (results: ConfigPresetImportItemResult[]): ConfigPresetImportCounts => {
  const counts: ConfigPresetImportCounts = { created: 0, overwritten: 0, skipped: 0, failed: 0 };
  results.forEach(({ status }) => {
    counts[status.toLowerCase() as keyof ConfigPresetImportCounts] += 1;
  });
  return counts;
};

// The items of the selection in the bundle, then their required dependencies from dependencies.json: the selection sent
// by the frontend is not trusted, and dependencies come first
const resolveImportItems = (bundle: ConfigPresetBundle, selections: ConfigPresetSelectionInput[]): ConfigPresetBundleItem[] => {
  const selected: ConfigPresetBundleItem[] = [];
  selections.forEach(({ type, items, excluded_items: excluded }) => {
    if (!CONFIG_PRESET_FAMILIES.some((family) => family.id === type)) {
      throw FunctionalError('Unknown configuration preset type', { type });
    }
    const available = bundle.items.filter((item) => item.type === type);
    const picked = items
      ? items.map((id) => available.find((item) => item.id === id) ?? (() => {
          throw FunctionalError('Unknown configuration preset item', { type, item: id });
        })())
      : available.filter((item) => !(excluded ?? []).includes(item.id));
    picked.forEach((item) => {
      if (!selected.includes(item)) {
        selected.push(item);
      }
    });
  });
  if (selected.length === 0) {
    throw FunctionalError('Select at least one configuration item to import');
  }
  return resolveBundleDependencies(bundle, selected);
};

const toOutput = (results: { item: ConfigPresetBundleItem; computed: ConfigPresetComputedItem }[]) => {
  return results.map(({ item, computed }) => toResult(item, computed.status, computed.reason));
};

// Reads only: what the import would do, nothing is written, no session change, no audit event
const dryRun = async (context: AuthContext, user: AuthUser, items: ConfigPresetBundleItem[]): Promise<ConfigPresetImportOutput> => {
  return { results: toOutput(await computeConfigPresetItems(context, user, items)), report_id: null, settings: null };
};

const realImport = async (
  context: AuthContext,
  user: AuthUser,
  fileId: string,
  bundle: ConfigPresetBundle,
  items: ConfigPresetBundleItem[],
  selections: ConfigPresetSelectionInput[],
): Promise<ConfigPresetImportOutput> => {
  const session = await readConfigPresetImportSession(context, user);
  // The import is on the pending zip of the session: another upload since (another tab) made this file missing
  if (!session || session.file_id !== fileId) {
    throw FunctionalError('The uploaded file no longer exists', { reason: CONFIG_PRESET_REASON_FILE_MISSING });
  }
  const startedAt = new Date().toISOString();
  // The session records what runs: the selection sent, plus the required dependencies added
  const sessionSelections = toSessionSelections(selections);
  items.forEach((item) => {
    if (!sessionSelections.some(({ type, items: ids }) => type === item.type && (ids === null || ids.includes(item.id)))) {
      const existing = sessionSelections.find(({ type, items: ids }) => type === item.type && ids !== null);
      if (existing) {
        existing.items = [...(existing.items ?? []), item.id];
      } else {
        sessionSelections.push({ type: item.type, items: [item.id], excluded_items: null });
      }
    }
  });
  // A second real import while the session is applying is refused by the transition
  await applyConfigPresetImportEvent(context, user, 'START', { started_at: startedAt, total: items.length, selections: sessionSelections });
  logApp.info('[CONFIG PRESET] Import started', { user_id: user.id, file_id: fileId, total: items.length });
  const importContext = context;
  const plan: ConfigPresetImportPlan = { created: new Set() };
  const results: ConfigPresetImportItemResult[] = [];
  const labels = new Map<string, string>();
  for (let i = 0; i < items.length; i += 1) {
    const item = items[i];
    // Re-read before each item: the rights of the user may have changed; the origin is kept for the audit
    const cachedUser = await resolveUserByIdFromCache(importContext, user.id);
    if (!cachedUser) {
      throw FunctionalError('The user who started the import no longer exists');
    }
    const runUser = { ...cachedUser, origin: user.origin } as AuthUser;
    const importer = CONFIG_PRESET_FAMILIES.find((family) => family.id === item.type)!.importer!;
    const computed = await importer.compute(importContext, runUser, item, plan);
    labels.set(configPresetPlanKey(item.type, item.id), computed.label);
    let result = toResult(item, computed.status, computed.reason);
    if (computed.status !== 'failed' && computed.status !== 'skipped') {
      try {
        const applied = await importer.apply(importContext, runUser, item, computed);
        if (applied) {
          result = toResult(item, applied, computed.reason);
        }
      } catch (err) {
        // The theme was not created: the items that depend on it fail with it
        plan.created.delete(configPresetPlanKey(item.type, item.id));
        result = toResult(item, 'failed', err instanceof Error ? err.message : String(err));
      }
    }
    results.push(result);
    await applyConfigPresetImportRunEvent(importContext, user, startedAt, 'ITEM_PROCESSED', { result });
  }
  // Completed once every selected item has been processed, whatever the failures, and only on a platform with a pending status
  const { platform_bootstrap_status: bootstrapStatus } = (await getSettings(importContext)) as { platform_bootstrap_status?: string };
  if (bootstrapStatus === 'pending') {
    await setPlatformBootstrapStatus(importContext, user, 'completed');
  }
  const counts = countResults(results);
  const report = await writeConfigPresetImportReport(importContext, user, fileId, {
    user_id: user.id,
    started_at: startedAt,
    ended_at: new Date().toISOString(),
    bundle: bundle.metadata,
    items: results.map((result) => ({ ...result, label: labels.get(configPresetPlanKey(result.type, result.key)) ?? result.key })),
    outcome: 'completed',
  });
  await applyConfigPresetImportRunEvent(importContext, user, startedAt, 'FINISH', { outcome: 'COMPLETED', counts, report_id: report.reportId });
  if (report.reportId) {
    // The listeners run in a Promise.all: a failing one never fails the import
    try {
      await publishUserAction({
        user,
        event_type: 'command',
        event_access: 'administration',
        event_scope: 'import',
        context_data: { file_id: report.reportId, path: report.folder, file_name: report.fileName, input: { counts } },
      });
    } catch (err) {
      logApp.warn('[CONFIG PRESET] The activity event of the import could not be published', { cause: err });
    }
  }
  logApp.info('[CONFIG PRESET] Import finished', { user_id: user.id, file_id: fileId, counts });
  return { results, report_id: report.reportId, settings: await getSettings(importContext) };
};

// Applies the selected items of the pending zip one by one, required dependencies first, and returns the result of each:
// the expected result for a dry run. A failed item never stops the next one.
export const configPresetImport = async (
  context: AuthContext,
  user: AuthUser,
  fileId: string,
  selections: ConfigPresetSelectionInput[],
  isDryRun: boolean,
): Promise<ConfigPresetImportOutput> => {
  checkConfigPresetImportAccess(context, user);
  // A real import goes on if the browser disconnects: its context is detached from the request
  const engineContext: AuthContext = isDryRun ? context : { ...context, requestAbortSignal: undefined };
  const bundle = await readConfigPresetBundle(await loadConfigPresetImportZip(engineContext, user, fileId));
  const items = resolveImportItems(bundle, selections);
  return isDryRun ? dryRun(engineContext, user, items) : realImport(engineContext, user, fileId, bundle, items, selections);
};
