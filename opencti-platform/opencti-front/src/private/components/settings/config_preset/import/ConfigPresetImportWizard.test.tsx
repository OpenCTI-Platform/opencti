import React from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { MockPayloadGenerator } from 'relay-test-utils';
import testRender, { createMockUserContext } from '../../../../../utils/tests/test-render';
import ConfigPresetImportWizard from './ConfigPresetImportWizard';

type Rendered = ReturnType<typeof testRender>;

const platformSettings = { key: 'platformSettings', label: 'Platform settings' };
const previewItem = (key: string, label: string, overrides: Record<string, unknown> = {}) => ({
  key,
  label,
  translatable: true,
  isDefault: false,
  exists: true,
  conflict: false,
  dependsOn: [],
  ...overrides,
});
const previewType = (key: string, label: string, items: unknown[], modes = ['OVERWRITE']) => ({
  key,
  label,
  description: `${label} description`,
  group: platformSettings,
  modes,
  items,
});
const preview = {
  bundle_name: 'Test bundle',
  openCTI_version: '7.0.0',
  generated_at: '2026-10-20T10:00:00.000Z',
  ignored: [],
  types: [
    previewType('platform', 'Platform configuration', [
      previewItem('platform', 'Platform configuration', {
        dependsOn: [{ type: 'branding', key: 'theme--1' }],
      }),
    ]),
    previewType('branding', 'Branding', [
      previewItem('theme--1', 'Import theme', { translatable: false, exists: false, isDefault: true }),
      // On the platform already: the import can overwrite it or add it as a copy
      previewItem('theme--2', 'Existing theme', { translatable: false, conflict: true }),
    ], ['OVERWRITE', 'COPY']),
    previewType('messages', 'Messages', [previewItem('banner', 'Banner')]),
  ],
};
// Two themes that are on the platform already, so that the choice can be made for the type
const previewWithTwoConflicts = {
  ...preview,
  types: preview.types.map((type) => (type.key === 'branding'
    ? { ...type, items: [...type.items, previewItem('theme--3', 'Another theme', { translatable: false, conflict: true })] }
    : type)),
};
const session = (overrides: Record<string, unknown> = {}) => ({
  status: 'DRAFT',
  file_id: 'config_preset/import/id/bundle.zip',
  revision: 0,
  selections: [],
  total: 0,
  results: [],
  outcome: null,
  counts: null,
  report_id: null,
  available_events: [],
  ...overrides,
});

const operationNames = ({ relayEnv }: Rendered) => relayEnv.mock.getAllOperations().map((operation) => operation.request.node.operation.name);
const operation = ({ relayEnv }: Rendered, name: string) => {
  const found = relayEnv.mock.getAllOperations().filter((candidate) => candidate.request.node.operation.name === name);
  return found[found.length - 1];
};
const resolve = async ({ relayEnv }: Rendered, name: string, resolvers: Record<string, () => unknown>) => {
  await act(async () => {
    const target = relayEnv.mock.getAllOperations().filter((candidate) => candidate.request.node.operation.name === name).pop()!;
    relayEnv.mock.resolve(target, MockPayloadGenerator.generate(target, resolvers));
  });
};
const reject = async ({ relayEnv }: Rendered, name: string, reason: string) => {
  await act(async () => {
    const target = relayEnv.mock.getAllOperations().filter((candidate) => candidate.request.node.operation.name === name).pop()!;
    relayEnv.mock.reject(target, { res: { errors: [{ message: reason, extensions: { code: 'FUNCTIONAL_ERROR', data: { reason } } }] } } as unknown as Error);
  });
};

const onFinish = vi.fn();
// The wizard is for BYPASS users
const userContext = createMockUserContext({
  me: { name: 'admin', capabilities: [{ name: 'BYPASS' }], userSubscriptions: { edges: [] } },
});
const renderWizard = async (currentSession: unknown) => {
  const rendered = testRender(<ConfigPresetImportWizard onFinish={onFinish} />, { userContext });
  await resolve(rendered, 'ConfigPresetImportWizardQuery', { Query: () => ({ configPresetImportSession: currentSession }) });
  return rendered;
};
// The expected results are asked for with the same mutation as the import, with dry_run
const dryRuns = ({ relayEnv }: Rendered) => relayEnv.mock.getAllOperations()
  .filter((candidate) => candidate.request.node.operation.name === 'ConfigPresetImportWizardApplyMutation' && candidate.request.variables.dry_run === true);
const resolveSimulation = async (rendered: Rendered, results: unknown[] = [], index = -1) => {
  await waitFor(() => expect(dryRuns(rendered).length).toBeGreaterThan(0));
  await act(async () => {
    const target = dryRuns(rendered).at(index)!;
    rendered.relayEnv.mock.resolve(target, MockPayloadGenerator.generate(target, { ConfigPresetImportOutput: () => ({ results, report_id: null, settings: null }) }));
  });
};
// The preview shown, its expected results not in yet
const openPreview = async (currentSession = session(), data: unknown = preview) => {
  const rendered = await renderWizard(currentSession);
  await resolve(rendered, 'ConfigPresetImportPreviewQuery', { Query: () => ({ configPresetImportPreview: data }) });
  await screen.findByRole('button', { name: 'Apply' });
  return rendered;
};
const renderPreview = async (currentSession = session(), results: unknown[] = [], data: unknown = preview) => {
  const rendered = await openPreview(currentSession, data);
  await resolveSimulation(rendered, results);
  await waitFor(() => expect(screen.getByRole('button', { name: 'Apply' })).toBeEnabled());
  return rendered;
};
const checkbox = (name: string) => screen.getByRole('checkbox', { name });

describe('ConfigPresetImportWizard', () => {
  beforeEach(() => {
    onFinish.mockReset();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  describe('without session', () => {
    it('shows the welcome choices, then the upload once the import is chosen', async () => {
      const { user } = await renderWizard(null);
      expect(screen.getByTestId('config-preset-wizard-import')).toBeInTheDocument();
      await user.click(within(screen.getByTestId('config-preset-wizard-import')).getByRole('button'));
      expect(screen.getByRole('button', { name: 'Upload a configuration bundle' })).toBeInTheDocument();
    });

    it('uploads the zip and reads the session again', async () => {
      const rendered = await renderWizard(null);
      await rendered.user.click(within(screen.getByTestId('config-preset-wizard-import')).getByRole('button'));
      const file = new File(['zip'], 'bundle.zip', { type: 'application/zip' });
      await rendered.user.upload(screen.getByTestId('config-preset-import-file'), file);
      expect(operation(rendered, 'ConfigPresetImportUploadMutation').request.variables).toEqual({ file });
      await resolve(rendered, 'ConfigPresetImportUploadMutation', {});
      expect(operationNames(rendered)).toContain('ConfigPresetImportWizardQuery');
    });
  });

  describe('preview', () => {
    it('reads the preview of the file of the session, with every item selected for a new upload', async () => {
      const rendered = await renderPreview();
      expect(operationNames(rendered)).not.toContain('ConfigPresetImportPreviewQuery');
      ['Platform configuration (1/1)', 'Messages (1/1)'].forEach((name) => expect(checkbox(name)).toHaveAttribute('data-state', 'checked'));
      expect(checkbox('Branding (2/2)')).toHaveAttribute('data-state', 'checked');
      expect(screen.getByRole('button', { name: 'Apply' })).toBeEnabled();
    });

    it('restores the saved selection', async () => {
      await renderPreview(session({ revision: 2, selections: [{ type: 'messages', items: ['banner'], excluded_items: null }] }));
      expect(checkbox('Messages (1/1)')).toHaveAttribute('data-state', 'checked');
      expect(checkbox('Platform configuration (0/1)')).toHaveAttribute('data-state', 'unchecked');
      expect(checkbox('Branding (0/2)')).toHaveAttribute('data-state', 'unchecked');
    });

    it('shows the required dependencies checked and disabled with their item', async () => {
      const { user } = await renderPreview(session({ revision: 1, selections: [{ type: 'messages', items: ['banner'], excluded_items: null }] }));
      await user.click(checkbox('Platform configuration (0/1)'));
      const theme = within(screen.getByTestId('config-preset-import-item-branding-theme--1')).getByRole('checkbox');
      expect(theme).toBeDisabled();
      expect(theme).toHaveAttribute('data-state', 'checked');
    });

    it('disables Apply with nothing selected', async () => {
      const { user } = await renderPreview();
      await user.click(checkbox('Platform configuration (1/1)'));
      await user.click(checkbox('Branding (2/2)'));
      await user.click(checkbox('Messages (1/1)'));
      expect(screen.getByRole('button', { name: 'Apply' })).toBeDisabled();
    });

    it('saves the selection 500 ms after the last change, with a revision that only goes up', async () => {
      const rendered = await renderPreview(session({ revision: 3, selections: [{ type: 'messages', items: ['banner'], excluded_items: null }] }));
      vi.useFakeTimers();
      fireEvent.click(checkbox('Messages (1/1)'));
      fireEvent.click(checkbox('Messages (0/1)'));
      expect(operationNames(rendered)).not.toContain('ConfigPresetImportPreviewSaveMutation');
      await act(async () => {
        vi.advanceTimersByTime(499);
      });
      expect(operationNames(rendered)).not.toContain('ConfigPresetImportPreviewSaveMutation');
      await act(async () => {
        vi.advanceTimersByTime(2);
      });
      const save = rendered.relayEnv.mock.getAllOperations().filter((candidate) => candidate.request.node.operation.name === 'ConfigPresetImportPreviewSaveMutation');
      expect(save).toHaveLength(1);
      expect(save[0].request.variables).toEqual({ file_id: 'config_preset/import/id/bundle.zip', selections: [{ type: 'messages', items: null }], revision: 5 });
      vi.useRealTimers();
      await resolve(rendered, 'ConfigPresetImportPreviewSaveMutation', {});
    });

    it('sends a pending save on close', async () => {
      const rendered = await renderPreview();
      await rendered.user.click(checkbox('Messages (1/1)'));
      rendered.unmount();
      expect(operationNames(rendered)).toContain('ConfigPresetImportPreviewSaveMutation');
    });

    it('sends a pending save before Apply, then the import with the current selection', async () => {
      const rendered = await renderPreview();
      await rendered.user.click(checkbox('Messages (1/1)'));
      // Apply waits for the expected results of the new selection
      await resolveSimulation(rendered);
      await waitFor(() => expect(screen.getByRole('button', { name: 'Apply' })).toBeEnabled());
      await rendered.user.click(screen.getByRole('button', { name: 'Apply' }));
      const names = operationNames(rendered);
      expect(names.indexOf('ConfigPresetImportPreviewSaveMutation')).toBeLessThan(names.indexOf('ConfigPresetImportWizardApplyMutation'));
      expect(operation(rendered, 'ConfigPresetImportWizardApplyMutation').request.variables).toEqual({
        file_id: 'config_preset/import/id/bundle.zip',
        selections: [{ type: 'platform', items: null }, { type: 'branding', items: null }],
        dry_run: false,
      });
    });

    it('shows a refused bundle with Start over as the exit', async () => {
      const rendered = await renderWizard(session());
      await reject(rendered, 'ConfigPresetImportPreviewQuery', 'bundle_refused');
      expect(await screen.findByText('This configuration bundle cannot be imported')).toBeInTheDocument();
      await rendered.user.click(screen.getByRole('button', { name: 'Start over' }));
      expect(operation(rendered, 'ConfigPresetImportWizardClearMutation').request.variables).toEqual({ delete_file: true });
      await resolve(rendered, 'ConfigPresetImportWizardClearMutation', {});
      expect(await screen.findByRole('button', { name: 'Upload a configuration bundle' })).toBeInTheDocument();
    });

    it('goes back to the upload step when the file is missing', async () => {
      const rendered = await renderWizard(session());
      await reject(rendered, 'ConfigPresetImportPreviewQuery', 'file_missing');
      expect(await screen.findByText('The uploaded file no longer exists')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Upload a configuration bundle' })).toBeInTheDocument();
    });

    it('asks a confirmation before Start over, which deletes the pending zip', async () => {
      const rendered = await renderPreview();
      await rendered.user.click(screen.getByRole('button', { name: 'Start over' }));
      expect(operationNames(rendered)).not.toContain('ConfigPresetImportWizardClearMutation');
      await rendered.user.click(within(screen.getByRole('dialog', { name: 'Start over' })).getByRole('button', { name: 'Start over' }));
      expect(operation(rendered, 'ConfigPresetImportWizardClearMutation').request.variables).toEqual({ delete_file: true });
    });
  });

  describe('apply, progress and result', () => {
    it('shows the progress while the import runs, then the result with the report', async () => {
      const rendered = await renderPreview();
      await rendered.user.click(screen.getByRole('button', { name: 'Apply' }));
      expect(await screen.findByText('Import in progress')).toBeInTheDocument();
      await resolve(rendered, 'ConfigPresetImportWizardApplyMutation', {});
      const finished = session({
        status: 'FINISHED',
        outcome: 'COMPLETED',
        total: 2,
        report_id: 'config_preset/history/id/import-report.json',
        counts: { created: 0, overwritten: 1, skipped: 0, failed: 1 },
        results: [{ type: 'messages', key: 'banner', status: 'OVERWRITTEN', reason: null }, { type: 'branding', key: 'theme--1', status: 'FAILED', reason: 'Theme name already exists' }],
      });
      await resolve(rendered, 'ConfigPresetImportWizardQuery', { Query: () => ({ configPresetImportSession: finished }) });
      expect(await screen.findByText('Import finished')).toBeInTheDocument();
      expect(screen.getByText('Theme name already exists')).toBeInTheDocument();
      expect(screen.getByText('0 created, 1 overwritten, 0 skipped, 1 failed')).toBeInTheDocument();
      expect(screen.getByRole('link', { name: 'Download report' })).toHaveAttribute('href', expect.stringContaining(encodeURIComponent('config_preset/history/id/import-report.json')));
    });

    it('keeps the preview and goes back to the upload when the apply says the file is missing', async () => {
      const rendered = await renderPreview();
      await rendered.user.click(screen.getByRole('button', { name: 'Apply' }));
      await reject(rendered, 'ConfigPresetImportWizardApplyMutation', 'file_missing');
      expect(await screen.findByText('The uploaded file no longer exists')).toBeInTheDocument();
    });

    it('resumes on the progress screen when the session is applying, and polls every five seconds until it changes', async () => {
      vi.useFakeTimers({ shouldAdvanceTime: true });
      const applying = session({ status: 'APPLYING', total: 4, results: [{ type: 'messages', key: 'banner', status: 'OVERWRITTEN', reason: null }] });
      const rendered = await renderWizard(applying);
      expect(screen.getByText('1 of 4 items processed')).toBeInTheDocument();
      await act(async () => {
        vi.advanceTimersByTime(5000);
      });
      expect(operationNames(rendered)).toContain('ConfigPresetImportWizardQuery');
      await resolve(rendered, 'ConfigPresetImportWizardQuery', { Query: () => ({ configPresetImportSession: session({ status: 'FINISHED', total: 4, counts: { created: 0, overwritten: 4, skipped: 0, failed: 0 } }) }) });
      expect(await screen.findByText('Import finished')).toBeInTheDocument();
      await act(async () => {
        vi.advanceTimersByTime(10000);
      });
      expect(operationNames(rendered)).not.toContain('ConfigPresetImportWizardQuery');
    });

    it('shows the result of a finished import without report link when there is no report', async () => {
      await renderWizard(session({ status: 'FINISHED', outcome: 'COMPLETED', counts: { created: 1, overwritten: 0, skipped: 0, failed: 0 }, results: [{ type: 'messages', key: 'banner', status: 'CREATED', reason: null }] }));
      expect(screen.getByText('Created')).toBeInTheDocument();
      expect(screen.queryByRole('link', { name: 'Download report' })).not.toBeInTheDocument();
    });

    it('clears the session and closes the wizard on Close of the result', async () => {
      const rendered = await renderWizard(session({ status: 'FINISHED', outcome: 'COMPLETED', counts: { created: 0, overwritten: 0, skipped: 0, failed: 0 } }));
      await rendered.user.click(screen.getByRole('button', { name: 'Close' }));
      expect(operation(rendered, 'ConfigPresetImportWizardClearMutation').request.variables).toEqual({ delete_file: false });
      expect(onFinish).not.toHaveBeenCalled();
      await resolve(rendered, 'ConfigPresetImportWizardClearMutation', {});
      await waitFor(() => expect(onFinish).toHaveBeenCalledTimes(1));
    });
  });

  describe('running and interrupted', () => {
    const running = (overrides: Record<string, unknown> = {}) => ({
      running: { name: 'Jane', is_mine: false, processed: 4, total: 7 },
      last_finished_at: null,
      ...overrides,
    });
    const resolveRunning = (rendered: Rendered, value: unknown) => resolve(rendered, 'ConfigPresetImportWizardRunningQuery', { Query: () => ({ configPresetImportRunning: value }) });

    it('shows the import of another administrator in a banner, and disables Apply with the reason', async () => {
      const rendered = await renderPreview();
      await resolveRunning(rendered, running());
      expect(await screen.findByText('Import by Jane in progress')).toBeInTheDocument();
      expect(screen.getByText('4 of 7')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Apply' })).toBeDisabled();
      expect(screen.getByText('Apply is available once the import in progress is over.')).toBeInTheDocument();
      // The preview and the selection stay available
      expect(checkbox('Messages (1/1)')).toBeEnabled();
    });

    it('shows no name when the administrator no longer exists, and no banner for the own import', async () => {
      vi.useFakeTimers({ shouldAdvanceTime: true });
      const rendered = await renderPreview();
      await resolveRunning(rendered, running({ running: { name: null, is_mine: false, processed: 1, total: 2 } }));
      expect(await screen.findByText('Import by another administrator in progress')).toBeInTheDocument();
      await act(async () => {
        vi.advanceTimersByTime(5000);
      });
      await resolveRunning(rendered, running({ running: { name: 'Me', is_mine: true, processed: 1, total: 2 } }));
      await waitFor(() => expect(screen.queryByText(/Import by/)).not.toBeInTheDocument());
      expect(screen.getByRole('button', { name: 'Apply' })).toBeEnabled();
    });

    it('polls the running import every five seconds, and stops with the wizard', async () => {
      vi.useFakeTimers({ shouldAdvanceTime: true });
      const rendered = await renderWizard(null);
      const count = () => operationNames(rendered).filter((name) => name === 'ConfigPresetImportWizardRunningQuery').length;
      expect(count()).toEqual(1);
      await resolveRunning(rendered, running({ running: null }));
      await act(async () => {
        vi.advanceTimersByTime(5000);
      });
      expect(count()).toEqual(1);
      rendered.unmount();
      await resolve(rendered, 'ConfigPresetImportWizardRunningQuery', {}).catch(() => undefined);
      await act(async () => {
        vi.advanceTimersByTime(20000);
      });
      expect(count()).toBeLessThanOrEqual(1);
    });

    it('adds who started the running import to a refused Apply, without a message of its own', async () => {
      const rendered = await renderPreview();
      await rendered.user.click(screen.getByRole('button', { name: 'Apply' }));
      await act(async () => {
        const target = operation(rendered, 'ConfigPresetImportWizardApplyMutation');
        rendered.relayEnv.mock.reject(target, { res: { errors: [{ message: 'An import is already running', extensions: { code: 'FUNCTIONAL_ERROR', data: { reason: 'import_running', started_by: 'Jane' } } }] } } as unknown as Error);
      });
      await resolve(rendered, 'ConfigPresetImportWizardQuery', { Query: () => ({ configPresetImportSession: session() }) });
      await resolve(rendered, 'ConfigPresetImportPreviewQuery', { Query: () => ({ configPresetImportPreview: preview }) });
      expect(await screen.findByText('Started by Jane')).toBeInTheDocument();
      expect(screen.queryByText('An import is already running')).not.toBeInTheDocument();
    });

    it('shows no "started by" when the refusal has no name', async () => {
      const rendered = await renderPreview();
      await rendered.user.click(screen.getByRole('button', { name: 'Apply' }));
      await reject(rendered, 'ConfigPresetImportWizardApplyMutation', 'import_running');
      await resolve(rendered, 'ConfigPresetImportWizardQuery', { Query: () => ({ configPresetImportSession: session() }) });
      await resolve(rendered, 'ConfigPresetImportPreviewQuery', { Query: () => ({ configPresetImportPreview: preview }) });
      expect(await screen.findByRole('button', { name: 'Apply' })).toBeInTheDocument();
      expect(screen.queryByText(/Started by/)).not.toBeInTheDocument();
    });

    it('computes the expected results again when another import ended', async () => {
      vi.useFakeTimers({ shouldAdvanceTime: true });
      const rendered = await renderPreview(session(), [{ type: 'messages', key: 'banner', status: 'OVERWRITTEN', reason: null }]);
      expect(await screen.findByText('Overwritten')).toBeInTheDocument();
      // The first date that is read is not a change
      await resolveRunning(rendered, running({ running: null, last_finished_at: '2026-10-27T10:00:00.000Z' }));
      expect(dryRuns(rendered)).toHaveLength(0);
      await act(async () => {
        vi.advanceTimersByTime(5000);
      });
      await resolveRunning(rendered, running({ running: null, last_finished_at: '2026-10-27T10:05:00.000Z' }));
      await resolveSimulation(rendered, []);
      await waitFor(() => expect(screen.queryByText('Overwritten')).not.toBeInTheDocument());
    });

    it('shows the interrupted screen with the results kept, and its two actions', async () => {
      const rendered = await renderWizard(session({
        status: 'INTERRUPTED',
        total: 3,
        results: [{ type: 'messages', key: 'banner', status: 'OVERWRITTEN', reason: null }],
      }));
      expect(screen.getByText('The import was interrupted')).toBeInTheDocument();
      expect(screen.getByText('Overwritten')).toBeInTheDocument();
      await rendered.user.click(screen.getByRole('button', { name: 'Back to selection' }));
      expect(operationNames(rendered)).toContain('ConfigPresetImportWizardBackMutation');
      await resolve(rendered, 'ConfigPresetImportWizardBackMutation', {});
      expect(operationNames(rendered).filter((name) => name === 'ConfigPresetImportWizardQuery')).toHaveLength(1);
    });

    it('starts over from the interrupted screen after a confirmation', async () => {
      const rendered = await renderWizard(session({ status: 'INTERRUPTED' }));
      await rendered.user.click(screen.getByRole('button', { name: 'Start over' }));
      expect(operationNames(rendered)).not.toContain('ConfigPresetImportWizardClearMutation');
      await rendered.user.click(within(screen.getByRole('dialog', { name: 'Start over' })).getByRole('button', { name: 'Start over' }));
      expect(operation(rendered, 'ConfigPresetImportWizardClearMutation').request.variables).toEqual({ delete_file: true });
    });

    it('moves an open wizard from applying to interrupted once the session says so', async () => {
      vi.useFakeTimers({ shouldAdvanceTime: true });
      const rendered = await renderWizard(session({ status: 'APPLYING', total: 2 }));
      expect(screen.getByText('Import in progress')).toBeInTheDocument();
      await act(async () => {
        vi.advanceTimersByTime(5000);
      });
      await resolve(rendered, 'ConfigPresetImportWizardQuery', { Query: () => ({ configPresetImportSession: session({ status: 'INTERRUPTED', total: 2 }) }) });
      expect(await screen.findByText('The import was interrupted')).toBeInTheDocument();
    });
  });

  describe('lock', () => {
    it('keeps the selection and makes Apply usable again after an Apply refused because an import is running', async () => {
      const saved = session({ revision: 2, selections: [{ type: 'messages', items: ['banner'], excluded_items: null }] });
      const rendered = await renderPreview(saved);
      await rendered.user.click(screen.getByRole('button', { name: 'Apply' }));
      await reject(rendered, 'ConfigPresetImportWizardApplyMutation', 'import_running');
      // The session is read again, still a draft: the step shows no message of its own
      await resolve(rendered, 'ConfigPresetImportWizardQuery', { Query: () => ({ configPresetImportSession: saved }) });
      await resolve(rendered, 'ConfigPresetImportPreviewQuery', { Query: () => ({ configPresetImportPreview: preview }) });
      expect(await screen.findByRole('button', { name: 'Apply' })).toBeInTheDocument();
      await resolveSimulation(rendered);
      await waitFor(() => expect(screen.getByRole('button', { name: 'Apply' })).toBeEnabled());
      expect(checkbox('Messages (1/1)')).toHaveAttribute('data-state', 'checked');
      expect(checkbox('Platform configuration (0/1)')).toHaveAttribute('data-state', 'unchecked');
      expect(screen.queryByText('An import is already running')).not.toBeInTheDocument();
    });

    it('shows the result of an import that was stopped like any other outcome', async () => {
      await renderWizard(session({
        status: 'FINISHED',
        outcome: 'STOPPED',
        counts: { created: 0, overwritten: 1, skipped: 0, failed: 1 },
        results: [{ type: 'platform', key: 'platform', status: 'OVERWRITTEN', reason: null }, { type: 'messages', key: 'banner', status: 'FAILED', reason: 'Import stopped: lock lost' }],
      }));
      expect(screen.getByText('Import stopped: lock lost')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Close' })).toBeInTheDocument();
    });
  });

  describe('expected results', () => {
    const simulated = [
      { type: 'branding', key: 'theme--1', status: 'CREATED', reason: null },
      { type: 'platform', key: 'platform', status: 'FAILED', reason: 'Default theme Import theme could not be imported' },
      { type: 'messages', key: 'banner', status: 'OVERWRITTEN', reason: null },
    ];

    it('asks for them as soon as the preview is shown, with the file id and the current selection', async () => {
      const rendered = await openPreview(session({ revision: 1, selections: [{ type: 'messages', items: ['banner'], excluded_items: null }] }));
      await waitFor(() => expect(dryRuns(rendered)).toHaveLength(1));
      expect(dryRuns(rendered)[0].request.variables).toEqual({
        file_id: 'config_preset/import/id/bundle.zip',
        selections: [{ type: 'messages', items: ['banner'] }],
        dry_run: true,
      });
    });

    it('has no Simulate button', async () => {
      await renderPreview();
      expect(screen.queryByRole('button', { name: 'Simulate' })).not.toBeInTheDocument();
    });

    it('shows what the import would do on each row, and nothing for an item that is created as it is', async () => {
      await renderPreview(session({ revision: 1, selections: [{ type: 'platform', items: ['platform'], excluded_items: null }] }), simulated.slice(0, 2));
      // The theme the platform depends on is created as it is: nothing to say
      expect(within(screen.getByTestId('config-preset-import-item-branding-theme--1')).queryByText(/Created|Overwritten|Skipped|Failed/)).not.toBeInTheDocument();
      const platform = screen.getByTestId('config-preset-import-item-platform-platform');
      expect(within(platform).getByText('Failed')).toBeInTheDocument();
      expect(within(platform).getByText('Default theme Import theme could not be imported')).toBeInTheDocument();
      // Not selected, not shown
      expect(within(screen.getByTestId('config-preset-import-item-messages-banner')).queryByText('Overwritten')).not.toBeInTheDocument();
    });

    it('shows that an item with no choice is overwritten', async () => {
      await renderPreview(session(), simulated);
      expect(within(screen.getByTestId('config-preset-import-item-messages-banner')).getByText('Overwritten')).toBeInTheDocument();
    });

    it('shows the default tag of an item', async () => {
      await renderPreview();
      expect(within(screen.getByTestId('config-preset-import-item-branding-theme--1')).getByText('default')).toBeInTheDocument();
    });

    it('computes them again on a selection change, Apply waiting for them and the checkboxes staying usable', async () => {
      const rendered = await renderPreview(session(), simulated);
      await rendered.user.click(checkbox('Messages (1/1)'));
      expect(screen.getByRole('button', { name: 'Apply' })).toBeDisabled();
      expect(screen.getByText('Checking what the import would do')).toBeInTheDocument();
      expect(checkbox('Messages (0/1)')).toBeEnabled();
      expect(screen.getByRole('button', { name: 'Start over' })).toBeEnabled();
      // The previous results stay until the new ones are in
      expect(screen.getByText('Failed')).toBeInTheDocument();
      await resolveSimulation(rendered, []);
      await waitFor(() => expect(screen.getByRole('button', { name: 'Apply' })).toBeEnabled());
      expect(screen.queryByText('Checking what the import would do')).not.toBeInTheDocument();
      expect(screen.queryByText('Failed')).not.toBeInTheDocument();
    });

    it('waits for the first ones before Apply', async () => {
      const rendered = await openPreview();
      expect(screen.getByRole('button', { name: 'Apply' })).toBeDisabled();
      expect(checkbox('Messages (1/1)')).toBeEnabled();
      await resolveSimulation(rendered);
      await waitFor(() => expect(screen.getByRole('button', { name: 'Apply' })).toBeEnabled());
    });

    it('keeps only the response of the latest request', async () => {
      const rendered = await openPreview();
      await waitFor(() => expect(dryRuns(rendered)).toHaveLength(1));
      await rendered.user.click(checkbox('Messages (1/1)'));
      await waitFor(() => expect(dryRuns(rendered)).toHaveLength(2));
      // The first one answers last: it is dropped
      await resolveSimulation(rendered, [], 1);
      await resolveSimulation(rendered, [{ type: 'platform', key: 'platform', status: 'FAILED', reason: 'Stale' }], 0);
      await waitFor(() => expect(screen.getByRole('button', { name: 'Apply' })).toBeEnabled());
      expect(screen.queryByText('Stale')).not.toBeInTheDocument();
    });

    it('drops a response that arrives after the wizard was closed', async () => {
      const rendered = await openPreview();
      await waitFor(() => expect(dryRuns(rendered)).toHaveLength(1));
      rendered.unmount();
      await expect(resolveSimulation(rendered, simulated)).resolves.not.toThrow();
    });

    it('computes nothing with nothing selected', async () => {
      const rendered = await openPreview(session({ revision: 1, selections: [] }));
      expect(dryRuns(rendered)).toHaveLength(0);
      expect(screen.getByRole('button', { name: 'Apply' })).toBeDisabled();
    });

    it('applies for real once they are in, even when they showed failed items', async () => {
      const rendered = await renderPreview(session(), simulated);
      await rendered.user.click(screen.getByRole('button', { name: 'Apply' }));
      expect(operation(rendered, 'ConfigPresetImportWizardApplyMutation').request.variables).toMatchObject({ dry_run: false });
    });

    it('goes back to the upload step when the file is missing, and stays on the step for any other error', async () => {
      const rendered = await openPreview();
      await waitFor(() => expect(dryRuns(rendered)).toHaveLength(1));
      await act(async () => {
        rendered.relayEnv.mock.reject(dryRuns(rendered)[0], { res: { errors: [{ message: 'network', extensions: { code: 'FUNCTIONAL_ERROR', data: { reason: 'network' } } }] } } as unknown as Error);
      });
      await waitFor(() => expect(screen.getByRole('button', { name: 'Apply' })).toBeEnabled());
      await rendered.user.click(checkbox('Messages (1/1)'));
      await waitFor(() => expect(dryRuns(rendered)).toHaveLength(1));
      await act(async () => {
        rendered.relayEnv.mock.reject(dryRuns(rendered)[0], { res: { errors: [{ message: 'file_missing', extensions: { code: 'FUNCTIONAL_ERROR', data: { reason: 'file_missing' } } }] } } as unknown as Error);
      });
      expect(await screen.findByText('The uploaded file no longer exists')).toBeInTheDocument();
    });
  });

  describe('import mode', () => {
    // Only the item that conflicts with the platform has a choice
    const modeSelect = () => screen.getByRole('combobox', { name: 'Existing theme: When it already exists' });
    const choose = async (rendered: Rendered, name: string) => {
      await rendered.user.click(modeSelect());
      await rendered.user.click(await screen.findByRole('option', { name }));
    };
    const saves = (rendered: Rendered) => rendered.relayEnv.mock.getAllOperations().filter((candidate) => candidate.request.node.operation.name === 'ConfigPresetImportPreviewSaveMutation');
    const saved = (modes: unknown) => session({ revision: 1, selections: [{ type: 'branding', items: null, excluded_items: null, item_modes: modes }] });

    it('is offered on the item that conflicts, overwrite by default, and on no other', async () => {
      await renderPreview();
      expect(screen.getAllByRole('combobox')).toHaveLength(1);
      expect(modeSelect()).toHaveTextContent('Overwrite');
      expect(within(screen.getByTestId('config-preset-import-item-branding-theme--1')).queryByRole('combobox')).not.toBeInTheDocument();
      expect(within(screen.getByTestId('config-preset-import-item-messages-banner')).queryByRole('combobox')).not.toBeInTheDocument();
    });

    it('is not offered on an item that is not imported', async () => {
      const { user } = await renderPreview();
      await user.click(within(screen.getByTestId('config-preset-import-item-branding-theme--2')).getByRole('checkbox'));
      expect(screen.queryByRole('combobox')).not.toBeInTheDocument();
    });

    it('lists the modes the type supports', async () => {
      const rendered = await renderPreview();
      await rendered.user.click(modeSelect());
      expect((await screen.findAllByRole('option')).map((option) => option.textContent)).toEqual(['Overwrite', 'Add as a copy']);
    });

    it('restores the mode of the saved selection', async () => {
      await renderPreview(saved([{ key: 'theme--2', mode: 'COPY' }]));
      expect(modeSelect()).toHaveTextContent('Add as a copy');
    });

    it('saves the mode of the item with the selection, and leaves out the default one', async () => {
      const rendered = await renderPreview(saved(null));
      await choose(rendered, 'Add as a copy');
      expect(modeSelect()).toHaveTextContent('Add as a copy');
      await waitFor(() => expect(saves(rendered)).toHaveLength(1), { timeout: 2000 });
      expect(saves(rendered)[0].request.variables).toMatchObject({ revision: 2, selections: [{ type: 'branding', items: null, item_modes: [{ key: 'theme--2', mode: 'COPY' }] }] });
      await resolve(rendered, 'ConfigPresetImportPreviewSaveMutation', {});
      await choose(rendered, 'Overwrite');
      await waitFor(() => expect(saves(rendered)).toHaveLength(1), { timeout: 2000 });
      expect(saves(rendered)[0].request.variables).toEqual({ file_id: 'config_preset/import/id/bundle.zip', selections: [{ type: 'branding', items: null }], revision: 3 });
    });

    it('sends the mode to the expected results and to Apply', async () => {
      const rendered = await openPreview(saved([{ key: 'theme--2', mode: 'COPY' }]));
      await waitFor(() => expect(dryRuns(rendered)).toHaveLength(1));
      expect(dryRuns(rendered)[0].request.variables).toEqual({
        file_id: 'config_preset/import/id/bundle.zip',
        selections: [{ type: 'branding', items: null, item_modes: [{ key: 'theme--2', mode: 'COPY' }] }],
        dry_run: true,
      });
      await resolveSimulation(rendered);
      await waitFor(() => expect(screen.getByRole('button', { name: 'Apply' })).toBeEnabled());
      await rendered.user.click(screen.getByRole('button', { name: 'Apply' }));
      expect(operation(rendered, 'ConfigPresetImportWizardApplyMutation').request.variables).toMatchObject({
        selections: [{ type: 'branding', items: null, item_modes: [{ key: 'theme--2', mode: 'COPY' }] }],
        dry_run: false,
      });
    });

    it('computes the expected results again when it changes, and shows the name of the copy', async () => {
      const rendered = await renderPreview(saved(null), [{ type: 'branding', key: 'theme--2', status: 'OVERWRITTEN', reason: null }]);
      // The choice says it is overwritten
      expect(within(screen.getByTestId('config-preset-import-item-branding-theme--2')).queryByText('Overwritten')).not.toBeInTheDocument();
      await choose(rendered, 'Add as a copy');
      expect(screen.getByRole('button', { name: 'Apply' })).toBeDisabled();
      await waitFor(() => expect(dryRuns(rendered)).toHaveLength(1));
      expect(dryRuns(rendered)[0].request.variables).toMatchObject({ selections: [{ type: 'branding', item_modes: [{ key: 'theme--2', mode: 'COPY' }] }] });
      await resolveSimulation(rendered, [{ type: 'branding', key: 'theme--2', status: 'CREATED', reason: 'Added as "Existing theme (1)"' }]);
      const row = screen.getByTestId('config-preset-import-item-branding-theme--2');
      expect(await within(row).findByText('Added as "Existing theme (1)"')).toBeInTheDocument();
      expect(within(row).getByText('Created')).toBeInTheDocument();
    });

    it('stays usable while the expected results are computed', async () => {
      await openPreview();
      expect(modeSelect()).toBeEnabled();
    });

    describe('for all the items of a type', () => {
      const familySelect = () => screen.getByRole('combobox', { name: 'Branding: Apply to all' });
      const anotherSelect = () => screen.getByRole('combobox', { name: 'Another theme: When it already exists' });
      const renderTwo = (currentSession = session(), results: unknown[] = []) => renderPreview(currentSession, results, previewWithTwoConflicts);

      it('is offered from two items that conflict, and not with one', async () => {
        await renderTwo();
        expect(familySelect()).toHaveTextContent('Overwrite');
      });

      it('is not offered with a single item in conflict, whose own choice is enough', async () => {
        await renderPreview();
        expect(screen.queryByRole('combobox', { name: 'Branding: Apply to all' })).not.toBeInTheDocument();
      });

      it('sets the mode of every item of the type that conflicts, and asks for the expected results again', async () => {
        const rendered = await renderTwo();
        await rendered.user.click(familySelect());
        await rendered.user.click(await screen.findByRole('option', { name: 'Add as a copy' }));
        expect(familySelect()).toHaveTextContent('Add as a copy');
        expect(modeSelect()).toHaveTextContent('Add as a copy');
        expect(anotherSelect()).toHaveTextContent('Add as a copy');
        await waitFor(() => expect(dryRuns(rendered)).toHaveLength(1));
        const [{ request }] = dryRuns(rendered);
        const branding = request.variables.selections.find((selection: { type: string }) => selection.type === 'branding');
        expect(branding.item_modes).toEqual(expect.arrayContaining([{ key: 'theme--2', mode: 'COPY' }, { key: 'theme--3', mode: 'COPY' }]));
        // An item that does not conflict has none
        expect(branding.item_modes).toHaveLength(2);
      });

      it('shows Mixed when the items differ, and one choice sets them all again', async () => {
        const rendered = await renderTwo();
        await rendered.user.click(modeSelect());
        await rendered.user.click(await screen.findByRole('option', { name: 'Add as a copy' }));
        expect(familySelect()).toHaveTextContent('Mixed');
        await rendered.user.click(familySelect());
        await rendered.user.click(await screen.findByRole('option', { name: 'Overwrite' }));
        expect(familySelect()).toHaveTextContent('Overwrite');
        expect(modeSelect()).toHaveTextContent('Overwrite');
      });

      it('restores from the saved selection', async () => {
        await renderTwo(session({ revision: 1, selections: [{ type: 'branding', items: null, excluded_items: null, item_modes: [{ key: 'theme--2', mode: 'COPY' }, { key: 'theme--3', mode: 'COPY' }] }] }));
        expect(familySelect()).toHaveTextContent('Add as a copy');
      });
    });
  });
});
