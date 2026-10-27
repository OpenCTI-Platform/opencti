import React from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { MockPayloadGenerator } from 'relay-test-utils';
import testRender from '../../../../utils/tests/test-render';
import ConfigPresetImportWizard from './ConfigPresetImportWizard';

type Rendered = ReturnType<typeof testRender>;

const field = (key: string, value: string | null, external_host = false) => ({ key, value, external_host });
const platformSettings = { key: 'platformSettings', label: 'Platform settings' };
const previewItem = (key: string, label: string, overrides: Record<string, unknown> = {}) => ({
  key,
  label,
  translatable: true,
  isDefault: false,
  exists: true,
  fields: [],
  dependsOn: [],
  ...overrides,
});
const previewType = (key: string, label: string, items: unknown[]) => ({ key, label, description: `${label} description`, group: platformSettings, items });
const preview = {
  bundle_name: 'Test bundle',
  openCTI_version: '7.0.0',
  generated_at: '2026-10-20T10:00:00.000Z',
  ignored: [],
  types: [
    previewType('platform', 'Platform configuration', [
      previewItem('platform', 'Platform configuration', {
        fields: [field('platform_title', 'Imported title'), field('platform_favicon', 'https://example.com/favicon.ico', true), field('platform_language', null)],
        dependsOn: [{ type: 'branding', key: 'theme--1' }],
      }),
    ]),
    previewType('branding', 'Branding', [
      previewItem('theme--1', 'Import theme', { translatable: false, exists: false, isDefault: true }),
      previewItem('whitemark', 'Remove Filigran logos'),
    ]),
    previewType('messages', 'Messages', [previewItem('banner', 'Banner')]),
  ],
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
const renderWizard = async (currentSession: unknown) => {
  const rendered = testRender(<ConfigPresetImportWizard onFinish={onFinish} />);
  await resolve(rendered, 'ConfigPresetImportWizardQuery', { Query: () => ({ configPresetImportSession: currentSession }) });
  return rendered;
};
const renderPreview = async (currentSession = session()) => {
  const rendered = await renderWizard(currentSession);
  await resolve(rendered, 'ConfigPresetImportPreviewQuery', { Query: () => ({ configPresetImportPreview: preview }) });
  await screen.findByRole('button', { name: 'Apply' });
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

    it('shows what each item would write: a null value untouched, an external host flagged, and whether it exists', async () => {
      await renderPreview();
      const platform = screen.getByTestId('config-preset-import-item-platform-platform');
      expect(platform).toHaveTextContent('platform_title: Imported title');
      expect(platform).toHaveTextContent('platform_language: Untouched');
      expect(platform).toHaveTextContent('External host');
      expect(platform).toHaveTextContent('Already exists, will be overwritten');
      expect(screen.getByTestId('config-preset-import-item-branding-theme--1')).toHaveTextContent('New');
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
      expect(await screen.findByText('Saved')).toBeInTheDocument();
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

  describe('simulate', () => {
    const simulated = [
      { type: 'branding', key: 'theme--1', status: 'CREATED', reason: null },
      { type: 'platform', key: 'platform', status: 'FAILED', reason: 'Default theme Import theme could not be imported' },
      { type: 'messages', key: 'banner', status: 'OVERWRITTEN', reason: null },
    ];
    const simulate = async (rendered: Rendered, results: unknown[] = simulated) => {
      await rendered.user.click(screen.getByRole('button', { name: 'Simulate' }));
      await resolve(rendered, 'ConfigPresetImportWizardApplyMutation', { Query: () => ({}), ConfigPresetImportOutput: () => ({ results, report_id: null, settings: null }) });
    };

    it('sends a dry run with the file id and the current selection', async () => {
      const rendered = await renderPreview(session({ revision: 1, selections: [{ type: 'messages', items: ['banner'], excluded_items: null }] }));
      await rendered.user.click(screen.getByRole('button', { name: 'Simulate' }));
      expect(operation(rendered, 'ConfigPresetImportWizardApplyMutation').request.variables).toEqual({
        file_id: 'config_preset/import/id/bundle.zip',
        selections: [{ type: 'messages', items: ['banner'] }],
        dry_run: true,
      });
    });

    it('shows the expected result on each selected row and required dependency, none on the others', async () => {
      const rendered = await renderPreview(session({ revision: 1, selections: [{ type: 'platform', items: ['platform'], excluded_items: null }] }));
      await simulate(rendered, simulated.slice(0, 2));
      expect(within(screen.getByTestId('config-preset-import-item-branding-theme--1')).getByText('Created')).toBeInTheDocument();
      const platform = screen.getByTestId('config-preset-import-item-platform-platform');
      expect(within(platform).getByText('Failed')).toBeInTheDocument();
      expect(within(platform).getByText('Default theme Import theme could not be imported')).toBeInTheDocument();
      expect(within(screen.getByTestId('config-preset-import-item-messages-banner')).queryByText('Overwritten')).not.toBeInTheDocument();
      expect(within(screen.getByTestId('config-preset-import-item-branding-whitemark')).queryByText(/Created|Overwritten|Skipped|Failed/)).not.toBeInTheDocument();
    });

    it('shows the default tag and the result together', async () => {
      const rendered = await renderPreview();
      await simulate(rendered);
      const theme = screen.getByTestId('config-preset-import-item-branding-theme--1');
      expect(within(theme).getByText('default')).toBeInTheDocument();
      expect(within(theme).getByText('Created')).toBeInTheDocument();
    });

    it('clears the results on a selection change and says to simulate again, Apply staying available', async () => {
      const rendered = await renderPreview();
      await simulate(rendered);
      expect(screen.getByText('Overwritten')).toBeInTheDocument();
      await rendered.user.click(checkbox('Messages (1/1)'));
      expect(screen.queryByText('Overwritten')).not.toBeInTheDocument();
      expect(screen.getByText('Simulate again to update')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Apply' })).toBeEnabled();
    });

    it('locks Simulate, Apply, Start over and the checkboxes while the request runs', async () => {
      const rendered = await renderPreview();
      await rendered.user.click(screen.getByRole('button', { name: 'Simulate' }));
      ['Simulate', 'Apply', 'Start over'].forEach((name) => expect(screen.getByRole('button', { name })).toBeDisabled());
      expect(checkbox('Messages (1/1)')).toBeDisabled();
      await rendered.user.click(screen.getByRole('button', { name: 'Simulate' }));
      expect(rendered.relayEnv.mock.getAllOperations().filter((candidate) => candidate.request.node.operation.name === 'ConfigPresetImportWizardApplyMutation')).toHaveLength(1);
      await resolve(rendered, 'ConfigPresetImportWizardApplyMutation', { ConfigPresetImportOutput: () => ({ results: [], report_id: null, settings: null }) });
      await waitFor(() => expect(screen.getByRole('button', { name: 'Apply' })).toBeEnabled());
    });

    it('drops a response that arrives after the wizard was closed', async () => {
      const rendered = await renderPreview();
      await rendered.user.click(screen.getByRole('button', { name: 'Simulate' }));
      rendered.unmount();
      await expect(resolve(rendered, 'ConfigPresetImportWizardApplyMutation', { ConfigPresetImportOutput: () => ({ results: simulated, report_id: null, settings: null }) })).resolves.not.toThrow();
    });

    it('does not offer Simulate with nothing selected', async () => {
      const rendered = await renderPreview(session({ revision: 1, selections: [] }));
      expect(screen.getByRole('button', { name: 'Simulate' })).toBeDisabled();
      expect(operationNames(rendered)).not.toContain('ConfigPresetImportWizardApplyMutation');
    });

    it('applies for real after a simulation, even when it showed failed items', async () => {
      const rendered = await renderPreview();
      await simulate(rendered);
      await rendered.user.click(screen.getByRole('button', { name: 'Apply' }));
      expect(operation(rendered, 'ConfigPresetImportWizardApplyMutation').request.variables).toMatchObject({ dry_run: false });
    });

    it('goes back to the upload step when the file is missing, and stays on the step for any other error', async () => {
      const rendered = await renderPreview();
      await rendered.user.click(screen.getByRole('button', { name: 'Simulate' }));
      await reject(rendered, 'ConfigPresetImportWizardApplyMutation', 'network');
      expect(await screen.findByRole('button', { name: 'Simulate' })).toBeEnabled();
      await rendered.user.click(screen.getByRole('button', { name: 'Simulate' }));
      await reject(rendered, 'ConfigPresetImportWizardApplyMutation', 'file_missing');
      expect(await screen.findByText('The uploaded file no longer exists')).toBeInTheDocument();
    });

    it('shows no expected result when the wizard is opened again on a draft session', async () => {
      await renderPreview(session({ revision: 2, selections: [{ type: 'messages', items: ['banner'], excluded_items: null }] }));
      expect(screen.queryByText(/Created|Overwritten|Skipped|Failed/)).not.toBeInTheDocument();
    });
  });
});
