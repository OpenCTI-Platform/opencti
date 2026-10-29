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
  fields: [],
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
// What the session returns for a processed item: its name, the type and the group of the type
const PROCESSED = {
  platform: { label: 'Platform configuration', translatable: true, type_label: 'Platform configuration', type_index: 0 },
  branding: { label: 'Import theme', translatable: false, type_label: 'Branding', type_index: 1 },
  messages: { label: 'Banner', translatable: true, type_label: 'Messages', type_index: 2 },
};
const processed = (type: keyof typeof PROCESSED, key: string, status: string, reason: string | null = null) => ({
  type,
  key,
  status,
  reason,
  ...PROCESSED[type],
  group: platformSettings,
});
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
const realApplies = ({ relayEnv }: Rendered) => relayEnv.mock.getAllOperations()
  .filter((candidate) => candidate.request.node.operation.name === 'ConfigPresetImportWizardApplyMutation' && candidate.request.variables.dry_run === false);
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
    it('keeps the loader when the session cannot be read', async () => {
      const rendered = testRender(<ConfigPresetImportWizard onFinish={onFinish} />, { userContext });
      await reject(rendered, 'ConfigPresetImportWizardQuery', 'elastic down');
      expect(screen.getByText('Loading')).toBeInTheDocument();
      expect(screen.queryByTestId('config-preset-wizard-import')).not.toBeInTheDocument();
    });

    it('shows the welcome choices, then the upload once the import is chosen', async () => {
      const { user } = await renderWizard(null);
      expect(screen.getByTestId('config-preset-wizard-import')).toBeInTheDocument();
      await user.click(within(screen.getByTestId('config-preset-wizard-import')).getByRole('button'));
      expect(screen.getByRole('button', { name: 'Upload a configuration bundle' })).toBeInTheDocument();
    });

    it('refuses a file that is not a zip in the field, without uploading it', async () => {
      const rendered = await renderWizard(null);
      await rendered.user.click(within(screen.getByTestId('config-preset-wizard-import')).getByRole('button'));
      // The change event does not go through the accept filter of the browser
      fireEvent.change(screen.getByTestId('config-preset-import-file'), { target: { files: [new File(['text'], 'notes.txt', { type: 'text/plain' })] } });
      expect(await screen.findByText('This file is not in the specified format')).toBeInTheDocument();
      expect(operationNames(rendered)).not.toContain('ConfigPresetImportUploadMutation');
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
    it('says that a value the bundle does not carry is left as it is', async () => {
      await renderPreview();
      expect(screen.getByText(/A value that the bundle does not carry is left as it is\./)).toBeInTheDocument();
    });

    it('reads the preview of the file of the session, with every item selected for a new upload', async () => {
      const rendered = await renderPreview();
      expect(operationNames(rendered)).not.toContain('ConfigPresetImportPreviewQuery');
      ['Platform configuration', 'Messages (1/1)'].forEach((name) => expect(checkbox(name)).toHaveAttribute('data-state', 'checked'));
      expect(checkbox('Branding (2/2)')).toHaveAttribute('data-state', 'checked');
      expect(screen.getByRole('button', { name: 'Apply' })).toBeEnabled();
    });

    it('restores the saved selection', async () => {
      await renderPreview(session({ revision: 2, selections: [{ type: 'messages', items: ['banner'], excluded_items: null }] }));
      expect(checkbox('Messages (1/1)')).toHaveAttribute('data-state', 'checked');
      expect(checkbox('Platform configuration')).toHaveAttribute('data-state', 'unchecked');
      expect(checkbox('Branding (0/2)')).toHaveAttribute('data-state', 'unchecked');
    });

    it('shows the required dependencies checked and disabled with their item', async () => {
      const { user } = await renderPreview(session({ revision: 1, selections: [{ type: 'messages', items: ['banner'], excluded_items: null }] }));
      await user.click(checkbox('Platform configuration'));
      const theme = within(screen.getByTestId('config-preset-import-item-branding-theme--1')).getByRole('checkbox');
      expect(theme).toBeDisabled();
      expect(theme).toHaveAttribute('data-state', 'checked');
    });

    it('lists the entity types the import hides under the item, by their names, while the item is selected', async () => {
      const withHiddenTypes = {
        ...preview,
        types: [
          ...preview.types,
          previewType('hiddenEntityTypes', 'Hidden entity types', [
            previewItem('hiddenEntityTypes', 'Hidden entity types', { fields: [{ key: 'hidden_entity_types', value: 'Attack-Pattern, Malware' }] }),
          ]),
        ],
      };
      const { user } = await renderPreview(session(), [], withHiddenTypes);
      expect(screen.getByText('Attack Pattern, Malware')).toBeInTheDocument();
      // A type with a single item of its name is one row, not a type with the same name below it
      expect(screen.getAllByText('Hidden entity types')).toHaveLength(1);
      await user.click(checkbox('Hidden entity types'));
      expect(screen.queryByText('Attack Pattern, Malware')).not.toBeInTheDocument();
    });

    it('disables Apply with nothing selected', async () => {
      const { user } = await renderPreview();
      await user.click(checkbox('Platform configuration'));
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
      // The import waits for the answer of the save: the session accepts a save only while it is a draft
      expect(operationNames(rendered)).toContain('ConfigPresetImportPreviewSaveMutation');
      expect(realApplies(rendered)).toHaveLength(0);
      await resolve(rendered, 'ConfigPresetImportPreviewSaveMutation', {});
      await waitFor(() => expect(realApplies(rendered)).toHaveLength(1));
      expect(realApplies(rendered)[0].request.variables).toEqual({
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

  describe('preview, requests that fail', () => {
    const rejectSave = async (rendered: Rendered, reason: string) => {
      await act(async () => {
        const target = rendered.relayEnv.mock.getAllOperations().filter((candidate) => candidate.request.node.operation.name === 'ConfigPresetImportPreviewSaveMutation').pop()!;
        rendered.relayEnv.mock.reject(target, { res: { errors: [{ message: reason, extensions: { code: 'FUNCTIONAL_ERROR', data: { reason } } }] } } as unknown as Error);
      });
    };

    it('goes back to the upload when the save says the file is missing', async () => {
      const rendered = await renderPreview();
      await rendered.user.click(checkbox('Messages (1/1)'));
      await waitFor(() => expect(operationNames(rendered)).toContain('ConfigPresetImportPreviewSaveMutation'), { timeout: 2000 });
      await rejectSave(rendered, 'file_missing');
      expect(await screen.findByText('The uploaded file no longer exists')).toBeInTheDocument();
    });

    it('sends one import when Apply is clicked twice while the save is pending', async () => {
      const rendered = await renderPreview();
      await rendered.user.click(checkbox('Messages (1/1)'));
      await resolveSimulation(rendered);
      await waitFor(() => expect(screen.getByRole('button', { name: 'Apply' })).toBeEnabled());
      await rendered.user.click(screen.getByRole('button', { name: 'Apply' }));
      // The save is in flight and the import is not sent yet: Apply cannot start a second one
      expect(screen.getByRole('button', { name: 'Apply' })).toBeDisabled();
      await rendered.user.click(screen.getByRole('button', { name: 'Apply' }));
      expect(realApplies(rendered)).toHaveLength(0);
      await resolve(rendered, 'ConfigPresetImportPreviewSaveMutation', {});
      await waitFor(() => expect(realApplies(rendered)).toHaveLength(1));
      await act(async () => {});
      expect(realApplies(rendered)).toHaveLength(1);
    });

    it('applies once the save is answered, even when the save failed', async () => {
      const rendered = await renderPreview();
      await rendered.user.click(checkbox('Messages (1/1)'));
      await resolveSimulation(rendered);
      await waitFor(() => expect(screen.getByRole('button', { name: 'Apply' })).toBeEnabled());
      await rendered.user.click(screen.getByRole('button', { name: 'Apply' }));
      expect(realApplies(rendered)).toHaveLength(0);
      await rejectSave(rendered, 'error');
      await waitFor(() => expect(realApplies(rendered)).toHaveLength(1));
    });

    it('drops the expected results of the previous selection when the new ones cannot be computed', async () => {
      const rendered = await renderPreview(session(), [{ type: 'messages', key: 'banner', status: 'OVERWRITTEN', reason: null }]);
      expect(await screen.findByText('Overwritten')).toBeInTheDocument();
      await rendered.user.click(checkbox('Platform configuration'));
      await waitFor(() => expect(dryRuns(rendered).length).toBeGreaterThan(0), { timeout: 2000 });
      await reject(rendered, 'ConfigPresetImportWizardApplyMutation', 'error');
      await waitFor(() => expect(screen.queryByText('Overwritten')).not.toBeInTheDocument());
    });
  });

  describe('preview, what is not imported', () => {
    it('lists the files of the bundle that cannot be imported', async () => {
      await renderPreview(session(), [], { ...preview, ignored: ['README.txt', 'other/unknown.json'] });
      expect(screen.getByText('Some files of the bundle cannot be imported')).toBeInTheDocument();
      expect(screen.getByText('README.txt, other/unknown.json')).toBeInTheDocument();
    });

    it('keeps the bundle when the confirmation of Start over is cancelled or dismissed', async () => {
      const rendered = await renderPreview();
      await rendered.user.click(screen.getByRole('button', { name: 'Start over' }));
      await rendered.user.click(within(screen.getByRole('dialog', { name: 'Start over' })).getByRole('button', { name: 'Cancel' }));
      await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Start over' })).not.toBeInTheDocument());
      await rendered.user.click(screen.getByRole('button', { name: 'Start over' }));
      await rendered.user.keyboard('{Escape}');
      await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Start over' })).not.toBeInTheDocument());
      expect(operationNames(rendered)).not.toContain('ConfigPresetImportWizardClearMutation');
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
        results: [processed('messages', 'banner', 'OVERWRITTEN'), processed('branding', 'theme--1', 'FAILED', 'Theme name already exists')],
      });
      await resolve(rendered, 'ConfigPresetImportWizardQuery', { Query: () => ({ configPresetImportSession: finished }) });
      expect(await screen.findByText('Import finished')).toBeInTheDocument();
      expect(screen.getByText('Theme name already exists')).toBeInTheDocument();
      expect(screen.getByText('0 created, 1 overwritten, 0 skipped, 1 failed')).toBeInTheDocument();
      expect(screen.getByRole('link', { name: 'Download report' })).toHaveAttribute('href', expect.stringContaining(encodeURIComponent('config_preset/history/id/import-report.json')));
    });

    it('names the section in each chevron, and links it to what it shows', async () => {
      await renderPreview();
      const chevron = screen.getByRole('button', { name: /^Collapse Platform settings/ });
      expect(chevron).toHaveAttribute('aria-expanded', 'true');
      expect(document.getElementById(chevron.getAttribute('aria-controls')!)).toBeInTheDocument();
    });

    it('keeps the progress until the session is read after the apply, instead of going back to the preview of a zip that is gone', async () => {
      const rendered = await renderPreview();
      await rendered.user.click(screen.getByRole('button', { name: 'Apply' }));
      await resolve(rendered, 'ConfigPresetImportWizardApplyMutation', {});
      // The session in hand is still the draft: the preview would ask for the zip that the import deleted
      expect(screen.getByText('Import in progress')).toBeInTheDocument();
      expect(operationNames(rendered)).not.toContain('ConfigPresetImportPreviewQuery');
      await resolve(rendered, 'ConfigPresetImportWizardQuery', {
        Query: () => ({ configPresetImportSession: session({ status: 'FINISHED', outcome: 'COMPLETED', total: 1, counts: { created: 0, overwritten: 1, skipped: 0, failed: 0 }, results: [processed('messages', 'banner', 'OVERWRITTEN')] }) }),
      });
      expect(await screen.findByText('Import finished')).toBeInTheDocument();
      expect(operationNames(rendered)).not.toContain('ConfigPresetImportPreviewQuery');
    });

    it('keeps the preview and goes back to the upload when the apply says the file is missing', async () => {
      const rendered = await renderPreview();
      await rendered.user.click(screen.getByRole('button', { name: 'Apply' }));
      await reject(rendered, 'ConfigPresetImportWizardApplyMutation', 'file_missing');
      expect(await screen.findByText('The uploaded file no longer exists')).toBeInTheDocument();
    });

    it('hands the entity settings that the import returns to the store, so that the hidden entity types need no refresh', async () => {
      const rendered = await renderPreview();
      await rendered.user.click(screen.getByRole('button', { name: 'Apply' }));
      await resolve(rendered, 'ConfigPresetImportWizardApplyMutation', {
        EntitySetting: () => ({ id: 'entity-setting-1', platform_hidden_type: true }),
        ConfigPresetImportOutput: () => ({ results: [], report_id: null, settings: null }),
      });
      expect(rendered.relayEnv.getStore().getSource().get('entity-setting-1')).toMatchObject({ platform_hidden_type: true });
    });

    describe('result groups', () => {
      const finished = (results: unknown[]) => session({
        status: 'FINISHED',
        outcome: 'COMPLETED',
        total: results.length,
        counts: { created: 0, overwritten: results.length, skipped: 0, failed: 0 },
        results,
      });
      // The items come in the order they were processed: the theme the platform depends on first
      const allImported = [processed('branding', 'theme--1', 'CREATED'), processed('platform', 'platform', 'OVERWRITTEN'), processed('messages', 'banner', 'OVERWRITTEN')];
      const oneFailed = [processed('branding', 'theme--1', 'FAILED', 'Theme name already exists'), processed('platform', 'platform', 'OVERWRITTEN'), processed('messages', 'banner', 'OVERWRITTEN')];

      it('keeps the groups closed when every item was imported, with what was imported out of all in the headers', async () => {
        await renderWizard(finished(allImported));
        expect(screen.getByText('Platform settings (3/3)')).toBeInTheDocument();
        expect(screen.queryByText('Branding (1/1)')).not.toBeInTheDocument();
        expect(screen.queryByText('Created')).not.toBeInTheDocument();
      });

      it('shows the types in the order of the selection, closed, and the names of the items once a type is opened', async () => {
        const { user } = await renderWizard(finished(allImported));
        await user.click(screen.getByRole('button', { name: /^Expand/ }));
        const headers = ['Platform configuration (1/1)', 'Branding (1/1)', 'Messages (1/1)'].map((name) => screen.getByText(name));
        headers.slice(1).forEach((header, index) => expect(headers[index].compareDocumentPosition(header) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy());
        expect(screen.queryByText('Import theme')).not.toBeInTheDocument();
        await user.click(screen.getAllByRole('button', { name: /^Expand/ })[1]);
        expect(screen.getByText('Import theme')).toBeInTheDocument();
        expect(screen.getByText('Created')).toBeInTheDocument();
        expect(screen.queryByText('theme--1')).not.toBeInTheDocument();
      });

      it('opens the group and the type that have a failed item, and only them', async () => {
        await renderWizard(finished(oneFailed));
        expect(screen.getByText('Platform settings (2/3)')).toBeInTheDocument();
        expect(screen.getByText('Branding (0/1)')).toBeInTheDocument();
        expect(screen.getByText('Import theme')).toBeInTheDocument();
        expect(screen.getByText('Failed')).toBeInTheDocument();
        expect(screen.getByText('Theme name already exists')).toBeInTheDocument();
        // What went well in the same group stays closed
        expect(screen.getByText('Platform configuration (1/1)')).toBeInTheDocument();
        expect(screen.getByText('Messages (1/1)')).toBeInTheDocument();
        expect(screen.queryByText('Banner')).not.toBeInTheDocument();
      });

      describe('ticks', () => {
        const ticks = () => screen.queryAllByTestId('config-preset-result-tick');

        it('lead the header of a group and of a type that went well, and each item that was imported', async () => {
          const { user } = await renderWizard(finished(allImported));
          // The group only: its types and its items are closed
          expect(ticks()).toHaveLength(1);
          await user.click(screen.getByRole('button', { name: /^Expand/ }));
          expect(ticks()).toHaveLength(4);
          await user.click(screen.getAllByRole('button', { name: /^Expand/ })[1]);
          expect(ticks()).toHaveLength(5);
          expect(within(screen.getByText('Import theme').parentElement!).getByTestId('config-preset-result-tick')).toBeInTheDocument();
        });

        it('are not shown for what failed, nor on the header that holds it, but are for the types that went well', async () => {
          await renderWizard(finished(oneFailed));
          // The group has a failure, the failed item has none: the types of the platform and of the messages went well
          expect(ticks()).toHaveLength(2);
          expect(within(screen.getByText('Import theme').parentElement!).queryByTestId('config-preset-result-tick')).not.toBeInTheDocument();
        });

        it('are not shown for what was skipped, and a header that only holds skipped items has none', async () => {
          const { user } = await renderWizard(finished([processed('platform', 'platform', 'SKIPPED', 'Nothing to import')]));
          expect(ticks()).toHaveLength(0);
          await user.click(screen.getByRole('button', { name: /^Expand/ }));
          await user.click(screen.getByRole('button', { name: /^Expand/ }));
          expect(screen.getByText('Skipped')).toBeInTheDocument();
          expect(ticks()).toHaveLength(0);
        });
      });

      it('lets a type that failed be closed, and a type that went well be opened', async () => {
        const { user } = await renderWizard(finished(oneFailed));
        await user.click(screen.getAllByRole('button', { name: /^Collapse/ })[1]);
        expect(screen.queryByText('Theme name already exists')).not.toBeInTheDocument();
        await user.click(screen.getAllByRole('button', { name: /^Expand/ }).at(-1)!);
        expect(screen.getByText('Banner')).toBeInTheDocument();
      });

      it('does not open a group for an item that was skipped', async () => {
        await renderWizard(finished([processed('platform', 'platform', 'SKIPPED', 'Nothing to import'), ...allImported.slice(2)]));
        expect(screen.getByText('Platform settings (2/2)')).toBeInTheDocument();
        expect(screen.queryByText('Nothing to import')).not.toBeInTheDocument();
      });

      it('groups the results of an interrupted import the same way', async () => {
        await renderWizard(session({ status: 'INTERRUPTED', total: 3, results: oneFailed.slice(0, 2) }));
        expect(screen.getByText('Platform settings (1/2)')).toBeInTheDocument();
        expect(screen.getByText('Theme name already exists')).toBeInTheDocument();
      });
    });

    it('resumes on the progress screen when the session is applying, and polls every five seconds until it changes', async () => {
      vi.useFakeTimers({ shouldAdvanceTime: true });
      const applying = session({ status: 'APPLYING', total: 4, results: [processed('messages', 'banner', 'OVERWRITTEN')] });
      const rendered = await renderWizard(applying);
      expect(screen.getByText('1 of 4 items processed')).toBeInTheDocument();
      // The progress names the items, it does not show their keys
      expect(screen.getByText('Banner')).toBeInTheDocument();
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
      await renderWizard(session({ status: 'FINISHED', outcome: 'COMPLETED', counts: { created: 1, overwritten: 0, skipped: 0, failed: 0 }, results: [processed('messages', 'banner', 'CREATED')] }));
      expect(screen.getByText('Platform settings (1/1)')).toBeInTheDocument();
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
        results: [processed('messages', 'banner', 'OVERWRITTEN')],
      }));
      expect(screen.getByText('The import was interrupted')).toBeInTheDocument();
      // Grouped like the result, closed as nothing failed
      expect(screen.getByText('Platform settings (1/1)')).toBeInTheDocument();
      expect(screen.queryByText('Overwritten')).not.toBeInTheDocument();
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

    it('keeps the interrupted import when the confirmation of Start over is cancelled or dismissed', async () => {
      const rendered = await renderWizard(session({ status: 'INTERRUPTED' }));
      await rendered.user.click(screen.getByRole('button', { name: 'Start over' }));
      await rendered.user.click(within(screen.getByRole('dialog', { name: 'Start over' })).getByRole('button', { name: 'Cancel' }));
      await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Start over' })).not.toBeInTheDocument());
      await rendered.user.click(screen.getByRole('button', { name: 'Start over' }));
      await rendered.user.keyboard('{Escape}');
      await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Start over' })).not.toBeInTheDocument());
      expect(operationNames(rendered)).not.toContain('ConfigPresetImportWizardClearMutation');
      expect(screen.getByText('The import was interrupted')).toBeInTheDocument();
    });

    it('keeps what it shows when the running import cannot be read', async () => {
      const rendered = await renderWizard(null);
      await reject(rendered, 'ConfigPresetImportWizardRunningQuery', 'redis down');
      expect(screen.getByTestId('config-preset-wizard-import')).toBeInTheDocument();
      expect(screen.queryByText(/Import by/)).not.toBeInTheDocument();
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
      expect(checkbox('Platform configuration')).toHaveAttribute('data-state', 'unchecked');
      expect(screen.queryByText('An import is already running')).not.toBeInTheDocument();
    });

    it('shows the result of an import that was stopped like any other outcome', async () => {
      await renderWizard(session({
        status: 'FINISHED',
        outcome: 'STOPPED',
        counts: { created: 0, overwritten: 1, skipped: 0, failed: 1 },
        results: [processed('platform', 'platform', 'OVERWRITTEN'), processed('messages', 'banner', 'FAILED', 'Import stopped: lock lost')],
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

    it('says that the platform keeps its default theme when that theme is added as a copy, and only then', async () => {
      const defaultInConflict = {
        ...preview,
        types: preview.types.map((type) => (type.key === 'branding'
          ? { ...type, items: (type.items as { key: string }[]).map((item) => (item.key === 'theme--1' ? { ...item, exists: true, conflict: true } : item)) }
          : type)),
      };
      const rendered = await renderPreview(session(), [], defaultInConflict);
      const hint = 'The platform keeps its current default theme.';
      const defaultSelect = () => screen.getByRole('combobox', { name: 'Import theme: When it already exists' });
      expect(screen.queryByText(hint)).not.toBeInTheDocument();
      await rendered.user.click(defaultSelect());
      await rendered.user.click(await screen.findByRole('option', { name: 'Add as a copy' }));
      expect(screen.getByText(hint)).toBeInTheDocument();
      // The theme that is not the default has no such hint
      await rendered.user.click(screen.getByRole('combobox', { name: 'Existing theme: When it already exists' }));
      await rendered.user.click(await screen.findByRole('option', { name: 'Add as a copy' }));
      expect(screen.getAllByText(hint)).toHaveLength(1);
      await rendered.user.click(defaultSelect());
      await rendered.user.click(await screen.findByRole('option', { name: 'Overwrite' }));
      expect(screen.queryByText(hint)).not.toBeInTheDocument();
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

      it('does not count an item that is not imported: with one left in conflict, the choice of the item is enough', async () => {
        const { user } = await renderTwo();
        expect(familySelect()).toBeInTheDocument();
        await user.click(within(screen.getByTestId('config-preset-import-item-branding-theme--3')).getByRole('checkbox'));
        expect(screen.queryByRole('combobox', { name: 'Branding: Apply to all' })).not.toBeInTheDocument();
        expect(modeSelect()).toBeInTheDocument();
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
