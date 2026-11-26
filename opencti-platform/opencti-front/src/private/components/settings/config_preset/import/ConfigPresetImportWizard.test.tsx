import React, { useSyncExternalStore } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { MockPayloadGenerator } from 'relay-test-utils';
import testRender, { createMockUserContext } from '../../../../../utils/tests/test-render';
import ConfigPresetImportWizard from './ConfigPresetImportWizard';

// The Enterprise Edition of the platform, which can change while the wizard is open (a license activated from it)
const enterpriseEdition = vi.hoisted(() => {
  const listeners = new Set<() => void>();
  return {
    enabled: false,
    subscribe: (listener: () => void) => {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
    activate: () => {
      enterpriseEdition.enabled = true;
      listeners.forEach((listener) => listener());
    },
  };
});
vi.mock('../../../../../utils/hooks/useEnterpriseEdition', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../utils/hooks/useEnterpriseEdition')>()),
  default: () => useSyncExternalStore(enterpriseEdition.subscribe, () => enterpriseEdition.enabled),
}));

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
  credentials: [],
  dependsOn: [],
  ...overrides,
});
// A type listed whole, as the API does for all but the types of thousands of items: its page is all of its items
const previewType = (key: string, label: string, items: unknown[], modes = ['OVERWRITE'], lockedByEnterpriseEdition = false) => ({
  key,
  label,
  description: `${label} description`,
  group: platformSettings,
  lockedByEnterpriseEdition,
  modes,
  items,
  itemsPageInfo: { globalCount: items.length, hasNextPage: false },
  conflictsCount: items.filter((item) => (item as { conflict?: boolean }).conflict).length,
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
// A bundle with the whitemark, a type that needs the Enterprise Edition: a platform without it has no item of it
const previewWithWhitemark = {
  ...preview,
  types: [...preview.types, previewType('whitemark', 'Remove Filigran logos', [], ['OVERWRITE'], true)],
};
// The same bundle once the platform has the license: the type comes with its item
const previewWithWhitemarkUnlocked = {
  ...preview,
  types: [...preview.types, previewType('whitemark', 'Remove Filigran logos', [previewItem('whitemark', 'Remove Filigran logos')])],
};
const ENTERPRISE_EDITION_GATE = 'Activate the Enterprise Edition to import this item';
const whitemarkRow = () => within(screen.getByTestId('config-preset-import-item-whitemark-whitemark'));
const lockedWhitemark = () => within(screen.getByRole('button', { name: ENTERPRISE_EDITION_GATE, hidden: true }));
// The types of the selection the pending expected results are asked for (a resolved request is no longer pending)
const lastSimulatedTypes = (rendered: Rendered) => (dryRuns(rendered).at(-1)!.request.variables.selections as { type: string }[]).map(({ type }) => type);
const simulatedTypes = async (rendered: Rendered) => {
  await waitFor(() => expect(dryRuns(rendered).length).toBeGreaterThan(0));
  return lastSimulatedTypes(rendered);
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
const previewWithConnector = {
  ...preview,
  types: [
    previewType('connectors', 'Connectors', [
      previewItem('mitre', 'MITRE', {
        translatable: false,
        exists: false,
        credentials: [{ key: 'MITRE_API_KEY', description: 'The key of the MITRE API', required: true, stored: false, secret: true, type: 'string' }],
      }),
    ], ['OVERWRITE', 'COPY']),
  ],
};
// What the session says of a run, as the backend gives it: counts by type, the first problems, the last items. The tests state the results
// of the run, and this is what the screens get of them.
const progressOf = (results: ReturnType<typeof processed>[]) => {
  const counts = new Map<string, Record<string, unknown>>();
  const bucket = (result: { status: string; code?: string | null }) => (result.status === 'SKIPPED' && result.code === 'unchanged' ? 'unchanged' : result.status.toLowerCase());
  results.forEach((result) => {
    const known = counts.get(result.type) ?? {
      type: result.type, type_label: result.type_label, type_index: result.type_index, group: result.group, created: 0, overwritten: 0, unchanged: 0, skipped: 0, failed: 0,
    };
    known[bucket(result)] = (known[bucket(result)] as number) + 1;
    counts.set(result.type, known);
  });
  return {
    processed: results.length,
    type_counts: [...counts.values()],
    problems: results.filter((result) => ['failed', 'skipped'].includes(bucket(result))).slice(0, 100),
    recent: results.slice(-10),
  };
};
const session = ({ results = [], ...overrides }: Record<string, unknown> = {}) => ({
  status: 'DRAFT',
  file_id: 'config_preset/import/id/bundle.zip',
  revision: 0,
  selections: [],
  total: 0,
  ...progressOf(results as ReturnType<typeof processed>[]),
  outcome: null,
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
// The groups open their types: each expanded level shows the chevrons of the next one
const expandAll = async ({ user }: Rendered) => {
  let chevrons = screen.queryAllByRole('button', { name: /^Expand/ });
  while (chevrons.length > 0) {
    for (const chevron of chevrons) {
      await user.click(chevron);
    }
    chevrons = screen.queryAllByRole('button', { name: /^Expand/ });
  }
};
// The preview shown, every section open, its expected results not in yet
const openPreview = async (currentSession = session(), data: unknown = preview, expanded = true) => {
  const rendered = await renderWizard(currentSession);
  await resolve(rendered, 'ConfigPresetImportPreviewQuery', { Query: () => ({ configPresetImportPreview: data }) });
  await screen.findByRole('button', { name: 'Apply' });
  if (expanded) {
    await expandAll(rendered);
  }
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
    enterpriseEdition.enabled = false;
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

    describe('a type that needs the Enterprise Edition', () => {
      it('is shown locked on a platform without it, with no item, and is asked for neither the expected results nor the import', async () => {
        const rendered = await openPreview(session(), previewWithWhitemark);
        // One row behind the gate, unchecked, with its chip
        expect(lockedWhitemark().getByRole('checkbox', { hidden: true })).toHaveAttribute('data-state', 'unchecked');
        expect(lockedWhitemark().getByText('EE')).toBeInTheDocument();
        expect(screen.queryByTestId('config-preset-import-item-whitemark-whitemark')).not.toBeInTheDocument();
        expect(await simulatedTypes(rendered)).toEqual(['platform', 'branding', 'messages']);
        await resolveSimulation(rendered);
        await waitFor(() => expect(screen.getByRole('button', { name: 'Apply' })).toBeEnabled());
        await rendered.user.click(screen.getByRole('button', { name: 'Apply' }));
        expect((operation(rendered, 'ConfigPresetImportWizardApplyMutation').request.variables.selections as { type: string }[]).map(({ type }) => type)).toEqual(['platform', 'branding', 'messages']);
      });

      it('opens the license dialog instead of being selected', async () => {
        const { user } = await renderPreview(session(), [], previewWithWhitemark);
        await user.click(screen.getByRole('button', { name: ENTERPRISE_EDITION_GATE }));
        expect(await screen.findByText('OpenCTI Enterprise Edition (EE) license agreement')).toBeInTheDocument();
        expect(lockedWhitemark().getByRole('checkbox', { hidden: true })).toHaveAttribute('data-state', 'unchecked');
      });

      it('is not counted by its group, which can be cleared and checked again without ever selecting it', async () => {
        const { user } = await renderPreview(session(), [], previewWithWhitemark);
        // Everything that can be selected is, and the type has nothing to count
        expect(checkbox('Platform settings (4/4)')).toHaveAttribute('data-state', 'checked');
        await user.click(checkbox('Platform settings (4/4)'));
        expect(checkbox('Platform settings (0/4)')).toHaveAttribute('data-state', 'unchecked');
        await user.click(checkbox('Platform settings (0/4)'));
        expect(checkbox('Platform settings (4/4)')).toHaveAttribute('data-state', 'checked');
        expect(lockedWhitemark().getByRole('checkbox', { hidden: true })).toHaveAttribute('data-state', 'unchecked');
      });

      it('is not sent from a selection saved before, either', async () => {
        await openPreview(session({ revision: 2, selections: [{ type: 'whitemark', items: ['whitemark'], excluded_items: null }] }), previewWithWhitemark);
        expect(lockedWhitemark().getByRole('checkbox', { hidden: true })).toHaveAttribute('data-state', 'unchecked');
        expect(screen.getByRole('button', { name: 'Apply' })).toBeDisabled();
      });

      it('is read again as soon as a license is activated, without a refresh: its item comes selected, and the expected results are asked again with it', async () => {
        const rendered = await renderPreview(session(), [], previewWithWhitemark);
        const askedBefore = dryRuns(rendered).length;
        const previewReads = () => rendered.relayEnv.mock.getAllOperations().filter((candidate) => candidate.request.node.operation.name === 'ConfigPresetImportPreviewQuery').length;
        expect(previewReads()).toBe(0);
        await act(async () => {
          enterpriseEdition.activate();
        });
        await waitFor(() => expect(previewReads()).toBe(1));
        await resolve(rendered, 'ConfigPresetImportPreviewQuery', { Query: () => ({ configPresetImportPreview: previewWithWhitemarkUnlocked }) });
        expect(screen.queryByRole('button', { name: ENTERPRISE_EDITION_GATE })).not.toBeInTheDocument();
        expect(whitemarkRow().queryByText('EE')).not.toBeInTheDocument();
        expect(whitemarkRow().getByRole('checkbox')).toHaveAttribute('data-state', 'checked');
        await waitFor(() => expect(dryRuns(rendered).length).toBeGreaterThan(askedBefore));
        expect(await simulatedTypes(rendered)).toEqual(['platform', 'branding', 'messages', 'whitemark']);
        // The checkbox is the user's again
        await rendered.user.click(whitemarkRow().getByRole('checkbox'));
        expect(whitemarkRow().getByRole('checkbox')).toHaveAttribute('data-state', 'unchecked');
      });

      it('keeps the selection made until the license is activated, and saves the new one', async () => {
        const rendered = await renderPreview(session(), [], previewWithWhitemark);
        await rendered.user.click(checkbox('Messages (1/1)'));
        await act(async () => {
          enterpriseEdition.activate();
        });
        await waitFor(() => expect(operationNames(rendered)).toContain('ConfigPresetImportPreviewQuery'));
        await resolve(rendered, 'ConfigPresetImportPreviewQuery', { Query: () => ({ configPresetImportPreview: previewWithWhitemarkUnlocked }) });
        expect(checkbox('Messages (0/1)')).toHaveAttribute('data-state', 'unchecked');
        expect(whitemarkRow().getByRole('checkbox')).toHaveAttribute('data-state', 'checked');
        await waitFor(() => expect(lastSimulatedTypes(rendered)).toEqual(['platform', 'branding', 'whitemark']));
        // The selection that is saved holds the type that was unlocked
        await waitFor(() => expect(operationNames(rendered)).toContain('ConfigPresetImportPreviewSaveMutation'), { timeout: 3000 });
        expect((operation(rendered, 'ConfigPresetImportPreviewSaveMutation').request.variables.selections as { type: string }[]).map(({ type }) => type)).toEqual(['platform', 'branding', 'whitemark']);
      });

      it('comes selected once a license is activated, even when its group was cleared before, as in the export', async () => {
        const rendered = await renderPreview(session(), [], previewWithWhitemark);
        await rendered.user.click(checkbox('Platform settings (4/4)'));
        await act(async () => {
          enterpriseEdition.activate();
        });
        await waitFor(() => expect(operationNames(rendered)).toContain('ConfigPresetImportPreviewQuery'));
        await resolve(rendered, 'ConfigPresetImportPreviewQuery', { Query: () => ({ configPresetImportPreview: previewWithWhitemarkUnlocked }) });
        expect(whitemarkRow().getByRole('checkbox')).toHaveAttribute('data-state', 'checked');
        expect(checkbox('Messages (0/1)')).toHaveAttribute('data-state', 'unchecked');
      });

      it('keeps the preview that is shown when the reload that follows a license change fails', async () => {
        const rendered = await renderPreview(session(), [], previewWithWhitemark);
        await act(async () => {
          enterpriseEdition.activate();
        });
        await waitFor(() => expect(operationNames(rendered)).toContain('ConfigPresetImportPreviewQuery'));
        await reject(rendered, 'ConfigPresetImportPreviewQuery', 'elastic down');
        expect(screen.queryByText('This configuration bundle cannot be imported')).not.toBeInTheDocument();
        expect(checkbox('Messages (1/1)')).toBeInTheDocument();
      });

      it.each([
        ['on', true, 'Enabled'],
        ['off', false, 'Disabled'],
      ])('shows its value under its name when it is %s in the bundle', async (_, isEnabled, label) => {
        enterpriseEdition.enabled = true;
        const withValue = {
          ...preview,
          types: [...preview.types, previewType('whitemark', 'Remove Filigran logos', [previewItem('whitemark', 'Remove Filigran logos', { isEnabled })])],
        };
        await openPreview(session(), withValue);
        expect(whitemarkRow().getByText(label)).toBeInTheDocument();
      });

      it('shows nothing under its name when the bundle does not set it', async () => {
        enterpriseEdition.enabled = true;
        const withoutValue = {
          ...preview,
          types: [...preview.types, previewType('whitemark', 'Remove Filigran logos', [previewItem('whitemark', 'Remove Filigran logos', { isEnabled: null })])],
        };
        await openPreview(session(), withoutValue);
        expect(whitemarkRow().queryByText(/Enabled|Disabled/)).not.toBeInTheDocument();
      });

      it('is selected like any type, with no gate, on a platform that has the Enterprise Edition', async () => {
        enterpriseEdition.enabled = true;
        const rendered = await openPreview(session(), previewWithWhitemarkUnlocked);
        expect(screen.queryByRole('button', { name: ENTERPRISE_EDITION_GATE })).not.toBeInTheDocument();
        expect(whitemarkRow().getByRole('checkbox')).toHaveAttribute('data-state', 'checked');
        expect(await simulatedTypes(rendered)).toEqual(['platform', 'branding', 'messages', 'whitemark']);
      });
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
        credentials: [],
        service_accounts: [],
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

    it('cancels a preview that is loading: the request is aborted, the zip is deleted and the upload comes back', async () => {
      const rendered = await renderWizard(session());
      // Nothing answered yet: the loader has a way out
      expect(operationNames(rendered)).toContain('ConfigPresetImportPreviewQuery');
      await rendered.user.click(await screen.findByRole('button', { name: 'Cancel' }));
      // No confirmation: nothing was selected. The preview request is no longer pending, and the session is cleared with its file
      expect(operationNames(rendered)).not.toContain('ConfigPresetImportPreviewQuery');
      expect(operation(rendered, 'ConfigPresetImportWizardClearMutation').request.variables).toEqual({ delete_file: true });
      await resolve(rendered, 'ConfigPresetImportWizardClearMutation', {});
      expect(await screen.findByRole('button', { name: 'Upload a configuration bundle' })).toBeInTheDocument();
    });

    it('aborts the preview request when the wizard is closed while it loads', async () => {
      const rendered = await renderWizard(session());
      expect(operationNames(rendered)).toContain('ConfigPresetImportPreviewQuery');
      rendered.unmount();
      expect(operationNames(rendered)).not.toContain('ConfigPresetImportPreviewQuery');
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

    it('waits for a save already sent by its delay before sending the import', async () => {
      const rendered = await renderPreview();
      vi.useFakeTimers();
      fireEvent.click(checkbox('Messages (1/1)'));
      // The 500 ms delay ends before Apply: the save is sent and its answer is not in yet
      await act(async () => {
        vi.advanceTimersByTime(501);
      });
      vi.useRealTimers();
      expect(operationNames(rendered)).toContain('ConfigPresetImportPreviewSaveMutation');
      await resolveSimulation(rendered);
      await waitFor(() => expect(screen.getByRole('button', { name: 'Apply' })).toBeEnabled());
      await rendered.user.click(screen.getByRole('button', { name: 'Apply' }));
      expect(realApplies(rendered)).toHaveLength(0);
      expect(screen.getByRole('button', { name: 'Apply' })).toBeDisabled();
      await resolve(rendered, 'ConfigPresetImportPreviewSaveMutation', {});
      await waitFor(() => expect(realApplies(rendered)).toHaveLength(1));
    });

    it('waits for every save in flight, not only the last one, before sending the import', async () => {
      const rendered = await renderPreview();
      const saves = () => rendered.relayEnv.mock.getAllOperations().filter((candidate) => candidate.request.node.operation.name === 'ConfigPresetImportPreviewSaveMutation');
      vi.useFakeTimers();
      // Two saves sent by their delay, neither answered
      fireEvent.click(checkbox('Messages (1/1)'));
      await act(async () => {
        vi.advanceTimersByTime(501);
      });
      fireEvent.click(checkbox('Messages (0/1)'));
      await act(async () => {
        vi.advanceTimersByTime(501);
      });
      vi.useRealTimers();
      expect(saves()).toHaveLength(2);
      const [first, second] = saves();
      await resolveSimulation(rendered);
      await waitFor(() => expect(screen.getByRole('button', { name: 'Apply' })).toBeEnabled());
      await rendered.user.click(screen.getByRole('button', { name: 'Apply' }));
      // The second save is answered first: the first one is still in flight
      await act(async () => {
        rendered.relayEnv.mock.resolve(second, MockPayloadGenerator.generate(second, {}));
      });
      await act(async () => {});
      expect(realApplies(rendered)).toHaveLength(0);
      await act(async () => {
        rendered.relayEnv.mock.resolve(first, MockPayloadGenerator.generate(first, {}));
      });
      await waitFor(() => expect(realApplies(rendered)).toHaveLength(1));
    });

    it('disables the selection and the modes while Apply waits for the save', async () => {
      const rendered = await renderPreview();
      await rendered.user.click(checkbox('Messages (1/1)'));
      await resolveSimulation(rendered);
      await waitFor(() => expect(screen.getByRole('button', { name: 'Apply' })).toBeEnabled());
      expect(screen.getByRole('combobox', { name: 'Existing theme: When it already exists' })).toBeEnabled();
      await rendered.user.click(screen.getByRole('button', { name: 'Apply' }));
      // A change now would be saved after the import is sent, when the session is no longer a draft
      expect(checkbox('Messages (0/1)')).toBeDisabled();
      expect(checkbox('Platform configuration')).toBeDisabled();
      expect(within(screen.getByTestId('config-preset-import-item-branding-theme--2')).getByRole('checkbox')).toBeDisabled();
      expect(screen.getByRole('combobox', { name: 'Existing theme: When it already exists' })).toBeDisabled();
      await resolve(rendered, 'ConfigPresetImportPreviewSaveMutation', {});
      await waitFor(() => expect(realApplies(rendered)).toHaveLength(1));
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
        results: [processed('messages', 'banner', 'OVERWRITTEN'), processed('branding', 'theme--1', 'FAILED', 'Theme name already exists')],
      });
      await resolve(rendered, 'ConfigPresetImportWizardQuery', { Query: () => ({ configPresetImportSession: finished }) });
      expect(await screen.findByText('Import finished')).toBeInTheDocument();
      expect(screen.getByText('Theme name already exists')).toBeInTheDocument();
      expect(screen.getByText('0 created, 1 overwritten, 0 up to date, 0 skipped, 1 failed')).toBeInTheDocument();
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
        Query: () => ({ configPresetImportSession: session({ status: 'FINISHED', outcome: 'COMPLETED', total: 1, results: [processed('messages', 'banner', 'OVERWRITTEN')] }) }),
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

    describe('result', () => {
      const finished = (results: unknown[], overrides: Record<string, unknown> = {}) => session({
        status: 'FINISHED',
        outcome: 'COMPLETED',
        total: results.length,
        results,
        ...overrides,
      });
      // The items come in the order they were processed: the theme the platform depends on first
      const allImported = [processed('branding', 'theme--1', 'CREATED'), processed('platform', 'platform', 'OVERWRITTEN'), processed('messages', 'banner', 'OVERWRITTEN')];
      const oneFailed = [processed('branding', 'theme--1', 'FAILED', 'Theme name already exists'), processed('platform', 'platform', 'OVERWRITTEN'), processed('messages', 'banner', 'OVERWRITTEN')];

      it('says what was done by type under its group, in the order of the selection, without listing the items that went well', async () => {
        await renderWizard(finished(allImported));
        expect(screen.getByText('Platform settings')).toBeInTheDocument();
        const lines = ['Platform configuration: 1 overwritten', 'Branding: 1 created', 'Messages: 1 overwritten'].map((name) => screen.getByText(name));
        lines.slice(1).forEach((line, index) => expect(lines[index].compareDocumentPosition(line) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy());
        expect(screen.getByText('1 created, 2 overwritten, 0 up to date, 0 skipped, 0 failed')).toBeInTheDocument();
        // Nothing to check: no list, and the names of the items are not shown
        expect(screen.queryByText(/^Items to check/)).not.toBeInTheDocument();
        expect(screen.queryByText('Import theme')).not.toBeInTheDocument();
        expect(screen.queryByText('Banner')).not.toBeInTheDocument();
      });

      it('lists what failed under the items to check, with the type, the name and the reason', async () => {
        await renderWizard(finished(oneFailed));
        expect(screen.getByText('Items to check (1)')).toBeInTheDocument();
        expect(screen.getByText('Branding: Import theme')).toBeInTheDocument();
        expect(screen.getByText('Failed')).toBeInTheDocument();
        expect(screen.getByText('Theme name already exists')).toBeInTheDocument();
        expect(screen.getByText('Branding: 1 failed')).toBeInTheDocument();
        // What went well is not listed
        expect(screen.queryByText('Banner')).not.toBeInTheDocument();
      });

      it('lists the first problems only, and sends to the report for the rest', async () => {
        const failures = Array.from({ length: 100 }, (_, index) => processed('messages', `banner-${index}`, 'FAILED', 'Bad value'));
        const counted = { ...progressOf(failures), type_counts: [{ ...progressOf(failures).type_counts[0], failed: 150 }] };
        await renderWizard(finished([], { ...counted, report_id: 'config_preset/history/id/import-report.json' }));
        expect(screen.getByText('Items to check (150)')).toBeInTheDocument();
        expect(screen.getAllByText('Bad value')).toHaveLength(100);
        expect(screen.getByText('The first 100 of 150 are listed. The report holds the complete list.')).toBeInTheDocument();
      });

      it('does not send to a report that was not written', async () => {
        const failures = Array.from({ length: 3 }, (_, index) => processed('messages', `banner-${index}`, 'FAILED', 'Bad value'));
        const counted = { ...progressOf(failures), type_counts: [{ ...progressOf(failures).type_counts[0], failed: 5 }] };
        await renderWizard(finished([], counted));
        expect(screen.getByText('The first 3 of 5 are listed.')).toBeInTheDocument();
      });

      it('leads with a tick the types that went well, not the ones with a failure or an item that was skipped', async () => {
        await renderWizard(finished([...oneFailed, processed('platform', 'platform', 'SKIPPED', 'Nothing to import')]));
        // The messages went well; the branding failed and the platform has a skipped item
        const ticks = screen.queryAllByTestId('config-preset-result-tick');
        expect(ticks).toHaveLength(1);
        expect(within(screen.getByText('Messages: 1 overwritten').parentElement!).getByTestId('config-preset-result-tick')).toBeInTheDocument();
      });

      it('lists what was skipped for a reason as an item to check, but not what the platform had as it is', async () => {
        await renderWizard(finished([
          { ...processed('messages', 'banner', 'SKIPPED', 'Already up to date'), code: 'unchanged' },
          processed('platform', 'platform', 'SKIPPED', 'Nothing to import'),
        ]));
        expect(screen.getByText('Items to check (1)')).toBeInTheDocument();
        expect(screen.getByText('Nothing to import')).toBeInTheDocument();
        expect(screen.queryByText('Already up to date')).not.toBeInTheDocument();
        expect(screen.getByText('Messages: 1 up to date')).toBeInTheDocument();
      });

      it('shows the counts and the problems of an interrupted import the same way', async () => {
        await renderWizard(session({ status: 'INTERRUPTED', total: 3, results: oneFailed.slice(0, 2) }));
        expect(screen.getByText('Items processed before the stop')).toBeInTheDocument();
        expect(screen.getByText('Platform configuration: 1 overwritten')).toBeInTheDocument();
        expect(screen.getByText('Items to check (1)')).toBeInTheDocument();
        expect(screen.getByText('Theme name already exists')).toBeInTheDocument();
      });
    });

    it('does not ask for the result of every item when the import is real, only when it is simulated', async () => {
      const rendered = await renderPreview();
      await rendered.user.click(screen.getByRole('button', { name: 'Apply' }));
      expect(realApplies(rendered)).toHaveLength(1);
      // The same document applies and simulates, and only the simulation reads the results of the items
      expect(realApplies(rendered)[0].request.node.params.text).toContain('@include(if: $dry_run)');
    });

    it('resumes on the progress screen when the session is applying, and polls every five seconds until it changes', async () => {
      vi.useFakeTimers({ shouldAdvanceTime: true });
      const applying = session({ status: 'APPLYING', total: 4, results: [processed('messages', 'banner', 'OVERWRITTEN')] });
      const rendered = await renderWizard(applying);
      expect(screen.getByText('1 of 4 items processed')).toBeInTheDocument();
      expect(screen.getByRole('progressbar', { name: 'Import progress' })).toHaveAttribute('aria-valuenow', '25');
      // The progress names the items, it does not show their keys
      expect(screen.getByText('Banner')).toBeInTheDocument();
      await act(async () => {
        vi.advanceTimersByTime(5000);
      });
      expect(operationNames(rendered)).toContain('ConfigPresetImportWizardQuery');
      await resolve(rendered, 'ConfigPresetImportWizardQuery', { Query: () => ({ configPresetImportSession: session({ status: 'FINISHED', total: 4 }) }) });
      expect(await screen.findByText('Import finished')).toBeInTheDocument();
      await act(async () => {
        vi.advanceTimersByTime(10000);
      });
      expect(operationNames(rendered)).not.toContain('ConfigPresetImportWizardQuery');
    });

    it('shows the result of a finished import without report link when there is no report', async () => {
      await renderWizard(session({ status: 'FINISHED', outcome: 'COMPLETED', results: [processed('messages', 'banner', 'CREATED')] }));
      expect(screen.getByText('Messages: 1 created')).toBeInTheDocument();
      expect(screen.queryByRole('link', { name: 'Download report' })).not.toBeInTheDocument();
    });

    it('counts the items the platform already had as they are apart from the skipped ones', async () => {
      await renderWizard(session({
        status: 'FINISHED',
        outcome: 'COMPLETED',
        results: [
          { ...processed('messages', 'banner', 'SKIPPED', 'Already up to date'), code: 'unchanged' },
          processed('branding', 'theme--1', 'SKIPPED', 'Theme name already exists'),
        ],
      }));
      expect(screen.getByText('0 created, 0 overwritten, 1 up to date, 1 skipped, 0 failed')).toBeInTheDocument();
    });

    it('clears the session and closes the wizard on Close of the result', async () => {
      const rendered = await renderWizard(session({ status: 'FINISHED', outcome: 'COMPLETED' }));
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
      // What was done by type, like the result
      expect(screen.getByText('Messages: 1 overwritten')).toBeInTheDocument();
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
      await expandAll(rendered);
      expect(checkbox('Messages (1/1)')).toHaveAttribute('data-state', 'checked');
      expect(checkbox('Platform configuration')).toHaveAttribute('data-state', 'unchecked');
      expect(screen.queryByText('An import is already running')).not.toBeInTheDocument();
    });

    it('shows the result of an import that was stopped like any other outcome', async () => {
      await renderWizard(session({
        status: 'FINISHED',
        outcome: 'STOPPED',
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
        credentials: [],
        service_accounts: [],
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
      // Under the label of the row, after what the item is
      expect(within(platform).getByText(/Default theme Import theme could not be imported/)).toBeInTheDocument();
      // Not selected, not shown
      expect(within(screen.getByTestId('config-preset-import-item-messages-banner')).queryByText('Overwritten')).not.toBeInTheDocument();
    });

    it('shows nothing for an item that has nothing to change on the platform', async () => {
      await renderPreview(session(), [{ type: 'messages', key: 'banner', status: 'SKIPPED', reason: 'Nothing to import', code: 'nothing_to_import' }]);
      expect(within(screen.getByTestId('config-preset-import-item-messages-banner')).queryByText(/Created|Overwritten|Skipped|Failed|Nothing to import/)).not.toBeInTheDocument();
    });

    it('says that an item the platform has already is up to date, without a status', async () => {
      await renderPreview(session(), [{ type: 'messages', key: 'banner', status: 'SKIPPED', reason: 'Already up to date', code: 'unchanged' }]);
      const banner = within(screen.getByTestId('config-preset-import-item-messages-banner'));
      expect(banner.getByText('Already up to date')).toBeInTheDocument();
      expect(banner.queryByText('Skipped')).not.toBeInTheDocument();
    });

    it('shows the expected result before the choice, which ends the row', async () => {
      await renderPreview(session(), [{ type: 'branding', key: 'theme--2', status: 'SKIPPED', reason: 'Already up to date', code: 'unchanged' }]);
      const row = within(screen.getByTestId('config-preset-import-item-branding-theme--2'));
      const choice = row.getByRole('combobox', { name: 'Existing theme: When it already exists' });
      expect(row.getByText('Already up to date').compareDocumentPosition(choice) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    });

    it('shows that an item with no choice is overwritten', async () => {
      await renderPreview(session(), simulated);
      expect(within(screen.getByTestId('config-preset-import-item-messages-banner')).getByText('Overwritten')).toBeInTheDocument();
    });

    it('shows the default tag of an item', async () => {
      await renderPreview();
      expect(within(screen.getByTestId('config-preset-import-item-branding-theme--1')).getByText('default')).toBeInTheDocument();
    });

    it('computes them again on a selection change, Apply and the checkboxes staying usable', async () => {
      const rendered = await renderPreview(session(), simulated);
      await rendered.user.click(checkbox('Messages (1/1)'));
      expect(screen.getByRole('button', { name: 'Apply' })).toBeEnabled();
      expect(checkbox('Messages (0/1)')).toBeEnabled();
      expect(screen.getByRole('button', { name: 'Start over' })).toBeEnabled();
      // The previous results stay until the new ones are in
      expect(screen.getByText('Failed')).toBeInTheDocument();
      await resolveSimulation(rendered, []);
      await waitFor(() => expect(screen.queryByText('Failed')).not.toBeInTheDocument());
      expect(screen.getByRole('button', { name: 'Apply' })).toBeEnabled();
    });

    it('does not make Apply wait for the first ones', async () => {
      const rendered = await openPreview();
      expect(screen.getByRole('button', { name: 'Apply' })).toBeEnabled();
      expect(checkbox('Messages (1/1)')).toBeEnabled();
      await resolveSimulation(rendered);
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

  describe('sections', () => {
    const withConnector = { ...preview, types: [...preview.types, ...previewWithConnector.types] };

    it('start collapsed when nothing is asked', async () => {
      await openPreview(session(), preview, false);
      expect(checkbox('Platform settings (4/4)')).toHaveAttribute('data-state', 'checked');
      expect(screen.getByRole('button', { name: /^Expand Platform settings/ })).toHaveAttribute('aria-expanded', 'false');
      expect(screen.queryByText('Banner')).not.toBeInTheDocument();
    });

    it('keep open the type whose secrets are asked, and its group, and only them', async () => {
      await openPreview(session(), withConnector, false);
      expect(screen.getByRole('button', { name: 'Enter the configuration of MITRE' })).toBeInTheDocument();
      expect(screen.queryByText('Import theme')).not.toBeInTheDocument();
    });

    it('keep open the type the license locks', async () => {
      await openPreview(session(), previewWithWhitemark, false);
      expect(lockedWhitemark().getByText('EE')).toBeInTheDocument();
      expect(screen.queryByText('Banner')).not.toBeInTheDocument();
    });

    it('stay open once the secrets are entered', async () => {
      const rendered = await openPreview(session(), withConnector, false);
      await rendered.user.click(screen.getByRole('button', { name: 'Enter the configuration of MITRE' }));
      await rendered.user.type(screen.getByLabelText(/MITRE_API_KEY/), 'secret-key');
      await rendered.user.click(screen.getByRole('button', { name: 'Save' }));
      expect(await screen.findByRole('button', { name: 'Configuration' })).toBeInTheDocument();
      expect(checkbox('MITRE')).toBeInTheDocument();
    });

    it('open the type of a connector that needs a service account once the expected results say so', async () => {
      const connectorPreview = { ...preview, types: [...preview.types, previewType('connectors', 'Connectors', [previewItem('mitre', 'MITRE', { translatable: false, exists: false })])] };
      const rendered = await openPreview(session(), connectorPreview, false);
      expect(screen.queryByText('MITRE')).not.toBeInTheDocument();
      await resolveSimulation(rendered, [{ type: 'connectors', key: 'mitre', status: 'FAILED', reason: 'You have not defined a default group for ingestion users', code: 'no_ingestion_group' }]);
      expect(await screen.findByRole('button', { name: 'Choose a service account' })).toBeInTheDocument();
      expect(screen.queryByText('Banner')).not.toBeInTheDocument();
    });
  });

  describe('credentials', () => {
    const enterCredentials = async (rendered: Rendered) => {
      await rendered.user.click(screen.getByRole('button', { name: 'Enter the configuration of MITRE' }));
      await rendered.user.type(screen.getByLabelText(/MITRE_API_KEY/), 'secret-key');
      await rendered.user.click(screen.getByRole('button', { name: 'Save' }));
    };
    const credentials = [{ type: 'connectors', key: 'mitre', values: [{ key: 'MITRE_API_KEY', secret: 'secret-key' }] }];

    it('locks an item whose required secrets are not entered, as the license locks a type: it is not imported', async () => {
      await openPreview(session(), previewWithConnector);
      expect(screen.getByText('Configuration required')).toBeInTheDocument();
      expect(screen.queryByRole('checkbox', { name: 'MITRE' })).toBeDisabled();
    });

    it('selects the item its secrets unlock, and sends them with the expected results and with Apply, never with the save', async () => {
      const rendered = await openPreview(session(), previewWithConnector);
      await enterCredentials(rendered);
      await waitFor(() => expect(checkbox('MITRE')).toHaveAttribute('data-state', 'checked'));
      await waitFor(() => expect(dryRuns(rendered).at(-1)!.request.variables.credentials).toEqual(credentials));
      await resolveSimulation(rendered);
      await waitFor(() => expect(screen.getByRole('button', { name: 'Apply' })).toBeEnabled());
      await rendered.user.click(screen.getByRole('button', { name: 'Apply' }));
      const saves = rendered.relayEnv.mock.getAllOperations().filter((candidate) => candidate.request.node.operation.name === 'ConfigPresetImportPreviewSaveMutation');
      saves.forEach((save) => expect(JSON.stringify(save.request.variables)).not.toContain('secret-key'));
      if (saves.length > 0) {
        await resolve(rendered, 'ConfigPresetImportPreviewSaveMutation', {});
      }
      await waitFor(() => expect(realApplies(rendered)).toHaveLength(1));
      expect(realApplies(rendered)[0].request.variables.credentials).toEqual(credentials);
    });

    it('offers to choose an existing service account for a connector that cannot get a new one', async () => {
      const connectorPreview = { ...previewWithConnector, types: [previewType('connectors', 'Connectors', [previewItem('mitre', 'MITRE', { translatable: false, exists: false })])] };
      const rendered = await openPreview(session(), connectorPreview);
      expect(screen.queryByRole('button', { name: 'Choose a service account' })).not.toBeInTheDocument();
      await resolveSimulation(rendered, [{ type: 'connectors', key: 'mitre', status: 'FAILED', reason: 'You have not defined a default group for ingestion users', code: 'no_ingestion_group' }]);
      await rendered.user.click(await screen.findByRole('button', { name: 'Choose a service account' }));
      expect(screen.getByText('No default group is defined for the service accounts: choose the user this item writes with.')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled();
    });

    it('lets the secrets be changed once entered', async () => {
      const rendered = await openPreview(session(), previewWithConnector);
      await enterCredentials(rendered);
      await rendered.user.click(await screen.findByRole('button', { name: 'Configuration' }));
      expect(screen.getByLabelText(/MITRE_API_KEY/)).toHaveValue('secret-key');
    });

    it('asks for a required field the bundle leaves empty with an input of its type, not masked', async () => {
      const withScore = [
        { key: 'MITRE_API_KEY', description: 'The key of the MITRE API', required: true, stored: false, secret: true, type: 'string' },
        { key: 'MITRE_SCORE', description: 'Minimum score', required: true, stored: false, secret: false, type: 'integer' },
      ];
      const scorePreview = { ...previewWithConnector, types: [previewType('connectors', 'Connectors', [previewItem('mitre', 'MITRE', { translatable: false, exists: false, credentials: withScore })])] };
      const rendered = await openPreview(session(), scorePreview);
      await rendered.user.click(screen.getByRole('button', { name: 'Enter the configuration of MITRE' }));
      expect(screen.getByLabelText(/MITRE_API_KEY/)).toHaveAttribute('type', 'password');
      expect(screen.getByLabelText(/MITRE_SCORE/)).toHaveAttribute('type', 'number');
      await rendered.user.type(screen.getByLabelText(/MITRE_API_KEY/), 'secret-key');
      expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled();
      await rendered.user.type(screen.getByLabelText(/MITRE_SCORE/), '90');
      await rendered.user.click(screen.getByRole('button', { name: 'Save' }));
      await waitFor(() => expect(dryRuns(rendered).at(-1)!.request.variables.credentials)
        .toEqual([{ type: 'connectors', key: 'mitre', values: [{ key: 'MITRE_API_KEY', secret: 'secret-key' }, { key: 'MITRE_SCORE', secret: '90' }] }]));
    });

    it('asks again for a secret the platform stores when the connector is added as a copy, and keeps the choice on the row', async () => {
      const storedSecret = [{ key: 'MITRE_API_KEY', description: 'The key of the MITRE API', required: true, stored: true, secret: true, type: 'string' }];
      const existingConnector = {
        ...previewWithConnector,
        types: [previewType('connectors', 'Connectors', [previewItem('mitre', 'MITRE', { translatable: false, conflict: true, credentials: storedSecret })], ['OVERWRITE', 'COPY'])],
      };
      const rendered = await openPreview(session(), existingConnector);
      expect(checkbox('MITRE')).toHaveAttribute('data-state', 'checked');
      expect(screen.queryByText('Configuration required')).not.toBeInTheDocument();
      const modeSelect = () => screen.getByRole('combobox', { name: 'MITRE: When it already exists' });
      await rendered.user.click(modeSelect());
      await rendered.user.click(await screen.findByRole('option', { name: 'Add as a copy' }));
      expect(await screen.findByText('Configuration required')).toBeInTheDocument();
      expect(modeSelect()).toHaveTextContent('Add as a copy');
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
      expect(screen.getAllByRole('combobox', { name: /When it already exists/ })).toHaveLength(1);
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

    it('says that the platform keeps its default fintel design when that design is added as a copy, with its own words', async () => {
      const withFintelDesigns = {
        ...preview,
        types: [...preview.types, previewType('fintelDesigns', 'Fintel designs', [
          previewItem('finteldesign--1', 'Filigran report', { translatable: false, exists: true, conflict: true, isDefault: true }),
        ], ['OVERWRITE', 'COPY'])],
      };
      const rendered = await renderPreview(session(), [], withFintelDesigns);
      const hint = 'The platform keeps its current default fintel design.';
      expect(screen.queryByText(hint)).not.toBeInTheDocument();
      await rendered.user.click(screen.getByRole('combobox', { name: 'Filigran report: When it already exists' }));
      await rendered.user.click(await screen.findByRole('option', { name: 'Add as a copy' }));
      expect(screen.getByText(hint)).toBeInTheDocument();
      expect(screen.queryByText('The platform keeps its current default theme.')).not.toBeInTheDocument();
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
        credentials: [],
        service_accounts: [],
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
      await waitFor(() => expect(dryRuns(rendered)).toHaveLength(1));
      expect(dryRuns(rendered)[0].request.variables).toMatchObject({ selections: [{ type: 'branding', item_modes: [{ key: 'theme--2', mode: 'COPY' }] }] });
      await resolveSimulation(rendered, [{ type: 'branding', key: 'theme--2', status: 'CREATED', reason: 'Added as "Existing theme (1)"' }]);
      const row = screen.getByTestId('config-preset-import-item-branding-theme--2');
      expect(await within(row).findByText('Added as "Existing theme (1)"')).toBeInTheDocument();
      // The reason says how it is created: no tag for a creation
      expect(within(row).queryByText('Created')).not.toBeInTheDocument();
    });

    it('stays usable while the expected results are computed', async () => {
      await openPreview();
      expect(modeSelect()).toBeEnabled();
    });

    describe('for all the items of a type', () => {
      const familySelect = () => screen.getByRole('combobox', { name: 'Branding: Apply to all' });
      const anotherSelect = () => screen.getByRole('combobox', { name: 'Another theme: When it already exists' });
      const renderTwo = (currentSession = session(), results: unknown[] = []) => renderPreview(currentSession, results, previewWithTwoConflicts);

      it('is offered from two items that conflict', async () => {
        await renderTwo();
        expect(familySelect()).toHaveTextContent('Overwrite');
      });

      it('does not count an item that is not imported: with none left in conflict, it is not offered', async () => {
        const { user } = await renderTwo();
        await user.click(within(screen.getByTestId('config-preset-import-item-branding-theme--3')).getByRole('checkbox'));
        expect(familySelect()).toBeInTheDocument();
        await user.click(within(screen.getByTestId('config-preset-import-item-branding-theme--2')).getByRole('checkbox'));
        expect(screen.queryByRole('combobox', { name: 'Branding: Apply to all' })).not.toBeInTheDocument();
      });

      it('is offered with a single item in conflict too, as for the types with several', async () => {
        await renderPreview();
        expect(familySelect()).toHaveTextContent('Overwrite');
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

// A bundle with a type of thousands of items: its first page comes with the preview, the rest from the items query
describe('ConfigPresetImportWizard: a type listed page by page', () => {
  const itemEdge = (key: string, label: string, overrides: Record<string, unknown> = {}) => ({ node: previewItem(key, label, { translatable: false, ...overrides }) });
  const bigPreview = {
    ...preview,
    types: [
      {
        ...previewType('labels', 'Labels', Array.from({ length: 10 }, (_, i) => previewItem(`label--${i}`, `Label ${i}`, { translatable: false, conflict: i < 3 }))),
        itemsPageInfo: { hasNextPage: true, globalCount: 5000 },
        conflictsCount: 120,
      },
    ],
  };
  const itemsQueries = (rendered: Rendered) => rendered.relayEnv.mock.getAllOperations().filter((candidate) => candidate.request.node.operation.name === 'ConfigPresetImportItemsQuery');
  // The variables of the items queries sent, the latest last: a query that was answered is no longer pending
  const itemsVariables: unknown[] = [];
  const resolveItems = async (rendered: Rendered, edges: unknown[]) => {
    await act(async () => {
      const target = itemsQueries(rendered).at(-1)!;
      itemsVariables.push(target.request.variables);
      rendered.relayEnv.mock.resolve(target, MockPayloadGenerator.generate(target, {
        ConfigPresetImportItemConnection: () => ({ edges, pageInfo: { hasNextPage: false, endCursor: '25', globalCount: edges.length } }),
      }));
    });
  };
  const openManage = async (rendered: Rendered, edges: unknown[]) => {
    await rendered.user.click(screen.getByRole('button', { name: 'Manage' }));
    await resolveItems(rendered, edges);
  };

  beforeEach(() => {
    onFinish.mockReset();
    enterpriseEdition.enabled = false;
    itemsVariables.length = 0;
  });

  it('shows a Manage button for the type, and counts all its items', async () => {
    await renderPreview(session(), [], bigPreview);
    expect(screen.getByRole('button', { name: 'Manage' })).toBeInTheDocument();
    expect(screen.getByText(/5000 items/)).toBeInTheDocument();
    expect(screen.getByRole('checkbox', { name: 'Labels (5000/5000)' })).toBeInTheDocument();
    // Its items are in the sub-view, not in the list
    expect(screen.queryByTestId('config-preset-import-item-labels-label--0')).not.toBeInTheDocument();
  });

  it('opens the sub-view that reads the items of the type from the API, and goes back', async () => {
    const rendered = await renderPreview(session(), [], bigPreview);
    await openManage(rendered, [itemEdge('label--20', 'Label 20'), itemEdge('label--21', 'Label 21', { conflict: true })]);
    expect(itemsVariables.at(-1)).toMatchObject({ file_id: 'config_preset/import/id/bundle.zip', type: 'labels', count: 25, search: '' });
    expect(screen.getByRole('checkbox', { name: 'Label 20' })).toBeInTheDocument();
    expect(screen.getByText('5000 / 5000 selected')).toBeInTheDocument();
    // The way back is in the sticky footer, as Apply is in the list: it stays at the bottom while the pages load, and is never the last row
    const footer = within(screen.getByTestId('config-preset-sticky-footer'));
    expect(footer.getByRole('button', { name: 'Back to bundle' })).toBeInTheDocument();
    expect(screen.getByTestId('config-preset-sticky-footer')).toHaveStyle({ position: 'sticky', bottom: '0px' });
    await rendered.user.click(footer.getByRole('button', { name: 'Back to bundle' }));
    expect(within(screen.getByTestId('config-preset-sticky-footer')).getByRole('button', { name: 'Apply' })).toBeInTheDocument();
  });

  it('searches and keeps the items that already exist, by asking the API again', async () => {
    const rendered = await renderPreview(session(), [], bigPreview);
    await openManage(rendered, [itemEdge('label--20', 'Label 20')]);
    await rendered.user.type(screen.getByRole('searchbox', { name: 'Search' }), 'acme');
    await waitFor(() => expect(itemsQueries(rendered).at(-1)!.request.variables).toMatchObject({ search: 'acme' }), { timeout: 2000 });
    await resolveItems(rendered, []);
    expect(await screen.findByText('No results')).toBeInTheDocument();
    await rendered.user.click(screen.getByRole('button', { name: 'Already exists 120' }));
    await waitFor(() => expect(itemsQueries(rendered).at(-1)!.request.variables).toMatchObject({ search: 'acme', conflictsOnly: true }));
  });

  it('keeps the items that are selected or not by their ids, as the export does', async () => {
    const rendered = await renderPreview(session(), [], bigPreview);
    await openManage(rendered, [itemEdge('label--20', 'Label 20')]);
    await rendered.user.click(screen.getByRole('checkbox', { name: 'Label 20' }));
    await rendered.user.click(screen.getByRole('button', { name: 'Excluded 1' }));
    await waitFor(() => expect(itemsQueries(rendered).at(-1)!.request.variables).toMatchObject({ ids: ['label--20'] }));
  });

  it('sends the selection of the type as every item but the excluded ones, never a list of thousands of keys', async () => {
    const rendered = await renderPreview(session(), [], bigPreview);
    await openManage(rendered, [itemEdge('label--20', 'Label 20')]);
    await rendered.user.click(screen.getByRole('checkbox', { name: 'Label 20' }));
    await waitFor(() => expect(rendered.relayEnv.mock.getAllOperations().filter((candidate) => candidate.request.node.operation.name === 'ConfigPresetImportPreviewSaveMutation')).toHaveLength(1), { timeout: 2000 });
    const save = rendered.relayEnv.mock.getAllOperations().find((candidate) => candidate.request.node.operation.name === 'ConfigPresetImportPreviewSaveMutation')!;
    expect(save.request.variables).toMatchObject({ selections: [{ type: 'labels', items: null, excluded_items: ['label--20'] }] });
  });
});
