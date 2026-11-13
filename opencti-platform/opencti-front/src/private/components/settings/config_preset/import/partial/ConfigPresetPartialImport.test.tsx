import React, { useSyncExternalStore } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, screen, waitFor } from '@testing-library/react';
import { MockPayloadGenerator } from 'relay-test-utils';
import testRender, { createMockUserContext } from '../../../../../../utils/tests/test-render';
import ConfigPresetPartialImport from './ConfigPresetPartialImport';

// The Enterprise Edition of the platform, which can change while the dialog is open (a license activated from the locked row)
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
vi.mock('../../../../../../utils/hooks/useEnterpriseEdition', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../../utils/hooks/useEnterpriseEdition')>()),
  default: () => useSyncExternalStore(enterpriseEdition.subscribe, () => enterpriseEdition.enabled),
}));

type Rendered = ReturnType<typeof testRender>;

const operation = ({ relayEnv }: Rendered, name: string) => relayEnv.mock.getAllOperations().find((candidate) => candidate.request.node.operation.name === name)!;
const resolve = async (rendered: Rendered, name: string, resolvers: Record<string, () => unknown>) => {
  await waitFor(() => expect(operation(rendered, name)).toBeDefined());
  await act(async () => {
    const target = operation(rendered, name);
    rendered.relayEnv.mock.resolve(target, MockPayloadGenerator.generate(target, resolvers));
  });
};

const previewOf = (items: unknown[]) => ({
  bundle_name: 'Prod bundle',
  default_mode: 'COPY',
  type: { key: 'branding', label: 'Branding', description: 'Themes, colors, logos', lockedByEnterpriseEdition: false, modes: ['OVERWRITE', 'COPY'], items },
});
const noAccount = { serviceAccountRequired: false, credentials: [] };
const themes = [
  { key: 'theme--a', label: 'Night', translatable: false, exists: false, conflict: false, ...noAccount },
  { key: 'theme--b', label: 'Day', translatable: false, exists: true, conflict: true, ...noAccount },
];

// The partial import is for BYPASS users: the locked row of a type opens the license dialog
const userContext = createMockUserContext({
  me: { name: 'admin', capabilities: [{ name: 'BYPASS' }], userSubscriptions: { edges: [] } },
});
const renderWithPreview = async (preview: unknown, onImported = vi.fn()) => {
  const onClose = vi.fn();
  const rendered = testRender(<ConfigPresetPartialImport type="branding" itemsLabel="themes" onImported={onImported} onClose={onClose} />, { userContext });
  const file = new File(['zip'], 'bundle.zip', { type: 'application/zip' });
  await rendered.user.upload(screen.getByTestId('config-preset-partial-import-file'), file);
  expect(operation(rendered, 'ConfigPresetPartialImportPreviewMutation').request.variables).toEqual({ file, type: 'branding' });
  await resolve(rendered, 'ConfigPresetPartialImportPreviewMutation', { ConfigPresetPartialImportPreview: () => preview });
  return { ...rendered, file, onClose, onImported };
};

describe('ConfigPresetPartialImport', () => {
  beforeEach(() => {
    enterpriseEdition.enabled = false;
  });

  it('lists the items of the type in the bundle, every one selected, with the mode of the item in conflict', async () => {
    await renderWithPreview(previewOf(themes));
    expect(screen.getByText('Bundle: Prod bundle')).toBeInTheDocument();
    expect(screen.getByRole('checkbox', { name: 'Night' })).toHaveAttribute('data-state', 'checked');
    expect(screen.getByRole('checkbox', { name: 'Day' })).toHaveAttribute('data-state', 'checked');
    expect(screen.getByRole('combobox', { name: 'Day: When it already exists' })).toHaveTextContent('Add as a copy');
    expect(screen.queryByRole('combobox', { name: 'Night: When it already exists' })).not.toBeInTheDocument();
  });

  it('says so when the bundle holds no item of the type, and cannot import', async () => {
    await renderWithPreview({ ...previewOf([]), type: null });
    expect(screen.getByText('This configuration bundle holds no themes.')).toBeInTheDocument();
    expect(screen.getByTestId('config-preset-partial-import-submit')).toBeDisabled();
  });

  it('shows a type locked by the Enterprise Edition as locked, not as an empty bundle, and cannot import', async () => {
    await renderWithPreview({
      bundle_name: null,
      default_mode: 'OVERWRITE',
      type: { key: 'whitemark', label: 'Remove Filigran logos', description: '', lockedByEnterpriseEdition: true, modes: ['OVERWRITE'], items: [] },
    });
    expect(screen.getByRole('checkbox', { name: 'Remove Filigran logos', hidden: true })).toHaveAttribute('data-state', 'unchecked');
    expect(screen.getByText('EE')).toBeInTheDocument();
    expect(screen.queryByText(/This configuration bundle holds no/)).not.toBeInTheDocument();
    expect(screen.getByTestId('config-preset-partial-import-submit')).toBeDisabled();
  });

  it('reads the same file again once a license is activated, and the type comes with its items, all selected', async () => {
    const rendered = await renderWithPreview({
      bundle_name: null,
      default_mode: 'OVERWRITE',
      type: { key: 'whitemark', label: 'Remove Filigran logos', description: '', lockedByEnterpriseEdition: true, modes: ['OVERWRITE'], items: [] },
    });
    act(() => {
      enterpriseEdition.activate();
    });
    // The same file, asked again
    await waitFor(() => expect(rendered.relayEnv.mock.getAllOperations().filter((candidate) => candidate.request.node.operation.name === 'ConfigPresetPartialImportPreviewMutation')).toHaveLength(1));
    const reread = operation(rendered, 'ConfigPresetPartialImportPreviewMutation');
    expect(reread.request.variables).toEqual({ file: rendered.file, type: 'branding' });
    await act(async () => {
      rendered.relayEnv.mock.resolve(reread, MockPayloadGenerator.generate(reread, {
        ConfigPresetPartialImportPreview: () => ({
          bundle_name: null,
          default_mode: 'OVERWRITE',
          type: {
            key: 'whitemark',
            label: 'Remove Filigran logos',
            description: '',
            lockedByEnterpriseEdition: false,
            modes: ['OVERWRITE'],
            items: [{ key: 'whitemark', label: 'Remove Filigran logos', translatable: true, exists: true, conflict: false, ...noAccount }],
          },
        }),
      }));
    });
    expect(screen.getByRole('checkbox', { name: 'Remove Filigran logos' })).toHaveAttribute('data-state', 'checked');
    expect(screen.getByTestId('config-preset-partial-import-submit')).toBeEnabled();
  });

  it('counts an item the platform already had as it is as up to date, not as skipped, as the wizard does', async () => {
    const rendered = await renderWithPreview(previewOf(themes));
    await rendered.user.click(screen.getByTestId('config-preset-partial-import-submit'));
    await resolve(rendered, 'ConfigPresetPartialImportMutation', {
      ConfigPresetPartialImportOutput: () => ({
        results: [
          { type: 'branding', key: 'theme--a', status: 'CREATED', reason: null, code: null, label: 'Night', translatable: false },
          { type: 'branding', key: 'theme--b', status: 'SKIPPED', reason: null, code: 'unchanged', label: 'Day', translatable: false },
        ],
        counts: { created: 1, overwritten: 0, skipped: 1, failed: 0 },
      }),
    });
    expect(screen.getByText('1 created, 0 overwritten, 1 up to date, 0 skipped, 0 failed')).toBeInTheDocument();
    expect(screen.queryByText('Skipped')).not.toBeInTheDocument();
  });

  it('offers no Cancel, the close button of the dialog is enough, and scrolls the list of items only', async () => {
    await renderWithPreview(previewOf(themes));
    expect(screen.queryByRole('button', { name: 'Cancel' })).not.toBeInTheDocument();
    expect(screen.getByTestId('config-preset-partial-import-items')).toHaveStyle({ overflowY: 'auto' });
    expect(screen.getByTestId('config-preset-partial-import-submit')).toBeEnabled();
  });

  it('offers the same mode for all the selected items in conflict from two of them, and applies it to each', async () => {
    const conflicts = [
      ...themes,
      { key: 'theme--c', label: 'Dusk', translatable: false, exists: true, conflict: true, ...noAccount },
    ];
    const rendered = await renderWithPreview(previewOf(conflicts));
    const applyToAll = () => screen.getByRole('combobox', { name: 'themes: Apply to all' });
    expect(applyToAll()).toHaveTextContent('Add as a copy');
    await rendered.user.click(applyToAll());
    await rendered.user.click(await screen.findByRole('option', { name: 'Overwrite' }));
    expect(screen.getByRole('combobox', { name: 'Day: When it already exists' })).toHaveTextContent('Overwrite');
    expect(screen.getByRole('combobox', { name: 'Dusk: When it already exists' })).toHaveTextContent('Overwrite');
    // One of them back to a copy: they differ
    await rendered.user.click(screen.getByRole('combobox', { name: 'Dusk: When it already exists' }));
    await rendered.user.click(await screen.findByRole('option', { name: 'Add as a copy' }));
    expect(applyToAll()).toHaveTextContent('Mixed');
    // The modes sent are the ones shown
    await rendered.user.click(screen.getByTestId('config-preset-partial-import-submit'));
    expect(operation(rendered, 'ConfigPresetPartialImportMutation').request.variables.item_modes).toEqual([
      { key: 'theme--b', mode: 'OVERWRITE' },
      { key: 'theme--c', mode: 'COPY' },
    ]);
  });

  it('does not offer the same mode for all with a single item in conflict, its own choice is enough', async () => {
    await renderWithPreview(previewOf(themes));
    expect(screen.queryByTestId('config-preset-partial-import-apply-to-all')).not.toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: 'Day: When it already exists' })).toBeInTheDocument();
  });

  it('imports the selected items with the mode of those in conflict, then shows the results', async () => {
    const rendered = await renderWithPreview(previewOf(themes));
    await rendered.user.click(screen.getByRole('checkbox', { name: 'Night' }));
    await rendered.user.click(screen.getByTestId('config-preset-partial-import-submit'));
    expect(operation(rendered, 'ConfigPresetPartialImportMutation').request.variables).toEqual({
      file: rendered.file,
      type: 'branding',
      items: ['theme--b'],
      item_modes: [{ key: 'theme--b', mode: 'COPY' }],
      credentials: [],
      service_accounts: [],
    });
    await resolve(rendered, 'ConfigPresetPartialImportMutation', {
      ConfigPresetPartialImportOutput: () => ({
        results: [{ type: 'branding', key: 'theme--b', status: 'CREATED', reason: 'Added as "Day (1)"', label: 'Day', translatable: false }],
        counts: { created: 1, overwritten: 0, skipped: 0, failed: 0 },
      }),
    });
    expect(screen.getByText('1 created, 0 overwritten, 0 up to date, 0 skipped, 0 failed')).toBeInTheDocument();
    expect(screen.getByText('Added as "Day (1)"')).toBeInTheDocument();
    expect(rendered.onImported).toHaveBeenCalledTimes(1);
    await rendered.user.click(screen.getByRole('button', { name: 'Close' }));
    expect(rendered.onClose).toHaveBeenCalledTimes(1);
  });

  describe('items that need credentials or a service account (feeds)', () => {
    const basic = { description: '', secret: true, type: 'string' };
    const feedsPreviewOf = (items: unknown[]) => ({
      bundle_name: null,
      default_mode: 'COPY',
      type: { key: 'taxiiFeeds', label: 'TAXII feeds', description: '', lockedByEnterpriseEdition: false, modes: ['OVERWRITE', 'COPY'], items },
    });
    const renderFeeds = async (items: unknown[]) => {
      const rendered = testRender(<ConfigPresetPartialImport type="taxiiFeeds" itemsLabel="TAXII feeds" onClose={vi.fn()} />, { userContext });
      const file = new File(['zip'], 'bundle.zip', { type: 'application/zip' });
      await rendered.user.upload(screen.getByTestId('config-preset-partial-import-file'), file);
      await resolve(rendered, 'ConfigPresetPartialImportPreviewMutation', { ConfigPresetPartialImportPreview: () => feedsPreviewOf(items) });
      return rendered;
    };

    it('keeps an item unchecked until its required credentials are entered, then imports it with them', async () => {
      const rendered = await renderFeeds([
        {
          key: 'Partner',
          label: 'Partner',
          translatable: false,
          exists: false,
          conflict: false,
          serviceAccountRequired: false,
          credentials: [{ key: 'username', required: true, stored: false, ...basic }, { key: 'password', required: true, stored: false, ...basic }],
        },
      ]);
      expect(screen.getByRole('checkbox', { name: 'Partner' })).toHaveAttribute('data-state', 'unchecked');
      expect(screen.getByTestId('config-preset-partial-import-submit')).toBeDisabled();
      await rendered.user.click(screen.getByRole('button', { name: 'Enter the configuration of Partner' }));
      await rendered.user.type(screen.getByLabelText(/username/), 'reader');
      await rendered.user.type(screen.getByLabelText(/password/), 's3cret');
      await rendered.user.click(screen.getByRole('button', { name: 'Save' }));
      expect(screen.getByRole('checkbox', { name: 'Partner' })).toHaveAttribute('data-state', 'checked');
      await rendered.user.click(screen.getByTestId('config-preset-partial-import-submit'));
      expect(operation(rendered, 'ConfigPresetPartialImportMutation').request.variables).toMatchObject({
        items: ['Partner'],
        credentials: [{ type: 'taxiiFeeds', key: 'Partner', values: [{ key: 'username', secret: 'reader' }, { key: 'password', secret: 's3cret' }] }],
        service_accounts: [],
      });
    });

    it('asks again for a stored secret on a copy, never on an overwrite', async () => {
      const rendered = await renderFeeds([
        {
          key: 'Partner',
          label: 'Partner',
          translatable: false,
          exists: true,
          conflict: true,
          serviceAccountRequired: false,
          credentials: [{ key: 'token', required: true, stored: true, ...basic }],
        },
      ]);
      // A copy by default: the secret of the existing feed is not kept
      expect(screen.getByRole('checkbox', { name: 'Partner' })).toHaveAttribute('data-state', 'unchecked');
      await rendered.user.click(screen.getByRole('combobox', { name: 'Partner: When it already exists' }));
      await rendered.user.click(await screen.findByRole('option', { name: 'Overwrite' }));
      expect(screen.getByRole('checkbox', { name: 'Partner' })).toHaveAttribute('data-state', 'checked');
      expect(screen.getByTestId('config-preset-partial-import-submit')).toBeEnabled();
    });

    it('asks for a service account for a created item when the platform has no default group, not for an overwritten one', async () => {
      const rendered = await renderFeeds([
        { key: 'News', label: 'News', translatable: false, exists: false, conflict: false, serviceAccountRequired: true, credentials: [] },
        { key: 'Partner', label: 'Partner', translatable: false, exists: true, conflict: true, serviceAccountRequired: true, credentials: [] },
      ]);
      expect(screen.getAllByRole('button', { name: 'Choose a service account' })).toHaveLength(2);
      expect(screen.getByTestId('config-preset-partial-import-submit')).toBeDisabled();
      // The existing one overwritten keeps its user; the new one still needs a choice
      await rendered.user.click(screen.getByRole('combobox', { name: 'Partner: When it already exists' }));
      await rendered.user.click(await screen.findByRole('option', { name: 'Overwrite' }));
      expect(screen.getAllByRole('button', { name: 'Choose a service account' })).toHaveLength(1);
      expect(screen.getByTestId('config-preset-partial-import-submit')).toBeDisabled();
      // Left out, nothing needs a choice any more
      await rendered.user.click(screen.getByRole('checkbox', { name: 'News' }));
      expect(screen.queryByRole('button', { name: 'Choose a service account' })).not.toBeInTheDocument();
      expect(screen.getByTestId('config-preset-partial-import-submit')).toBeEnabled();
    });
  });
});
