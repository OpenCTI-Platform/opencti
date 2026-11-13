import React from 'react';
import { beforeEach, describe, expect, it, Mock, vi } from 'vitest';
import { act, screen, waitFor } from '@testing-library/react';
import { MockPayloadGenerator } from 'relay-test-utils';
import testRender from '../../../../utils/tests/test-render';
import useConfigPresetPartialImportAccess from '../../settings/config_preset/import/partial/useConfigPresetPartialImportAccess';
import IngestionJsonImport from './IngestionJsonImport';

vi.mock('../../settings/config_preset/import/partial/useConfigPresetPartialImportAccess', () => ({ default: vi.fn() }));

type Rendered = ReturnType<typeof testRender>;

const operation = ({ relayEnv }: Rendered, name: string) => relayEnv.mock.getAllOperations().find((candidate) => candidate.request.node.operation.name === name);
const trigger = () => screen.getByRole('button', { name: 'Import a JSON feed' });
const fileInput = () => document.querySelector('input[type="file"]') as HTMLInputElement;

const renderImport = (canImportFromBundle: boolean, onBundleImported = vi.fn()) => {
  (useConfigPresetPartialImportAccess as Mock).mockReturnValue(canImportFromBundle);
  return { ...testRender(<IngestionJsonImport onBundleImported={onBundleImported} />), onBundleImported };
};

describe('IngestionJsonImport', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('opens the file picker at once without the partial import', async () => {
    const { user } = renderImport(false);
    const openPicker = vi.spyOn(fileInput(), 'click');
    await user.click(trigger());
    expect(openPicker).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('offers the feed file or the JSON feeds of a bundle, and a file picked closes the dialog and imports the file as before', async () => {
    const rendered = renderImport(true);
    await rendered.user.click(trigger());
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    const openPicker = vi.spyOn(fileInput(), 'click');
    await rendered.user.click(screen.getByRole('button', { name: /^Import a feed file/ }));
    expect(openPicker).toHaveBeenCalledTimes(1);
    await rendered.user.upload(fileInput(), new File(['{}'], 'feed.json', { type: 'application/json' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(operation(rendered, 'IngestionJsonImportMutation')).toBeDefined();
  });

  it('imports the JSON feeds of a bundle, then tells the screen', async () => {
    const rendered = renderImport(true);
    await rendered.user.click(trigger());
    await rendered.user.click(screen.getByRole('button', { name: /^Import from bundle platform config/ }));
    const file = new File(['zip'], 'bundle.zip', { type: 'application/zip' });
    await rendered.user.upload(screen.getByTestId('config-preset-partial-import-file'), file);
    await waitFor(() => expect(operation(rendered, 'ConfigPresetPartialImportPreviewMutation')).toBeDefined());
    expect(operation(rendered, 'ConfigPresetPartialImportPreviewMutation')?.request.variables).toEqual({ file, type: 'jsonFeeds' });
    await act(async () => {
      const preview = operation(rendered, 'ConfigPresetPartialImportPreviewMutation')!;
      rendered.relayEnv.mock.resolve(preview, MockPayloadGenerator.generate(preview, {
        ConfigPresetPartialImportPreview: () => ({
          bundle_name: null,
          default_mode: 'COPY',
          type: {
            key: 'jsonFeeds',
            label: 'JSON feeds',
            description: '',
            lockedByEnterpriseEdition: false,
            modes: ['OVERWRITE', 'COPY'],
            items: [{ key: 'Vendor', label: 'Vendor', translatable: false, exists: false, conflict: false, serviceAccountRequired: false, credentials: [] }],
          },
        }),
      }));
    });
    await rendered.user.click(screen.getByTestId('config-preset-partial-import-submit'));
    await waitFor(() => expect(operation(rendered, 'ConfigPresetPartialImportMutation')).toBeDefined());
    await act(async () => {
      const imported = operation(rendered, 'ConfigPresetPartialImportMutation')!;
      rendered.relayEnv.mock.resolve(imported, MockPayloadGenerator.generate(imported, {
        ConfigPresetPartialImportOutput: () => ({
          results: [{ type: 'jsonFeeds', key: 'Vendor', status: 'CREATED', reason: null, code: null, label: 'Vendor', translatable: false }],
          counts: { created: 1, overwritten: 0, skipped: 0, failed: 0 },
        }),
      }));
    });
    expect(rendered.onBundleImported).toHaveBeenCalledTimes(1);
  });
});
