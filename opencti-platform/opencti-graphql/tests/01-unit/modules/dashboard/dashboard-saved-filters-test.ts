import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../src/modules/savedFilter/savedFilter-domain', () => ({ findSavedFilter: vi.fn() }));

import { findSavedFilter } from '../../../../src/modules/savedFilter/savedFilter-domain';
import { readManifestWithValidWidgets, resolveSavedFiltersInDataSelection } from '../../../../src/modules/dashboard/dashboard-utils';
import { toB64 } from '../../../../src/utils/base64';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;
const inline = { mode: 'and', filters: [{ key: ['objectLabel'], values: ['label-id'] }], filterGroups: [] };
const widgetWith = (selection: Record<string, unknown>) => ({ id: 'widget1', dataSelection: [selection] }) as unknown as Parameters<typeof resolveSavedFiltersInDataSelection>[2]
  & { dataSelection: Record<string, unknown>[] };

beforeEach(() => {
  vi.resetAllMocks();
});

describe('Saved filters of a widget data selection, on export', () => {
  it('replaces a saved filter by its filters, and drops the reference', async () => {
    vi.mocked(findSavedFilter).mockResolvedValue({ filters: JSON.stringify(inline) } as never);
    const widget = widgetWith({ filters_id: 'saved-id' });
    await resolveSavedFiltersInDataSelection(context, user, widget);
    expect(widget.dataSelection[0]).toEqual({ filters: inline, filters_id: undefined });
  });

  it('fails the export on a saved filter that does not exist, as the file exports do', async () => {
    vi.mocked(findSavedFilter).mockResolvedValue(undefined as never);
    await expect(resolveSavedFiltersInDataSelection(context, user, widgetWith({ filters_id: 'gone-id' }))).rejects.toThrow('Saved filter not found');
  });

  it('keeps the reference of a saved filter that does not exist when asked to, for every saved filter key of the selection', async () => {
    vi.mocked(findSavedFilter).mockResolvedValue(undefined as never);
    const selection = { filters_id: 'gone-1', dynamicFrom_id: 'gone-2', dynamicTo_id: 'gone-3' };
    const widget = widgetWith({ ...selection });
    await resolveSavedFiltersInDataSelection(context, user, widget, true);
    expect(widget.dataSelection[0]).toEqual(selection);
  });

  it('still resolves the saved filters that exist when it keeps the missing ones', async () => {
    vi.mocked(findSavedFilter).mockImplementation(async (_context, _user, id) => (id === 'saved-id' ? { filters: JSON.stringify(inline) } : undefined) as never);
    const widget = widgetWith({ filters_id: 'saved-id', dynamicFrom_id: 'gone-id' });
    await resolveSavedFiltersInDataSelection(context, user, widget, true);
    expect(widget.dataSelection[0]).toEqual({ filters: inline, filters_id: undefined, dynamicFrom_id: 'gone-id' });
  });
});

describe('Manifest of a file whose widgets are read without being checked', () => {
  const encode = (manifest: unknown) => toB64(manifest) as string;
  const widget = { id: 'widget1', type: 'number', dataSelection: [] };

  it('decodes a manifest with no widget, or with widgets that have a data selection of objects', () => {
    expect(readManifestWithValidWidgets(encode({ config: {} }))).toEqual({ config: {} });
    const widgets = { widget1: widget, widget2: { ...widget, dataSelection: [{ filters: {} }] } };
    expect(readManifestWithValidWidgets(encode({ widgets }))).toMatchObject({ widgets });
  });

  it('leaves what else the manifest holds, the variables, to the caller', () => {
    expect(readManifestWithValidWidgets(encode({ widgets: {}, variables: 'not a list' }))).toMatchObject({ variables: 'not a list' });
  });

  it.each([
    ['a value that is not base64 json', 'not a manifest'],
    ['a manifest that is not an object', encode([1])],
    ['widgets that are a list', encode({ widgets: [widget] })],
    ['a widget that is not an object', encode({ widgets: { widget1: 'text' } })],
    ['a widget without data selection', encode({ widgets: { widget1: { id: 'widget1' } } })],
    ['a data selection that holds a null', encode({ widgets: { widget1: { id: 'widget1', dataSelection: [null] } } })],
    ['a data selection that holds a value that is not an object', encode({ widgets: { widget1: { id: 'widget1', dataSelection: ['text'] } } })],
  ])('refuses %s', (_label, encoded) => {
    expect(readManifestWithValidWidgets(encoded)).toBeUndefined();
  });
});
