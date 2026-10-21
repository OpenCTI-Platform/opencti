import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import MappingSelectionPopover from './MappingSelectionPopover';

const fetchQuery = vi.hoisted(() => vi.fn());
vi.mock('../../../../relay/environment', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../relay/environment')>(),
  fetchQuery,
}));

const existingFile = { id: 'file-id', standard_id: 'file--1', entity_type: 'StixFile', representative: { main: 'some-example.zip' }, containersNumber: { total: 2 } };
const selection = (text: string) => ({ text, rect: new DOMRect(10, 10, 100, 20), passage: text });

const renderPopover = (text: string, existing: unknown[] = []) => {
  fetchQuery.mockReturnValue({ toPromise: () => Promise.resolve({ stixCoreObjects: { edges: existing.map((node) => ({ node })) } }) });
  const onMapExisting = vi.fn();
  const onCreate = vi.fn();
  const view = testRender(<MappingSelectionPopover selection={selection(text)} onClose={vi.fn()} onMapExisting={onMapExisting} onCreate={onCreate} />);
  return { ...view, onMapExisting, onCreate };
};

describe('MappingSelectionPopover', () => {
  beforeEach(() => fetchQuery.mockReset());

  it('should search the refanged selection and list existing objects first', async () => {
    const { user, onMapExisting } = renderPopover('some-example.zip', [existingFile]);
    expect(fetchQuery).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ search: 'some-example.zip' }));
    expect(await screen.findByText('Already in the platform')).toBeInTheDocument();
    expect(screen.getByText(/seen in 2/)).toBeInTheDocument();
    await user.keyboard('{Enter}');
    expect(onMapExisting).toHaveBeenCalledWith('some-example.zip', expect.objectContaining({ id: 'file-id' }));
  });

  it('should only offer existing objects whose name or alias matches the value', async () => {
    renderPopover('FRP', [
      { id: 'tool-id', standard_id: 'tool--1', entity_type: 'Tool', representative: { main: 'Fast Reverse Proxy' }, aliases: ['FRP'], containersNumber: { total: 0 } },
      { id: 'campaign-id', standard_id: 'campaign--1', entity_type: 'Campaign', representative: { main: 'admin@338' }, aliases: [], containersNumber: { total: 1 } },
    ]);
    expect(await screen.findByText('Fast Reverse Proxy')).toBeInTheDocument();
    expect(screen.queryByText('admin@338')).not.toBeInTheDocument();
  });

  it('should offer the valid types with the field the value goes to, and a number shortcut', async () => {
    const { user, onCreate } = renderPopover('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    expect(await screen.findByText('hashes.SHA-256')).toBeInTheDocument();
    await user.keyboard('1');
    expect(onCreate).toHaveBeenCalledWith('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'StixFile');
  });

  it('should show the refanged value and grey out the types the value cannot have', async () => {
    renderPopover('update-check[.]net');
    expect(fetchQuery).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ search: 'update-check.net' }));
    // The refang line shows the selection, an arrow and the cleaned value.
    expect(await screen.findByText('→')).toBeInTheDocument();
    expect(screen.getByText('update-check[.]net')).toBeInTheDocument();
    expect(screen.getAllByText('update-check.net').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Not valid for this value').length).toBeGreaterThan(0);
  });
});
