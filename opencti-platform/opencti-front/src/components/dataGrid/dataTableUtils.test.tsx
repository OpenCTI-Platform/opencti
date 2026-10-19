import React from 'react';
import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../utils/tests/test-render';
import { defaultColumnsMap } from './dataTableUtils';

const renderColumn = (id: string, data: unknown, helpers?: unknown) => {
  const column = defaultColumnsMap.get(id);
  if (!column?.render) throw new Error(`Column "${id}" has no render function`);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return testRender(<div>{column.render(data as any, helpers as any)}</div>);
};

const fileData = (mimetype: string, size: number) => ({
  importFiles: { edges: [{ node: { name: 'sample.bin', metaData: { mimetype }, size } }] },
});

describe('dataTableUtils default columns — tooltip anchors', () => {
  it('anchors the color tooltip', async () => {
    const { user } = renderColumn('color', { color: '#ff7f50' });
    await user.hover(screen.getByText('#ff7f50'));
    expect(await screen.findByRole('tooltip')).toHaveTextContent('#ff7f50');
  });

  it('anchors the x_opencti_color tooltip', async () => {
    const { user } = renderColumn('x_opencti_color', { x_opencti_color: '#4b0082' });
    await user.hover(screen.getByText('#4b0082'));
    expect(await screen.findByRole('tooltip')).toHaveTextContent('#4b0082');
  });

  it('anchors the file_size tooltip, on the size the cell shows', async () => {
    const { user } = renderColumn('file_size', fileData('text/plain', 42), {
      b: (value: number) => `${value} Bytes`,
    });
    await user.hover(screen.getByText('42 Bytes'));
    expect(await screen.findByRole('tooltip')).toHaveTextContent('42 Bytes');
  });

  it('anchors the number_observed tooltip', async () => {
    const { user } = renderColumn('number_observed', { number_observed: 7 }, {
      n: (value: number) => `${value} times`,
    });
    await user.hover(screen.getByText('7 times'));
    expect(await screen.findByRole('tooltip')).toHaveTextContent('7');
  });

  it('anchors the operatingSystem tooltip', async () => {
    const { user } = renderColumn('operatingSystem', { operatingSystem: { name: 'Debian 12' } });
    await user.hover(screen.getByText('Debian 12'));
    expect(await screen.findByRole('tooltip')).toHaveTextContent('Debian 12');
  });
});

describe('dataTableUtils default columns, allowed markings', () => {
  it('shows one marking chip and lists the others in the tooltip', async () => {
    const { user } = renderColumn('allowed_markings', {
      allowed_markings: [
        { id: 'm1', definition: 'PAP:RED' },
        { id: 'm2', definition: 'TLP:AMBER' },
        { id: 'm3', definition: 'PAP:AMBER' },
      ],
    });
    expect(screen.getByText('PAP:RED')).toBeInTheDocument();
    expect(screen.queryByText('TLP:AMBER')).not.toBeInTheDocument();
    expect(screen.queryByText('PAP:AMBER')).not.toBeInTheDocument();
    await user.hover(screen.getByText('PAP:RED'));
    const tooltip = await screen.findByRole('tooltip');
    expect(tooltip).toHaveTextContent('TLP:AMBER');
    expect(tooltip).toHaveTextContent('PAP:AMBER');
  });
});
