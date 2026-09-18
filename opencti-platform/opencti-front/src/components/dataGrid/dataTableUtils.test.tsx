import React from 'react';
import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../utils/tests/test-render';
import { defaultColumnsMap } from './dataTableUtils';

/**
 * MUI `Tooltip` forwards its ref to its single child and gates the popper on
 * having resolved a DOM node from it (`open: childNode ? open : false`). A
 * Fragment cannot hold a ref, so a column rendering `<Tooltip><>…</></Tooltip>`
 * silently never shows its tooltip. These cases guard the anchor, not the
 * markup: they hover the rendered value and require a tooltip to appear.
 */

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

  it('anchors the file_size tooltip', async () => {
    const { user } = renderColumn('file_size', fileData('text/plain', 42), {
      b: (value: number) => `${value} Bytes`,
    });
    await user.hover(screen.getByText('42 Bytes'));
    expect(await screen.findByRole('tooltip')).toHaveTextContent('text/plain');
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
