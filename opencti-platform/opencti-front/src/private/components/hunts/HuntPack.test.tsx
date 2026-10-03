import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import { HuntPackExportButton } from './HuntPack';

const dataTableContext = vi.hoisted(() => ({ current: {} as Record<string, unknown> }));

vi.mock('../../../components/dataGrid/components/DataTableContext', () => ({
  useDataTableContext: () => dataTableContext.current,
}));

const resolvePath = (data: { hunts: { edges: { node: { id: string } }[] } }) => data.hunts.edges.map((edge) => edge.node);

describe('HuntPackExportButton', () => {
  beforeEach(() => {
    dataTableContext.current = {};
  });

  it('renders disabled before the first page of the table is loaded', () => {
    dataTableContext.current = {
      useDataTableToggle: { selectedElements: {}, deSelectedElements: {}, selectAll: true },
      data: undefined,
      resolvePath,
    };
    testRender(<HuntPackExportButton />);
    expect(screen.getByTestId('hunt-pack-export')).toBeDisabled();
  });

  it('exports the loaded hunts when the whole table is selected', () => {
    dataTableContext.current = {
      useDataTableToggle: { selectedElements: {}, deSelectedElements: {}, selectAll: true },
      data: { hunts: { edges: [{ node: { id: 'hunt-1' } }] } },
      resolvePath,
    };
    testRender(<HuntPackExportButton />);
    expect(screen.getByTestId('hunt-pack-export')).toBeEnabled();
  });
});
