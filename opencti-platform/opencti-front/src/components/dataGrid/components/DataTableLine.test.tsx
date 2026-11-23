import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router';
import { createTheme, ThemeProvider } from '@mui/material/styles';
import DataTableLine from './DataTableLine';
import { useDataTableContext } from './DataTableContext';
import { DataTableContextProps, DataTableVariant } from '../dataTableTypes';

vi.mock('./DataTableContext', () => ({ useDataTableContext: vi.fn() }));
vi.mock('./DataTableHeader', () => ({ SELECT_COLUMN_SIZE: 42 }));

const row = { id: 'match-1', entity_type: 'IntelligenceRequirementMatch', name: 'CVE-2024-7347' };
const theme = createTheme();

const context = (overrides: Partial<DataTableContextProps> = {}) => ({
  variant: DataTableVariant.default,
  columns: [{ id: 'name', visible: true, percentWidth: 50, render: (d: typeof row) => d.name }, { id: 'navigate', visible: true }],
  tableWidthState: [500, vi.fn()],
  useLineData: (r: typeof row) => r,
  useDataCellHelpers: () => ({}),
  getComputeLink: () => '/dashboard/entities/null/match-1',
  startsWithAction: false,
  startsWithIcon: false,
  endsWithAction: true,
  endsWithNavigate: true,
  useDataTableToggle: { selectAll: false, deSelectedElements: {}, selectedElements: {}, onToggleEntity: vi.fn() },
  useDataTablePaginationLocalStorage: { viewStorage: {} },
  formatter: { t_i18n: (message: string) => message },
  ...overrides,
} as unknown as DataTableContextProps);

const renderLine = () => render(
  <MemoryRouter initialEntries={['/dashboard/intelligence_requirements/ir-1/entities']}>
    <ThemeProvider theme={theme}>
      <Routes>
        <Route path="/dashboard/intelligence_requirements/ir-1/entities" element={<DataTableLine row={row} index={0} onToggleShiftEntity={vi.fn()} />} />
        <Route path="*" element={<div>navigated away</div>} />
      </Routes>
    </ThemeProvider>
  </MemoryRouter>,
);

describe('DataTableLine row chevron', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // The intelligence requirement Entities table: its rows are matches with no page, the chevron opens the drawer
  it('runs the row click and never navigates when the table gives the rows no link', () => {
    const onLineClick = vi.fn();
    vi.mocked(useDataTableContext).mockReturnValue(context({ onLineClick, getComputeLink: () => undefined }));
    renderLine();
    fireEvent.click(screen.getByRole('button', { name: 'Open link' }));
    expect(onLineClick).toHaveBeenCalledWith(row);
    expect(screen.queryByText('navigated away')).not.toBeInTheDocument();
  });

  it('navigates to the row link when the table has one', () => {
    vi.mocked(useDataTableContext).mockReturnValue(context());
    renderLine();
    fireEvent.click(screen.getByRole('button', { name: 'Open link' }));
    expect(screen.getByText('navigated away')).toBeInTheDocument();
  });
});
