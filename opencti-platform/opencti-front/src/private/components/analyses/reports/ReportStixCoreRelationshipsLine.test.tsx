import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import { BrowserRouter } from 'react-router';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import ReportStixCoreRelationshipsLine, { ReportRelationshipNode } from './ReportStixCoreRelationshipsLine';
import type { DataColumns } from '../../../../components/list_lines';

const useFragmentMock = vi.hoisted(() => vi.fn());

vi.mock('react-relay', () => ({
  useFragment: useFragmentMock,
}));

vi.mock('@filigran/design-system', () => ({
  Checkbox: ({ checked, ...props }: { checked: boolean; 'aria-label': string }) => (
    <input type="checkbox" checked={checked} readOnly {...props} />
  ),
}));

vi.mock('../../../../components/ItemEntityType', () => ({
  default: ({ entityType }: { entityType: string }) => <span>{entityType}</span>,
}));

vi.mock('../../../../components/ItemIcon', () => ({
  default: () => null,
}));

vi.mock('../../../../utils/defaultRepresentatives', () => ({
  getMainRepresentative: (entity: { representative?: { main?: string | null } }) => entity.representative?.main,
}));

vi.mock('../../../../utils/Entity', () => ({
  resolveLink: (entityType: string) => `/dashboard/${entityType}`,
}));

const dataColumns: DataColumns = {
  fromType: { label: 'From type', width: '11%', isSortable: false },
  fromName: { label: 'From name', width: '16%', isSortable: false },
  relationship_type: { label: 'Relationship type', width: '12%', isSortable: true },
  toType: { label: 'To type', width: '11%', isSortable: false },
  toName: { label: 'To name', width: '16%', isSortable: false },
  createdBy: { label: 'Author', width: '9%', isSortable: false },
  created_at: { label: 'Created', width: '9%', isSortable: true },
  objectMarking: { label: 'Marking', width: '8%', isSortable: false },
};

const relationship: ReportRelationshipNode = {
  id: 'relationship-id',
  entity_type: 'stix-core-relationship',
  relationship_type: 'targets',
  created_at: '2026-09-18T10:00:00.000Z',
  createdBy: { name: 'Analyst' },
  objectMarking: [{ definition: 'TLP:AMBER' }],
  from: {
    id: 'malware-id',
    entity_type: 'Malware',
    representative: { main: 'Example malware' },
  },
  to: {
    id: 'location-id',
    entity_type: 'Location',
    representative: { main: 'Example location' },
  },
};

const renderLine = (onToggleEntity = vi.fn()) => render(
  <ThemeProvider theme={createTheme()}>
    <BrowserRouter>
      <ReportStixCoreRelationshipsLine
        dataColumns={dataColumns}
        node={relationship}
        onToggleEntity={onToggleEntity}
        selectedElements={{}}
        deSelectedElements={{}}
        selectAll={false}
      />
    </BrowserRouter>
  </ThemeProvider>,
);

describe('ReportStixCoreRelationshipsLine', () => {
  beforeEach(() => {
    useFragmentMock.mockReturnValue(relationship);
  });

  it('renders the materialized relationship values and relation link', () => {
    renderLine();

    expect(screen.getByText('Malware')).toBeInTheDocument();
    expect(screen.getByText('Example malware')).toBeInTheDocument();
    expect(screen.getByText('targets')).toBeInTheDocument();
    expect(screen.getByText('Location')).toBeInTheDocument();
    expect(screen.getByText('Example location')).toBeInTheDocument();
    expect(screen.getByText('Analyst')).toBeInTheDocument();
    expect(screen.getByText('TLP:AMBER')).toBeInTheDocument();
    expect(screen.queryByText(/Entity_undefined|Unknown/)).not.toBeInTheDocument();
    expect(screen.getByRole('link')).toHaveAttribute(
      'href',
      '/dashboard/Malware/malware-id/knowledge/relations/relationship-id',
    );
  });

  it('passes the materialized relationship to the selection handler', () => {
    const onToggleEntity = vi.fn();
    renderLine(onToggleEntity);

    fireEvent.click(screen.getByRole('checkbox', { name: 'Select line' }));

    expect(onToggleEntity).toHaveBeenCalledWith(relationship, expect.anything());
  });
});
