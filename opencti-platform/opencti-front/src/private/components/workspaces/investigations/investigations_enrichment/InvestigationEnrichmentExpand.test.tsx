import React from 'react';
import { act } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import testRender from '../../../../../utils/tests/test-render';
import InvestigationEnrichmentExpand from './InvestigationEnrichmentExpand';
import { InvestigationEnrichmentWork } from './investigation-enrichment.types';

const mocks = vi.hoisted(() => ({
  form: vi.fn(),
  resetFilters: vi.fn(),
  expandWorks: vi.fn(),
}));

vi.mock('@filigran/design-system', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@filigran/design-system')>()),
  Dialog: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  DialogContent: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  DialogTitle: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

vi.mock('../InvestigationExpandForm', () => ({
  default: (props: Record<string, unknown>) => {
    mocks.form(props);
    return null;
  },
}));

vi.mock('./useInvestigationEnrichmentExpand', () => ({
  default: () => ({ graphIds: new Set(), expandWorks: mocks.expandWorks }),
}));

vi.mock('./investigation-enrichment.utils', () => ({
  toExpandElements: () => [],
  countExpandOptions: () => ({
    targets: new Map([['Malware', 1]]),
    relationships: new Map(),
  }),
}));

vi.mock('../../../../../components/graph/GraphContext', () => ({
  useGraphContext: () => ({ graphData: { nodes: [], links: [] } }),
}));

vi.mock('../../../../../components/graph/utils/useGraphInteractions', () => ({
  default: () => ({
    setSelectedNodes: vi.fn(),
    setSelectedLinks: vi.fn(),
    setIsExpandOpen: vi.fn(),
    resetFilters: mocks.resetFilters,
  }),
}));

const works = [
  { id: 'work-1', eventSource: { id: 'ip-1', entity_type: 'IPv4-Addr', value: '1.1.1.1' } },
] as unknown as InvestigationEnrichmentWork[];

const submitExpand = async (resetFilters: boolean) => {
  const { calls } = mocks.form.mock;
  const { onSubmit } = calls[calls.length - 1][0];
  await act(() => onSubmit(
    {
      entity_types: [{ label: 'Malware', value: 'Malware' }],
      relationship_types: [],
      reset_filters: resetFilters,
    },
    { resetForm: vi.fn() },
  ));
};

const renderExpand = () => testRender(
  <InvestigationEnrichmentExpand
    investigationId="investigation-1"
    canEdit
    works={works}
    onClose={() => {}}
    onDismiss={() => {}}
  />,
);

describe('InvestigationEnrichmentExpand', () => {
  it('resets the graph filters after the expand when Reset filters is on', async () => {
    mocks.resetFilters.mockClear();
    renderExpand();

    await submitExpand(true);

    expect(mocks.expandWorks).toHaveBeenCalled();
    expect(mocks.resetFilters).toHaveBeenCalledTimes(1);
  });

  it('keeps the graph filters when Reset filters is off', async () => {
    mocks.resetFilters.mockClear();
    renderExpand();

    await submitExpand(false);

    expect(mocks.resetFilters).not.toHaveBeenCalled();
  });
});
