import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import Hunt from './Hunt';

vi.mock('react-relay', async (importOriginal) => {
  const original = await importOriginal<typeof import('react-relay')>();
  return { ...original, useFragment: (_fragment: unknown, data: unknown) => data };
});

vi.mock('../../../utils/hooks/useOverviewLayoutCustomization', () => ({
  default: () => [{ key: 'sources', width: 6 }],
}));

vi.mock('../common/provenance/ProvenanceSourcesCard', () => ({
  default: ({ id }: { id: string }) => <div data-testid="provenance-sources-card">{id}</div>,
}));

vi.mock('./HuntDraftBanner', () => ({ default: () => null }));

describe('Hunt overview', () => {
  it('shows the Sources card in the sources slot of the layout, as the other overviews do', () => {
    testRender(<Hunt data={{ id: 'hunt-1', entity_type: 'Hunt', objectMarking: [] } as never} />);
    expect(screen.getByTestId('provenance-sources-card')).toHaveTextContent('hunt-1');
  });
});
