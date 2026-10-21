import { fireEvent, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import StixCoreObjectEnrichmentWorkTouchedElements from './StixCoreObjectEnrichmentWorkTouchedElements';

/**
 * Build a touched element as the drawer fragment returns it.
 */
const element = (id: string, main: string) => ({ id, entity_type: 'Intrusion-Set', representative: { main } });

describe('StixCoreObjectEnrichmentWorkTouchedElements', () => {
  it('renders nothing while the work is running', () => {
    testRender(
      <StixCoreObjectEnrichmentWorkTouchedElements
        work={{ status: 'progress', touchedElements: [element('1', 'APT1')] }}
        first={100}
      />,
    );
    expect(screen.queryByText('Elements touched by this enrichment')).toBeNull();
  });

  it('shows the count of a completed work and lists the elements on demand', () => {
    testRender(
      <StixCoreObjectEnrichmentWorkTouchedElements
        work={{ status: 'complete', touchedElements: [element('1', 'APT1'), element('2', 'APT2'), element('3', 'APT3')] }}
        first={100}
      />,
    );
    expect(screen.getByText('3')).toBeTruthy();
    expect(screen.queryByText('APT1')).toBeNull();
    fireEvent.click(screen.getByText('Elements touched by this enrichment'));
    expect(screen.getByText('APT1').closest('a')?.getAttribute('href')).toBe('/dashboard/id/1');
    expect(screen.getByText('APT3')).toBeTruthy();
  });

  it('marks the count as partial when the list reaches the limit', () => {
    testRender(
      <StixCoreObjectEnrichmentWorkTouchedElements
        work={{ status: 'complete', touchedElements: [element('1', 'APT1'), element('2', 'APT2')] }}
        first={2}
      />,
    );
    expect(screen.getByText('2+')).toBeTruthy();
  });

  it('links relationships with their relationship label and skips rows without an id', () => {
    testRender(
      <StixCoreObjectEnrichmentWorkTouchedElements
        work={{
          status: 'complete',
          touchedElements: [
            { id: 'rel-1', entity_type: 'related-to', parent_types: ['basic-relationship', 'stix-relationship', 'stix-core-relationship'], representative: { main: 'APT1 related to Malware' } },
            { id: 'sig-1', entity_type: 'stix-sighting-relationship', parent_types: ['basic-relationship', 'stix-relationship'], representative: { main: 'APT1 sighted' } },
            { entity_type: 'related-to', representative: { main: 'No id relationship' } },
            null,
          ],
        }}
        first={100}
      />,
    );
    expect(screen.getByText('2')).toBeTruthy();
    fireEvent.click(screen.getByText('Elements touched by this enrichment'));
    expect(screen.getByText('APT1 related to Malware').closest('a')?.getAttribute('href')).toBe('/dashboard/id/rel-1');
    // Labelled with relationship_related-to, and entity_stix-sighting-relationship for the sighting
    expect(screen.getByText('related to')).toBeTruthy();
    expect(screen.getByText('Sightings')).toBeTruthy();
    expect(screen.queryByText('No id relationship')).toBeNull();
  });

  it('renders nothing when the touched elements were never recorded', () => {
    testRender(
      <StixCoreObjectEnrichmentWorkTouchedElements
        work={{ status: 'complete', touchedElements: null }}
        first={100}
      />,
    );
    expect(screen.queryByText('Elements touched by this enrichment')).toBeNull();
  });

  it('shows a zero count without an expander when the enrichment touched nothing', () => {
    testRender(
      <StixCoreObjectEnrichmentWorkTouchedElements
        work={{ status: 'complete', touchedElements: [] }}
        first={100}
      />,
    );
    expect(screen.getByText('Elements touched by this enrichment')).toBeTruthy();
    expect(screen.getByText('0')).toBeTruthy();
    expect(screen.queryByRole('button')).toBeNull();
  });
});
