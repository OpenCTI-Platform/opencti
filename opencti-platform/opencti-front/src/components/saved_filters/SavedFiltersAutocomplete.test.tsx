import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { fireEvent, screen } from '@testing-library/react';
import testRender from '../../utils/tests/test-render';
import SavedFiltersAutocomplete from './SavedFiltersAutocomplete';
import { type SavedFiltersAutocompleteOptionType, type SavedFiltersSelectionData } from './SavedFilterSelection';

vi.mock('./SavedFilterEditDialog', () => ({ default: () => <div /> }));

const buildOption = (id: string, label: string): SavedFiltersAutocompleteOptionType => ({
  label,
  value: { id, name: label, filters: '{}', scope: 'Stix-Core-Object', creator_id: 'me' } as unknown as SavedFiltersSelectionData,
  isOwner: true,
  canManage: false,
});

const options = [buildOption('a', 'Alpha'), buildOption('b', 'Bravo'), buildOption('c', 'Charlie')];

const visibleLabels = () => screen.getAllByRole('option').map((o) => o.textContent);

describe('SavedFiltersAutocomplete', () => {
  it('lists every saved filter when one is already selected, so another can replace it directly', () => {
    testRender(<SavedFiltersAutocomplete options={options} value={options[0]} inputValue="Alpha" />);

    fireEvent.click(screen.getByLabelText('Select saved filter'));

    expect(visibleLabels()).toEqual(['Alpha', 'Bravo', 'Charlie']);
  });

  it('still narrows the list on typed text', () => {
    testRender(<SavedFiltersAutocomplete options={options} value={options[0]} inputValue="Bra" />);

    fireEvent.click(screen.getByLabelText('Select saved filter'));

    expect(visibleLabels()).toEqual(['Bravo']);
  });
});
