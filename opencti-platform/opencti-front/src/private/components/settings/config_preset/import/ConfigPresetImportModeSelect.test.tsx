import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../../utils/tests/test-render';
import ConfigPresetImportModeSelect from './ConfigPresetImportModeSelect';

describe('ConfigPresetImportModeSelect', () => {
  it('shows the choice from two modes, named after its subject and its purpose', () => {
    testRender(<ConfigPresetImportModeSelect subject="Dark" modes={['OVERWRITE', 'COPY']} value="OVERWRITE" purpose="When it already exists" onChange={vi.fn()} />);
    expect(screen.getByRole('combobox', { name: 'Dark: When it already exists' })).toBeInTheDocument();
  });

  it('shows nothing for a type with no choice, or with a mode it does not know', () => {
    const { container } = testRender(<ConfigPresetImportModeSelect subject="Banner" modes={['OVERWRITE']} value="OVERWRITE" purpose="When it already exists" onChange={vi.fn()} />);
    expect(screen.queryByRole('combobox')).not.toBeInTheDocument();
    expect(container).toBeEmptyDOMElement();
    testRender(<ConfigPresetImportModeSelect subject="Banner" modes={['OVERWRITE', 'MERGE']} value={null} purpose="Apply to all" onChange={vi.fn()} />);
    expect(screen.queryByRole('combobox')).not.toBeInTheDocument();
  });
});
