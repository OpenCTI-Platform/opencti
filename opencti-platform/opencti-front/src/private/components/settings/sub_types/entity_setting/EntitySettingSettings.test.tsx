import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../../utils/tests/test-render';
import useHelper from '../../../../../utils/hooks/useHelper';
import EntitySettingSettings from './EntitySettingSettings';
import type { EntitySettingsFragment_entitySetting$key } from './__generated__/EntitySettingsFragment_entitySetting.graphql';
import type { EntitySettingProvenanceRelationships_entitySetting$key } from './__generated__/EntitySettingProvenanceRelationships_entitySetting.graphql';

vi.mock('../../../../../utils/hooks/useHelper', () => ({
  default: vi.fn(),
}));

// The fragment data is given as is, the sections are stubs: the relationship list runs its statistics query once mounted
vi.mock('react-relay', async (importOriginal) => ({
  ...await importOriginal<typeof import('react-relay')>(),
  useFragment: (_: unknown, data: unknown) => data,
}));
vi.mock('../../../../../utils/hooks/useApiMutation', () => ({
  default: () => [vi.fn(), false],
}));
vi.mock('./EntitySettingVisibility', () => ({ default: () => <div data-testid="visibility-section" /> }));
vi.mock('./EntitySettingReferences', () => ({ default: () => <div data-testid="references-section" /> }));
vi.mock('./EntitySettingProvenance', () => ({ default: () => <div data-testid="provenance-section" /> }));
vi.mock('./EntitySettingProvenanceRelationships', () => ({ default: () => <div data-testid="provenance-relationships-section" /> }));
vi.mock('./EntitySettingProcedures', () => ({ default: () => <div data-testid="procedures-section" /> }));

const setProvenanceEnabled = (enabled: boolean) => {
  vi.mocked(useHelper).mockReturnValue({ isProvenanceEnabled: () => enabled } as unknown as ReturnType<typeof useHelper>);
};

const RELATIONSHIP_SETTINGS = ['attributes_configuration', 'enforce_reference', 'provenance_tracking', 'provenance_relationship_types', 'procedures_preservation', 'procedures_description_policy'];
const ENTITY_SETTINGS = ['attributes_configuration', 'platform_hidden_type', 'enforce_reference', 'provenance_tracking'];

const renderSettings = (availableSettings: string[]) => testRender(
  <EntitySettingSettings
    entitySettingsData={{ id: 'entity-setting-id', availableSettings } as unknown as EntitySettingsFragment_entitySetting$key}
    provenanceRelationshipsData={{} as EntitySettingProvenanceRelationships_entitySetting$key}
  />,
);

describe('Entity type settings', () => {
  it('shows per-relationship-type tracking and the procedures of relationships while provenance is enabled', () => {
    setProvenanceEnabled(true);
    renderSettings(RELATIONSHIP_SETTINGS);
    expect(screen.getByTestId('provenance-relationships-section')).toBeInTheDocument();
    expect(screen.getByTestId('procedures-section')).toBeInTheDocument();
    expect(screen.queryByTestId('provenance-section')).not.toBeInTheDocument();
  });

  it('shows the provenance tracking of an entity type while provenance is enabled', () => {
    setProvenanceEnabled(true);
    renderSettings(ENTITY_SETTINGS);
    expect(screen.getByTestId('provenance-section')).toBeInTheDocument();
    expect(screen.queryByTestId('procedures-section')).not.toBeInTheDocument();
  });

  it.each([['relationships', RELATIONSHIP_SETTINGS], ['an entity type', ENTITY_SETTINGS]])('hides every provenance section of %s while provenance is disabled', (_, availableSettings) => {
    setProvenanceEnabled(false);
    renderSettings(availableSettings);
    expect(screen.getByTestId('visibility-section')).toBeInTheDocument();
    expect(screen.getByTestId('references-section')).toBeInTheDocument();
    expect(screen.queryByTestId('provenance-section')).not.toBeInTheDocument();
    expect(screen.queryByTestId('provenance-relationships-section')).not.toBeInTheDocument();
    expect(screen.queryByTestId('procedures-section')).not.toBeInTheDocument();
  });
});
