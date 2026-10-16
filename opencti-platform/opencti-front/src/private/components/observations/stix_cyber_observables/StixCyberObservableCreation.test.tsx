import React from 'react';
import { screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import StixCyberObservableCreation from './StixCyberObservableCreation';

const { mockCommit, IPV4_ATTRIBUTE_NAMES } = vi.hoisted(() => ({
  mockCommit: vi.fn(),
  // What schemaAttributeNames answers for IPv4-Addr, the dates a hunt run writes included
  IPV4_ATTRIBUTE_NAMES: [
    'created_at',
    'entity_type',
    'id',
    'internal_id',
    'parent_types',
    'standard_id',
    'updated_at',
    'value',
    'x_opencti_description',
    'x_opencti_hunt_matched_at',
    'x_opencti_hunted_at',
    'x_opencti_modified_at',
    'x_opencti_score',
    'x_opencti_stix_ids',
  ],
}));

const HUNT_DATES = ['x_opencti_hunted_at', 'x_opencti_hunt_matched_at'];

vi.mock('../../../../relay/environment', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../relay/environment')>();
  return {
    ...actual,
    QueryRenderer: ({ render }: { render: (args: { props: unknown }) => React.ReactNode }) => render({
      props: { schemaAttributeNames: { edges: IPV4_ATTRIBUTE_NAMES.map((value) => ({ node: { value } })) } },
    }),
    handleErrorInForm: vi.fn(),
  };
});
vi.mock('../../../../utils/hooks/useApiMutation', () => ({ default: () => [mockCommit, false] }));
vi.mock('../../../../utils/hooks/useVocabularyCategory', () => ({
  default: () => ({ isVocabularyField: () => false, fieldToCategory: () => undefined, fields: [] }),
}));
vi.mock('../../../../components/fields/markdownField/MarkdownField', () => ({ default: () => null }));
vi.mock('../../common/form/CreatedByField', () => ({ default: () => null }));
vi.mock('../../common/form/ObjectLabelField', () => ({ default: () => null }));
vi.mock('../../common/form/ObjectMarkingField', () => ({ default: () => null }));
vi.mock('../../common/form/ExternalReferencesField', () => ({ ExternalReferencesField: () => null }));
vi.mock('../../common/files/CustomFileUploader', () => ({ default: () => null }));

const renderIPv4Creation = () => testRender(
  <StixCyberObservableCreation
    contextual={true}
    display={true}
    speeddial={true}
    open={true}
    type="IPv4-Addr"
    inputValue=""
    paginationKey="Pagination_stixCoreObjects"
    defaultCreatedBy={undefined}
  />,
  { userContext: createMockUserContext({ schema: { sdos: [], scos: [] }, settings: { metrics_definition: [] } }) },
);

describe('StixCyberObservableCreation', () => {
  it('does not offer the dates only the platform writes', () => {
    renderIPv4Creation();

    expect(screen.getByRole('textbox', { name: /^Value/ })).toBeInTheDocument();
    HUNT_DATES.forEach((name) => {
      expect(document.querySelector(`[name="${name}"]`)).toBeNull();
    });
  });

  it('creates the observable without sending the dates only the platform writes', async () => {
    const { user } = renderIPv4Creation();

    await user.type(screen.getByRole('textbox', { name: /^Value/ }), '8.8.8.8');
    await user.click(screen.getByRole('button', { name: 'Create' }));

    await waitFor(() => expect(mockCommit).toHaveBeenCalledTimes(1));
    const { variables } = mockCommit.mock.calls[0][0];
    expect(variables.type).toBe('IPv4-Addr');
    expect(variables.IPv4Addr.value).toBe('8.8.8.8');
    HUNT_DATES.forEach((name) => {
      expect(variables.IPv4Addr).not.toHaveProperty(name);
    });
  });
});
