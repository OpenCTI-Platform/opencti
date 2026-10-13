import { describe, it, expect, vi } from 'vitest';
import { screen } from '@testing-library/react';
import * as Yup from 'yup';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import StixCoreRelationshipCreationForm from './StixCoreRelationshipCreationForm';

// Avoid the entitySettings context dependency, not relevant for these tests.
vi.mock('../../../../utils/hooks/useDefaultValues', () => ({
  __esModule: true,
  default: (_id: string, initialValues: unknown) => initialValues,
}));
vi.mock('../../../../utils/hooks/useEntitySettings', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../utils/hooks/useEntitySettings')>();
  return {
    ...actual,
    useSchemaCreationValidation: (_id: string, shape: Yup.ObjectShape) => Yup.object().shape(shape),
  };
});

describe('Component: StixCoreRelationshipCreationForm', () => {
  const userContext = createMockUserContext({
    entitySettings: { edges: [] },
  });

  const fromEntities = [{ id: 'from-id', entity_type: 'Security-Coverage-Result', name: 'My coverage result' }];

  const renderForm = (props: { toEntities: unknown[] | undefined; toEntityType?: string }) => {
    testRender(
      <StixCoreRelationshipCreationForm
        fromEntities={fromEntities}
        relationshipTypes={['has-covered']}
        onSubmit={vi.fn()}
        handleClose={vi.fn()}
        handleReverseRelation={undefined}
        handleResetSelection={undefined}
        defaultConfidence={undefined}
        defaultStartTime={undefined}
        defaultStopTime={undefined}
        defaultCreatedBy={undefined}
        defaultMarkingDefinitions={undefined}
        {...props}
      />,
      { userContext },
    );
  };

  it('should display the given entity type when "to" entities are not provided', () => {
    renderForm({ toEntities: undefined, toEntityType: 'Vulnerability' });

    expect(screen.getByText('Multiple entities selected')).toBeInTheDocument();
    expect(screen.getByText('Vulnerability')).toBeInTheDocument();
  });

  it('should fallback on a generic entity type when "to" entities are empty and no type is given', () => {
    renderForm({ toEntities: [] });

    expect(screen.getByText('Multiple entities selected')).toBeInTheDocument();
    expect(screen.getByText('Entity and observable')).toBeInTheDocument();
  });

  it('should display the "to" entity when a single one is provided', () => {
    renderForm({
      toEntities: [{ id: 'to-id', entity_type: 'Vulnerability', name: 'CVE-2024-0001' }],
      toEntityType: 'Attack-Pattern',
    });

    expect(screen.getByText('CVE-2024-0001')).toBeInTheDocument();
    expect(screen.getByText('Vulnerability')).toBeInTheDocument();
    expect(screen.queryByText('Multiple entities selected')).not.toBeInTheDocument();
  });
});
