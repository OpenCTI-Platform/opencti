import React, { Suspense } from 'react';
import { describe, expect, it } from 'vitest';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { act, screen } from '@testing-library/react';
import testRender from '../../../../../utils/tests/test-render';
import { EntityStixCoreRelationshipsEntitiesViewLine } from './EntityStixCoreRelationshipsEntitiesViewLine';
import { EntityStixCoreRelationshipsEntitiesViewLineTestQuery } from './__generated__/EntityStixCoreRelationshipsEntitiesViewLineTestQuery.graphql';

const testQuery = graphql`
  query EntityStixCoreRelationshipsEntitiesViewLineTestQuery($id: String!) {
    stixCoreObject(id: $id) {
      ...EntityStixCoreRelationshipsEntitiesViewLine_node
    }
  }
`;

const dataColumns = {
  entity_type: { width: '10%' },
  name: { width: '20%' },
  observable_value: { width: '20%' },
  createdBy: { width: '10%' },
  creator: { width: '10%' },
  objectLabel: { width: '10%' },
  created_at: { width: '10%' },
  analyses: { width: '10%' },
  objectMarking: { width: '10%' },
} as never;

const Harness = () => {
  const data = useLazyLoadQuery<EntityStixCoreRelationshipsEntitiesViewLineTestQuery>(testQuery, { id: 'procedure-1' });
  if (!data.stixCoreObject) return null;
  return (
    <EntityStixCoreRelationshipsEntitiesViewLine
      node={data.stixCoreObject}
      dataColumns={dataColumns}
      onLabelClick={() => undefined}
      onToggleEntity={() => undefined}
      selectedElements={{}}
      deSelectedElements={{}}
      selectAll={false}
      onToggleShiftEntity={() => undefined}
      index={0}
    />
  );
};

describe('EntityStixCoreRelationshipsEntitiesViewLine', () => {
  it('renders the name of a Procedure node', async () => {
    const { relayEnv } = testRender(
      <Suspense fallback="loading">
        <Harness />
      </Suspense>,
    );
    act(() => {
      relayEnv.mock.resolveMostRecentOperation({
        data: {
          stixCoreObject: {
            __typename: 'Procedure',
            id: 'procedure-1',
            entity_type: 'Procedure',
            draftVersion: null,
            created_at: '2026-11-13T10:00:00.000Z',
            created: '2026-11-13T10:00:00.000Z',
            modified: '2026-11-13T10:00:00.000Z',
            name: 'Credential dumping via LSASS',
            createdBy: null,
            objectMarking: [],
            objectLabel: [],
            creators: [],
          },
        },
      });
    });
    expect(await screen.findByText('Credential dumping via LSASS')).toBeInTheDocument();
    expect(screen.queryByText('Unknown')).not.toBeInTheDocument();
  });
});
