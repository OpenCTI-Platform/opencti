// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { FunctionComponent } from 'react';
import { Route, Routes } from 'react-router';
import { graphql, useFragment } from 'react-relay';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import { DataComponentKnowledge_dataComponent$key } from './__generated__/DataComponentKnowledge_dataComponent.graphql';

const DataComponentKnowledgeFragment = graphql`
  fragment DataComponentKnowledge_dataComponent on DataComponent {
    id
    name
    aliases
  }
`;

interface DataComponentKnowledgeProps {
  data: DataComponentKnowledge_dataComponent$key;
  enableReferences: boolean;
}

const DataComponentKnowledge: FunctionComponent<
DataComponentKnowledgeProps
> = ({ data }) => {
  const dataComponent = useFragment(DataComponentKnowledgeFragment, data);
  return (
    <>
      <Routes>
        <Route
          path="/relations/:relationId"
          element={
            <StixCoreRelationship entityId={dataComponent.id} />
          }
        />
      </Routes>
    </>
  );
};

export default DataComponentKnowledge;
