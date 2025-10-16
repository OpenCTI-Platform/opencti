// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { FunctionComponent } from 'react';
import { Route, Routes } from 'react-router';
import { graphql, useFragment } from 'react-relay';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import { DataSourceKnowledge_dataSource$key } from './__generated__/DataSourceKnowledge_dataSource.graphql';

const DataSourceKnowledgeFragment = graphql`
  fragment DataSourceKnowledge_dataSource on DataSource {
    id
    name
    aliases
  }
`;

interface DataSourceKnowledgeComponentProps {
  data: DataSourceKnowledge_dataSource$key;
  enableReferences: boolean;
}

const DataSourceKnowledgeComponent: FunctionComponent<
DataSourceKnowledgeComponentProps
> = ({ data }) => {
  const dataSource = useFragment(DataSourceKnowledgeFragment, data);
  return (
    <>
      <Routes>
        <Route
          path="/relations/:relationId"
          element={
            <StixCoreRelationship entityId={dataSource.id} />
          }
        />
      </Routes>
    </>
  );
};

export default DataSourceKnowledgeComponent;
