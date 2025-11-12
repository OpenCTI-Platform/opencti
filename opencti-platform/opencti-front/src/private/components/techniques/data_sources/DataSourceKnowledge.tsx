// TODO Remove this when V6
// biome-ignore lint/suspicious/noTsIgnore: disable ts-ignore
// @ts-nocheck
import React, { FunctionComponent } from 'react';
import { Route, Routes } from 'react-router-dom';
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
