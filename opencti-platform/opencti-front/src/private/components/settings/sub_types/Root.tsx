/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React from 'react';
import { Route, Routes, useParams } from 'react-router-dom';
import { graphql } from 'react-relay';
import { QueryRenderer } from '../../../../relay/environment';
import Loader from '../../../../components/Loader';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import SubType from './SubType';
import { RootSubTypeQuery$data } from './__generated__/RootEntityTypeQuery.graphql';

export const subTypeQuery = graphql`
  query RootSubTypeQuery($id: String!) {
    subType(id: $id) {
      ...SubType_subType
    }
  }
`;

const RootSubType = () => {
  const { subTypeId } = useParams() as { subTypeId: string };
  return (
    <QueryRenderer
      query={subTypeQuery}
      variables={{ id: subTypeId }}
      render={({ props }: { props: RootSubTypeQuery$data }) => {
        if (props) {
          if (props.subType) {
            return (
              <Routes>
                <Route
                  path="/"
                  element={ <SubType data={props.subType} />}
                />
              </Routes>
            );
          }
          return <ErrorNotFound />;
        }
        return <Loader />;
      }}
    />
  );
};

export default RootSubType;
