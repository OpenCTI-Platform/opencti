import React from 'react';
import { GraphiQL } from 'graphiql';
import { createGraphiQLFetcher } from '@graphiql/toolkit';
import 'graphiql/graphiql.css';
import { APP_BASE_PATH } from '../../relay/environment';
import PublicTopBar from './PublicTopBar';

const fetcher = createGraphiQLFetcher({ url: `${APP_BASE_PATH}/graphql` });

const Playground: React.FC = () => {
  return (
    <>
      <PublicTopBar title={'GraphQL playground'} />
      <GraphiQL fetcher={fetcher} />
    </>
  );
};

export default Playground;
