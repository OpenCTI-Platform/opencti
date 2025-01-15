import React from 'react';
import { GraphiQL } from 'graphiql';
import { createGraphiQLFetcher } from '@graphiql/toolkit';
import 'graphiql/graphiql.css';
import { APP_BASE_PATH } from '../../relay/environment';
import PublicTopBar from './PublicTopBar';

const fetcher = createGraphiQLFetcher({ url: `${APP_BASE_PATH}/graphql` });

const Playground: React.FC = () => {
  return (
    <div style={{ height: '100vh', display: 'flex', flexDirection: 'column' }}>
      <PublicTopBar title={'GraphQL playground'} />
      <GraphiQL fetcher={fetcher} />
    </div>
  );
};

export default Playground;
