import React from 'react';
import { GraphiQL } from 'graphiql';
import { createGraphiQLFetcher } from '@graphiql/toolkit';
import 'graphiql/graphiql.css';
import { APP_BASE_PATH } from '../../relay/environment';
import { useFormatter } from '../../components/i18n';
import PublicTopBar from './PublicTopBar';

const fetcher = createGraphiQLFetcher({ url: `${APP_BASE_PATH}/graphql` });

const Playground: React.FC = () => {
  const { t_i18n } = useFormatter();
  return (
    <div style={{ height: '100vh', display: 'flex', flexDirection: 'column' }}>
      <PublicTopBar title={t_i18n('GraphQL playground')} />
      <GraphiQL fetcher={fetcher} />
    </div>
  );
};

export default Playground;
