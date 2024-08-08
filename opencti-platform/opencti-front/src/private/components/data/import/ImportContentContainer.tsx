import ImportConnectors from '@components/data/import/ImportConnectors';
import React, { FunctionComponent } from 'react';
import ImportContent, { importContentQuery } from '@components/data/import/ImportContent';
import { ImportContentQuery } from '@components/import/__generated__/ImportContentQuery.graphql';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import { ImportContentContainer_connectorsImport$key } from './__generated__/ImportContentContainer_connectorsImport.graphql';
import ImportWorkbenches from './ImportWorkbenches';

interface ImportContentContainerProps {
  tab?: string;
  queryRef: PreloadedQuery<ImportContentQuery>;
}

const importConnectorsFragment = graphql`
    fragment ImportContentContainer_connectorsImport on Connector
    @relay(plural: true) {
        id
        name
        active
        only_contextual
        connector_scope
        updated_at
        configurations {
            id
            name,
            configuration
        }
    }
`;

const ImportContentContainer: FunctionComponent<ImportContentContainerProps> = ({ tab, queryRef }) => {
  const data = usePreloadedQuery(importContentQuery, queryRef);
  const connectorsData = useFragment<ImportContentContainer_connectorsImport$key>(
    importConnectorsFragment,
    data.connectorsForImport as ImportContentContainer_connectorsImport$key,
  );
  const connectors = connectorsData.filter((n) => !n.only_contextual); // Can be null but not empty

  if (tab === 'connectors') {
    return (
      <ImportConnectors
        connectors={connectors}
      />
    );
  }
  if (tab === 'workbench') {
    return (
      <ImportWorkbenches />
    );
  }
  return (
    <ImportContent
      connectors={connectors}
      importFiles={data.importFiles}
    />
  );
};

export default ImportContentContainer;
