import ImportConnectors from '@components/data/import/ImportConnectors';
import React, { FunctionComponent } from 'react';
import ImportContent, { importContentQuery } from '@components/data/import/ImportContent';
import { ImportContentQuery } from '@components/import/__generated__/ImportContentQuery.graphql';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { ImportContent_connectorsImport$key } from './__generated__/ImportContent_connectorsImport.graphql';

interface ImportContentContainerProps {
  tab?: string;
  queryRef: PreloadedQuery<ImportContentQuery>;
}

const ImportContentContainer: FunctionComponent<ImportContentContainerProps> = ({ tab, queryRef }) => {
  const data = usePreloadedQuery(importContentQuery, queryRef);
  if (tab === 'connectors') {
    return (
      <ImportConnectors
        connectorsImport={data.connectorsForImport as ImportContent_connectorsImport$key}
      />
    );
  }
  return (
    <ImportContent
      connectorsImport={data.connectorsForImport}
      importFiles={data.importFiles}
      pendingFiles={data.pendingFiles}
    />
  );
};

export default ImportContentContainer;
