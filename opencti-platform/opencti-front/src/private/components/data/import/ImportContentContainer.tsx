import ImportConnectors from '@components/data/import/ImportConnectors';
import React, { FunctionComponent } from 'react';
import ImportContent, { importContentQuery } from '@components/data/import/ImportContent';
import { ImportContentQuery } from '@components/import/__generated__/ImportContentQuery.graphql';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';

interface ImportContentContainerProps {
  tab?: string;
  queryRef: PreloadedQuery<ImportContentQuery>;
}

const ImportContentContainer: FunctionComponent<ImportContentContainerProps> = ({ tab, queryRef }) => {
  const data = usePreloadedQuery(importContentQuery, queryRef);
  if (tab === 'connectors') {
    return (
      <ImportConnectors
        connectorsImport={data.connectorsForImport}
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
