import ImportConnectors from '@components/data/import/ImportConnectors';
import React, { FunctionComponent } from 'react';
import ImportContent, { importContentQuery } from '@components/data/import/ImportContent';
import { ImportContentQuery } from '@components/import/__generated__/ImportContentQuery.graphql';
import { PreloadedQuery } from 'react-relay';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';

interface ImportContentContainerProps {
  tab?: string;
  queryRef: PreloadedQuery<ImportContentQuery>;
}

const ImportContentContainer: FunctionComponent<ImportContentContainerProps> = ({ tab, queryRef }) => {
  const data = usePreloadedPaginationFragment(
    {
      linesQuery: importContentQuery,
      linesFragment,
      queryRef,
    }
  );
  if (tab === 'connectors') {
    return (
      <ImportConnectors
        connectorsImport={props.connectorsForImport}
      />
    );
  }
  return (
    <ImportContent
      connectorsImport={props.connectorsForImport}
      importFiles={props.importFiles}
      pendingFiles={props.pendingFiles}
    />
  );
};

export default ImportContentContainer;
