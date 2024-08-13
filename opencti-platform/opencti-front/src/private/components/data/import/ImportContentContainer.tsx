import React, { FunctionComponent } from 'react';
import ImportContent, { importContentQuery } from '@components/data/import/ImportContent';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import ImportWorkbenchesContent from '@components/data/import/ImportWorkbenchesContent';
import ImportFilesContent from '@components/data/import/ImportFilesContent';
import { ImportContentQuery } from './__generated__/ImportContentQuery.graphql';

interface ImportContentContainerProps {
  tab?: string;
  queryRef: PreloadedQuery<ImportContentQuery>;
}

export const importConnectorsFragment = graphql`
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
  if (tab === 'file') {
    return (
      <ImportFilesContent />
    );
  }
  if (tab === 'workbench') {
    return (
      <ImportWorkbenchesContent />
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
