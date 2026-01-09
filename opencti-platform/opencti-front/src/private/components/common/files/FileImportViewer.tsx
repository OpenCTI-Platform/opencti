import React, { FunctionComponent, useEffect } from 'react';
import { createRefetchContainer, graphql, RelayRefetchProp } from 'react-relay';
import { interval } from 'rxjs';
import Grid from '@mui/material/Grid';
import List from '@mui/material/List';
import FileLine from './FileLine';
import { TEN_SECONDS } from '../../../../utils/Time';
import { useFormatter } from '../../../../components/i18n';
import { FileImportViewer_entity$data } from './__generated__/FileImportViewer_entity.graphql';
import { FileLine_file$data } from './__generated__/FileLine_file.graphql';
import { KNOWLEDGE_KNUPLOAD } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import UploadImport from '../../../../components/UploadImport';
import Card from '../../../../components/common/card/Card';

const interval$ = interval(TEN_SECONDS);

interface FileImportViewerComponentProps {
  entity: FileImportViewer_entity$data;
  disableImport: boolean;
  handleOpenImport: (file: FileLine_file$data | undefined) => void;
  connectors: { [p: string]: { data: { name: string; active: boolean } }[] };
  relay: RelayRefetchProp;
  isArtifact?: boolean;
  directDownload?: boolean;
}

const FileImportViewerComponent: FunctionComponent<
  FileImportViewerComponentProps
> = ({
  entity,
  disableImport,
  handleOpenImport,
  connectors,
  relay,
  isArtifact,
  directDownload,
}) => {
  const { t_i18n } = useFormatter();

  const { id, importFiles } = entity;
  useEffect(() => {
    // Refresh the export viewer every interval
    const subscription = interval$.subscribe(() => {
      relay.refetch({ id });
    });
    return function cleanup() {
      subscription.unsubscribe();
    };
  }, []);
  return (
    <Grid item xs={6}>
      <Card
        padding="horizontal"
        title={t_i18n('Uploaded files')}
        action={(
          <Security needs={[KNOWLEDGE_KNUPLOAD]}>
            <UploadImport
              entityId={id}
              size="small"
              fontSize="small"
              onSuccess={() => relay.refetch({ id })}
            />
          </Security>
        )}
      >
        {importFiles?.edges?.length ? (
          <List>
            {importFiles?.edges?.map((file) => {
              return (
                file?.node && (
                  <FileLine
                    key={file?.node.id}
                    dense={true}
                    disableImport={disableImport}
                    file={file?.node}
                    connectors={
                      connectors
                      && connectors[file?.node?.metaData?.mimetype ?? 0]
                    }
                    handleOpenImport={handleOpenImport}
                    isArtifact={isArtifact}
                    directDownload={directDownload}
                  />
                )
              );
            })}
          </List>
        ) : (
          <div style={{ display: 'table', height: '100%', width: '100%' }}>
            <span
              style={{
                display: 'table-cell',
                verticalAlign: 'middle',
                textAlign: 'center',
              }}
            >
              {t_i18n('No file for the moment')}
            </span>
          </div>
        )}
      </Card>
    </Grid>
  );
};

const FileImportViewerRefetchQuery = graphql`
  query FileImportViewerRefetchQuery($id: String!) {
    stixCoreObject(id: $id) {
      ...FileImportViewer_entity
    }
  }
`;

const FileImportViewer = createRefetchContainer(
  FileImportViewerComponent,
  {
    entity: graphql`
      fragment FileImportViewer_entity on StixCoreObject {
        id
        entity_type
        importFiles(first: 500) @connection(key: "Pagination_importFiles") {
          edges {
            node {
              id
              ...FileLine_file
              metaData {
                mimetype
              }
            }
          }
        }
      }
    `,
  },
  FileImportViewerRefetchQuery,
);

export default FileImportViewer;
