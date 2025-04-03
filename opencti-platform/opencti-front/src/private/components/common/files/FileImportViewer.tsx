import React, { FunctionComponent, useEffect } from 'react';
import { createRefetchContainer, graphql, RelayRefetchProp } from 'react-relay';
import { interval } from 'rxjs';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import List from '@mui/material/List';
import makeStyles from '@mui/styles/makeStyles';
import FileLine from './FileLine';
import { TEN_SECONDS } from '../../../../utils/Time';
import { useFormatter } from '../../../../components/i18n';
import { FileImportViewer_entity$data } from './__generated__/FileImportViewer_entity.graphql';
import { FileLine_file$data } from './__generated__/FileLine_file.graphql';
import { KNOWLEDGE_KNUPLOAD } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import UploadImport from '../../../../components/UploadImport';

const interval$ = interval(TEN_SECONDS);

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  paper: {
    padding: '10px 15px 10px 15px',
    borderRadius: 4,
    marginTop: 2,
  },
}));

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
  const classes = useStyles();
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
      <>
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {t_i18n('Uploaded files')}
        </Typography>
        <Security needs={[KNOWLEDGE_KNUPLOAD]} placeholder={<div style={{ height: 25 }} />}>
          <div style={{ float: 'left', marginTop: -15 }}>
            <UploadImport
              entityId={id}
              onSuccess={() => relay.refetch({ id })}
            />
          </div>
        </Security>
        <div className="clearfix" />
        <Paper classes={{ root: classes.paper }} className={'paper-for-grid'} variant="outlined">
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
        </Paper>
      </>
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
