import { FunctionComponent, useEffect } from 'react';
import { createRefetchContainer, graphql, RelayRefetchProp } from 'react-relay';
import { interval } from 'rxjs';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import List from '@mui/material/List';
import makeStyles from '@mui/styles/makeStyles';
import FileLine from './FileLine';
import { TEN_SECONDS } from '../../../../utils/Time';
import FileUploader from './FileUploader';
import { useFormatter } from '../../../../components/i18n';
import FreeTextUploader from './FreeTextUploader';
import { FileImportViewer_entity$data } from './__generated__/FileImportViewer_entity.graphql';
import { FileLine_file$data } from './__generated__/FileLine_file.graphql';

const interval$ = interval(TEN_SECONDS);

const useStyles = makeStyles(() => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    padding: '10px 15px 10px 15px',
    borderRadius: 6,
    marginTop: 2,
  },
}));

interface FileImportViewerComponentProps {
  entity: FileImportViewer_entity$data;
  disableImport: boolean;
  handleOpenImport: (file: FileLine_file$data | undefined) => void;
  connectors: { [p: string]: { data: { name: string; active: boolean } }[] };
  relay: RelayRefetchProp;
}

const FileImportViewerComponent: FunctionComponent<
FileImportViewerComponentProps
> = ({ entity, disableImport, handleOpenImport, connectors, relay }) => {
  const classes = useStyles();
  const { t } = useFormatter();
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
    <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
      <div style={{ height: '100%' }} className="break">
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {t('Uploaded files')}
        </Typography>
        <div style={{ float: 'left', marginTop: -15 }}>
          <FileUploader
            entityId={id}
            onUploadSuccess={() => relay.refetch({ id })}
            size="medium"
            color={undefined}
          />
          <FreeTextUploader
            entityId={id}
            onUploadSuccess={() => relay.refetch({ id })}
            size="medium"
          />
        </div>
        <div className="clearfix" />
        <Paper classes={{ root: classes.paper }} variant="outlined">
          {importFiles?.edges?.length ? (
            <List>
              {importFiles?.edges?.map((file) => (
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
                />
              ))}
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
                {t('No file for the moment')}
              </span>
            </div>
          )}
        </Paper>
      </div>
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
        importFiles(first: 1000) @connection(key: "Pagination_importFiles") {
          edges {
            node {
              id
              ...FileLine_file
              metaData {
                mimetype
                description
                order
                inCarousel
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
