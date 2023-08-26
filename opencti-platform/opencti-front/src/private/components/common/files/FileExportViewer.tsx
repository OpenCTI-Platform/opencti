import React, { FunctionComponent, useEffect } from 'react';
import { createRefetchContainer, graphql, RelayRefetchProp } from 'react-relay';
import { interval } from 'rxjs';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import List from '@mui/material/List';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@mui/material/IconButton';
import { FileExportOutline } from 'mdi-material-ui';
import makeStyles from '@mui/styles/makeStyles';
import { FIVE_SECONDS } from '../../../../utils/Time';
import FileLine from './FileLine';
import { useFormatter } from '../../../../components/i18n';
import { FileExportViewer_entity$data } from './__generated__/FileExportViewer_entity.graphql';

const interval$ = interval(FIVE_SECONDS);

const useStyles = makeStyles(() => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    padding: '10px 15px 10px 15px',
    borderRadius: 6,
    marginTop: 2,
  },
}));

interface FileExportViewerComponentProps {
  entity: FileExportViewer_entity$data;
  relay: RelayRefetchProp;
  handleOpenExport: () => void;
  isExportPossible: boolean;
}

const FileExportViewerComponent: FunctionComponent<
FileExportViewerComponentProps
> = ({ entity, relay, handleOpenExport, isExportPossible }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const { id, exportFiles } = entity;
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
    <Grid item={true} xs={6} style={{ marginTop: 40 }}>
      <div style={{ height: '100%' }} className="break">
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {t('Exported files')}
        </Typography>
        <div style={{ float: 'left', marginTop: -15 }}>
          <Tooltip
            title={
              isExportPossible
                ? t('Generate an export')
                : t('No export connector available to generate an export')
            }
            aria-label="generate-export"
          >
            <span>
              <IconButton
                onClick={handleOpenExport}
                disabled={!isExportPossible}
                aria-haspopup="true"
                color="primary"
                size="medium"
              >
                <FileExportOutline />
              </IconButton>
            </span>
          </Tooltip>
        </div>
        <div className="clearfix" />
        <Paper classes={{ root: classes.paper }} variant="outlined">
          {exportFiles?.edges?.length ? (
            <List>
              {exportFiles.edges.map((file) => {
                return (
                  file?.node && (
                    <FileLine
                      key={file?.node.id}
                      file={file?.node}
                      dense={true}
                      disableImport={true}
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
                {t('No file for the moment')}
              </span>
            </div>
          )}
        </Paper>
      </div>
    </Grid>
  );
};

const FileExportViewerRefetchQuery = graphql`
  query FileExportViewerRefetchQuery($id: String!) {
    stixCoreObject(id: $id) {
      ...FileExportViewer_entity
    }
  }
`;

const FileExportViewer = createRefetchContainer(
  FileExportViewerComponent,
  {
    entity: graphql`
      fragment FileExportViewer_entity on StixCoreObject {
        id
        exportFiles(first: 1000) @connection(key: "Pagination_exportFiles") {
          edges {
            node {
              id
              ...FileLine_file
            }
          }
        }
      }
    `,
  },
  FileExportViewerRefetchQuery,
);

export default FileExportViewer;
