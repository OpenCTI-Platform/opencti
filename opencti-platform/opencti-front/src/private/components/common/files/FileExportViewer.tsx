import React, { FunctionComponent, useEffect } from 'react';
import { createRefetchContainer, graphql, RelayRefetchProp } from 'react-relay';
import { interval } from 'rxjs';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import List from '@mui/material/List';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@common/button/IconButton';
import { FileExportOutline } from 'mdi-material-ui';
import makeStyles from '@mui/styles/makeStyles';
import { FIVE_SECONDS } from '../../../../utils/Time';
import FileLine from './FileLine';
import { useFormatter } from '../../../../components/i18n';
import { FileExportViewer_entity$data } from './__generated__/FileExportViewer_entity.graphql';
import useDraftContext from '../../../../utils/hooks/useDraftContext';

const interval$ = interval(FIVE_SECONDS);

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  paper: {
    padding: '10px 15px 10px 15px',
    borderRadius: 4,
    marginTop: 2,
  },
}));

interface FileExportViewerComponentProps {
  entity: FileExportViewer_entity$data;
  relay: RelayRefetchProp;
  handleOpenExport: () => void;
  isExportPossible: boolean;
}

const FileExportViewerComponent: FunctionComponent<FileExportViewerComponentProps> = ({ entity, relay, handleOpenExport, isExportPossible }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const draftContext = useDraftContext();
  let titleToUse = t_i18n('Generate an export');
  if (draftContext) {
    titleToUse = t_i18n('Not available in draft');
  } else if (!isExportPossible) {
    titleToUse = t_i18n('No export connector available to generate an export');
  }
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
    <Grid item xs={6}>
      <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
        {t_i18n('Exported files')}
      </Typography>
      <div style={{ float: 'left', marginTop: -15 }}>
        <Tooltip
          title={titleToUse}
          aria-label="generate-export"
        >
          <span>
            <IconButton
              onClick={handleOpenExport}
              disabled={!isExportPossible || !!draftContext}
              aria-haspopup="true"
              color="primary"
            >
              <FileExportOutline />
            </IconButton>
          </span>
        </Tooltip>
      </div>
      <div className="clearfix" />
      <Paper classes={{ root: classes.paper }} className="paper-for-grid" variant="outlined">
        {exportFiles?.edges?.length ? (
          <List data-testid="FileExportManager">
            {exportFiles.edges.map((file) => (
              file?.node && (
                <FileLine
                  key={file?.node.id}
                  file={file?.node}
                  dense={true}
                  disableImport={true}
                />
              )
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
              {t_i18n('No file for the moment')}
            </span>
          </div>
        )}
      </Paper>
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
        exportFiles(first: 500) @connection(key: "Pagination_exportFiles") {
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
