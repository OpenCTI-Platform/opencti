import React, { FunctionComponent, useEffect } from 'react';
import { createRefetchContainer, graphql, RelayRefetchProp } from 'react-relay';
import { interval } from 'rxjs';
import Grid from '@mui/material/Grid';
import List from '@mui/material/List';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@common/button/IconButton';
import { FileExportOutline } from 'mdi-material-ui';
import { FIVE_SECONDS } from '../../../../utils/Time';
import FileLine from './FileLine';
import { useFormatter } from '../../../../components/i18n';
import { FileExportViewer_entity$data } from './__generated__/FileExportViewer_entity.graphql';
import useDraftContext from '../../../../utils/hooks/useDraftContext';
import Card from '../../../../components/common/card/Card';

const interval$ = interval(FIVE_SECONDS);

interface FileExportViewerComponentProps {
  entity: FileExportViewer_entity$data;
  relay: RelayRefetchProp;
  handleOpenExport: () => void;
  isExportPossible: boolean;
}

const FileExportViewerComponent: FunctionComponent<FileExportViewerComponentProps> = ({ entity, relay, handleOpenExport, isExportPossible }) => {
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
      <Card
        padding="horizontal"
        title={t_i18n('Exported files')}
        action={(
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
                size="small"
              >
                <FileExportOutline fontSize="small" />
              </IconButton>
            </span>
          </Tooltip>
        )}
      >
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
      </Card>
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
