import React, { FunctionComponent, useEffect } from 'react';
import { createRefetchContainer, graphql, RelayRefetchProp } from 'react-relay';
import { interval } from 'rxjs';
import { useLocation } from 'react-router';
import { getContentTabFilePath } from '../stix_core_objects/StixCoreObjectContentFileUtils';
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
  const { pathname } = useLocation();
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
    <Grid size={6}>
      <Card
        padding="horizontal"
        title={t_i18n('Exported files')}
        action={(
          <Tooltip
            title={titleToUse}
            aria-label="generate-export"
          >
            <IconButton
              onClick={handleOpenExport}
              disabled={!isExportPossible || !!draftContext}
              aria-haspopup="true"
              color="primary"
              size="small"
              aria-label={t_i18n('Exported files')}
            >
              <FileExportOutline fontSize="small" />
            </IconButton>
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
                  openInNewTabAction
                  contentTabLink={getContentTabFilePath(pathname, entity.entity_type, file.node.id, file.node.metaData?.mimetype, 'export')}
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
        entity_type
        exportFiles(first: 500) @connection(key: "Pagination_exportFiles") {
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
  FileExportViewerRefetchQuery,
);

export default FileExportViewer;
