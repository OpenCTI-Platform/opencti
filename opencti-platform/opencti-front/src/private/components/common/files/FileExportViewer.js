import React, { useEffect } from 'react';
import * as PropTypes from 'prop-types';
import { createRefetchContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { interval } from 'rxjs';
import Grid from '@material-ui/core/Grid';
import Typography from '@material-ui/core/Typography';
import Paper from '@material-ui/core/Paper';
import List from '@material-ui/core/List';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core';
import Tooltip from '@material-ui/core/Tooltip';
import IconButton from '@material-ui/core/IconButton';
import { FileExportOutline } from 'mdi-material-ui';
import { FIVE_SECONDS } from '../../../../utils/Time';
import FileLine from './FileLine';
import inject18n from '../../../../components/i18n';

const interval$ = interval(FIVE_SECONDS);

const styles = () => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    padding: '10px 15px 10px 15px',
    borderRadius: 6,
  },
});

const FileExportViewerBase = ({
  entity, relay, t, classes, handleOpenExport, isExportPossible
}) => {
  const { id, exportFiles } = entity;
  const { edges } = exportFiles;
  useEffect(() => {
    // Refresh the export viewer every interval
    const subscription = interval$.subscribe(() => {
      relay.refetch({ id });
    });
    return function cleanup() {
      subscription.unsubscribe();
    };
  });
  return (
    <React.Fragment>
      <Grid item={true} xs={6}>
        <div style={{ height: '100%' }} className="break">
          <Typography
            variant="h4"
            gutterBottom={true}
            style={{ float: 'left' }}
          >
            {t('Exported files')}
          </Typography>
          <div style={{ float: 'left', marginTop: -17 }}>
            <Tooltip
              title={isExportPossible ? t('Generate an export') : t('No export connector available to generate an export')}
              aria-label="generate-export"
            >
              <span>
              <IconButton
                onClick={handleOpenExport}
                disabled={!isExportPossible}
                aria-haspopup="true"
                color="primary"
              >
                <FileExportOutline />
              </IconButton>
              </span>
            </Tooltip>
          </div>
          <div className="clearfix" />
          <Paper classes={{ root: classes.paper }} elevation={2}>
            {edges.length ? (
              <List>
                {edges.map((file) => (
                  <FileLine
                    key={file.node.id}
                    file={file.node}
                    dense={true}
                    disableImport={true}
                  />
                ))}
              </List>
            ) : (
              <div style={{ padding: 10 }}>{t('No file for the moment')}</div>
            )}
          </Paper>
        </div>
      </Grid>
    </React.Fragment>
  );
};

const FileExportViewerComponent = compose(
  inject18n,
  withStyles(styles),
)(FileExportViewerBase);

const FileExportViewerRefetchQuery = graphql`
  query FileExportViewerRefetchQuery($id: String!) {
    stixDomainEntity(id: $id) {
      ...FileExportViewer_entity
    }
  }
`;

const FileExportViewer = createRefetchContainer(
  FileExportViewerComponent,
  {
    entity: graphql`
      fragment FileExportViewer_entity on StixDomainEntity {
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

FileExportViewer.propTypes = {
  entity: PropTypes.object,
  handleOpenExport: PropTypes.func,
  isExportPossible: PropTypes.bool,
};

export default FileExportViewer;
