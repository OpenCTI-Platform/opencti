import React, { Component } from 'react';
import PropTypes from 'prop-types';
import * as R from 'ramda';
import { interval } from 'rxjs';
import { withStyles } from '@material-ui/core/styles';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemText from '@material-ui/core/ListItemText';
import Drawer from '@material-ui/core/Drawer';
import { createRefetchContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import ListSubheader from '@material-ui/core/ListSubheader';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import { FileOutline } from 'mdi-material-ui';
import { propOr } from 'ramda';
import moment from 'moment';
import { FIVE_SECONDS } from '../../../../utils/Time';
import inject18n from '../../../../components/i18n';

const interval$ = interval(FIVE_SECONDS);

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: 250,
    padding: '0 0 20px 0',
    position: 'fixed',
    zIndex: 1100,
    backgroundColor: theme.palette.navAlt.background,
  },
  drawerPaperExports: {
    minHeight: '100vh',
    width: 250,
    right: 310,
    padding: '0 0 20px 0',
    backgroundColor: theme.palette.navAlt.background,
    transition: theme.transitions.create('right', {
      easing: theme.transitions.easing.easeOut,
      duration: theme.transitions.duration.leavingScreen,
    }),
  },
  listIcon: {
    marginRight: 0,
  },
  itemField: {
    padding: '0 15px 0 15px',
  },
  toolbar: theme.mixins.toolbar,
});

class ReportContentFilesComponent extends Component {
  componentDidMount() {
    this.subscription = interval$.subscribe(() => {
      this.props.relay.refetch();
    });
  }

  render() {
    const {
      classes, t, handleSelectFile, report, fld, currentFile,
    } = this.props;
    const sortByLastModified = R.sortBy(R.prop('name'));
    const importFiles = R.map(
      (n) => n.node,
      R.pathOr([], ['importFiles', 'edges'], report),
    );
    const externalReferencesFiles = R.pipe(
      R.map((n) => n.node.importFiles.edges),
      R.flatten,
      R.map((n) => n.node),
    )(R.pathOr([], ['externalReferences', 'edges'], report));
    const files = R.pipe(
      R.filter((n) => [
        'text/plain',
        'text/html',
        'text/markdown',
        'application/pdf',
      ].includes(n.metaData.mimetype)),
      sortByLastModified,
    )([...importFiles, ...externalReferencesFiles]);
    return (
      <Drawer
        variant="permanent"
        anchor="right"
        classes={{ paper: classes.drawerPaper }}
      >
        <div className={classes.toolbar} />
        <List
          subheader={
            <ListSubheader component="div">{t('Files')}</ListSubheader>
          }
        >
          {files.map((file) => (
            <ListItem
              key={file.id}
              dense={true}
              button={true}
              selected={file.id === currentFile.id}
              onClick={handleSelectFile.bind(this, file)}
              classes={{ root: classes.item }}
            >
              <ListItemIcon>
                <FileOutline color="primary" />
              </ListItemIcon>
              <ListItemText
                primary={file.name}
                secondary={fld(propOr(moment(), 'lastModified', file))}
              />
            </ListItem>
          ))}
        </List>
      </Drawer>
    );
  }
}

export const reportContentFilesRefetchQuery = graphql`
  query ReportContentFilesRefetchQuery($id: String!) {
    report(id: $id) {
      ...ReportContentFiles_report
    }
  }
`;

const ReportContentFiles = createRefetchContainer(
  ReportContentFilesComponent,
  {
    report: graphql`
      fragment ReportContentFiles_report on Report {
        id
        importFiles(first: 1000) {
          edges {
            node {
              id
              name
              uploadStatus
              lastModified
              lastModifiedSinceMin
              metaData {
                mimetype
                list_filters
                messages {
                  timestamp
                  message
                }
                errors {
                  timestamp
                  message
                }
              }
              metaData {
                mimetype
              }
            }
          }
        }
        externalReferences {
          edges {
            node {
              source_name
              url
              description
              importFiles(first: 1000) {
                edges {
                  node {
                    id
                    name
                    uploadStatus
                    lastModified
                    lastModifiedSinceMin
                    metaData {
                      mimetype
                      list_filters
                      messages {
                        timestamp
                        message
                      }
                      errors {
                        timestamp
                        message
                      }
                    }
                    metaData {
                      mimetype
                    }
                  }
                }
              }
            }
          }
        }
      }
    `,
  },
  reportContentFilesRefetchQuery,
);

ReportContentFiles.propTypes = {
  reportId: PropTypes.object,
  report: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  handleSelectFile: PropTypes.func,
  currentFile: PropTypes.object,
};

export default R.compose(inject18n, withStyles(styles))(ReportContentFiles);
