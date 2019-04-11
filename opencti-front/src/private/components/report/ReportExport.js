import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { interval } from 'rxjs';
import { compose, filter, head } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import fileDownload from 'js-file-download';
import { createRefetchContainer } from 'react-relay';
import { withStyles } from '@material-ui/core/styles';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import CircularProgress from '@material-ui/core/CircularProgress';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import IconButton from '@material-ui/core/IconButton';
import { Refresh } from '@material-ui/icons';
import { FileDownload } from 'mdi-material-ui';
import inject18n from '../../../components/i18n';
import { FIVE_SECONDS } from '../../../utils/Time';
import { commitMutation } from '../../../relay/environment';

const interval$ = interval(FIVE_SECONDS);

const styles = () => ({
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
  },
  importButton: {
    position: 'absolute',
    top: 30,
    right: 30,
  },
});

export const reportMutationRefreshExport = graphql`
  mutation ReportExportRefreshExportMutation(
    $id: ID!
    $type: String!
    $types: [String]!
  ) {
    reportEdit(id: $id) {
      refreshExport(type: $type) {
        ...ReportExport_report @arguments(types: $types)
      }
    }
  }
`;

class ReportExportComponent extends Component {
  componentDidMount() {
    this.subscription = interval$.subscribe(() => {
      this.props.relay.refetch({
        id: this.props.report.id,
        types: ['stix2.simple', 'stix2.full'],
      });
    });
  }

  componentWillUnmount() {
    this.subscription.unsubscribe();
  }

  handleRefreshExport(type) {
    commitMutation({
      mutation: reportMutationRefreshExport,
      variables: {
        id: this.props.report.id,
        type,
        types: ['stix2.simple', 'stix2.full'],
      },
    });
  }

  handleDownload(content) {
    fileDownload(
      Buffer.from(content, 'base64').toString('utf-8'),
      `${this.props.report.name}.stix2.json`,
    );
  }

  render() {
    const { t, nsdt, report } = this.props;
    const exportStix2Simple = head(
      filter(n => n.export_type === 'stix2.simple', report.exports),
    );
    const exportStix2Full = head(
      filter(n => n.export_type === 'stix2.full', report.exports),
    );

    return (
      <div>
        <List>
          <ListItem
            dense={true}
            divider={true}
            button={exportStix2Simple && exportStix2Simple.object_status === 1}
            onClick={
              exportStix2Simple && exportStix2Simple.object_status === 1
                ? this.handleDownload.bind(this, exportStix2Simple.raw_data)
                : undefined
            }
          >
            <ListItemIcon>
              {exportStix2Simple && exportStix2Simple.object_status === 0 ? (
                <CircularProgress
                  color="primary"
                  size={17}
                  style={{ marginRight: 8 }}
                />
              ) : (
                <FileDownload color="primary" />
              )}
            </ListItemIcon>
            <ListItemText
              primary={t('STIX2 - Simple export')}
              secondary={
                !exportStix2Simple
                  ? t('Never generated')
                  : exportStix2Simple.object_status === 0
                    ? t('Generation in progress...')
                    : `${t('Generated the')} ${nsdt(
                      exportStix2Simple.created_at,
                    )}`
              }
            />
            <ListItemSecondaryAction>
              <IconButton
                color="secondary"
                onClick={this.handleRefreshExport.bind(this, 'stix2.simple')}
              >
                <Refresh />
              </IconButton>
            </ListItemSecondaryAction>
          </ListItem>
          <ListItem
            dense={true}
            divider={true}
            button={exportStix2Full && exportStix2Full.object_status === 1}
            onClick={
              exportStix2Full && exportStix2Full.object_status === 1
                ? this.handleDownload.bind(this, exportStix2Full.raw_data)
                : undefined
            }
          >
            <ListItemIcon>
              {exportStix2Full && exportStix2Full.object_status === 0 ? (
                <CircularProgress
                  color="primary"
                  size={17}
                  style={{ marginRight: 8 }}
                />
              ) : (
                <FileDownload color="primary" />
              )}
            </ListItemIcon>
            <ListItemText
              primary={t('STIX2 - Full export')}
              secondary={
                !exportStix2Full
                  ? t('Never generated')
                  : exportStix2Full.object_status === 0
                    ? t('Generation in progress...')
                    : `${t('Generated the')} ${nsdt(exportStix2Full.created_at)}`
              }
            />
            <ListItemSecondaryAction>
              <IconButton
                color="secondary"
                onClick={this.handleRefreshExport.bind(this, 'stix2.full')}
              >
                <Refresh />
              </IconButton>
            </ListItemSecondaryAction>
          </ListItem>
        </List>
      </div>
    );
  }
}

ReportExportComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  nsdt: PropTypes.func,
  report: PropTypes.object,
  editUsers: PropTypes.array,
  me: PropTypes.object,
};

export const reportExportQuery = graphql`
  query ReportExportQuery($id: String!, $types: [String]!) {
    report(id: $id) {
      ...ReportExport_report @arguments(types: $types)
    }
  }
`;

const ReportExport = createRefetchContainer(
  ReportExportComponent,
  {
    report: graphql`
      fragment ReportExport_report on Report
        @argumentDefinitions(types: { type: "[String]!" }) {
        id
        name
        exports(types: $types) {
          id
          export_type
          raw_data
          object_status
          created_at
        }
      }
    `,
  },
  reportExportQuery,
);

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(ReportExport);
