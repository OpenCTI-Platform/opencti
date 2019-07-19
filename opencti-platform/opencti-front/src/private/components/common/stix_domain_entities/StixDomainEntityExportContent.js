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
import inject18n from '../../../../components/i18n';
import { FIVE_SECONDS } from '../../../../utils/Time';
import { commitMutation } from '../../../../relay/environment';

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

export const stixDomainEntityExportContentRefreshExportMutation = graphql`
  mutation StixDomainEntityExportContentRefreshExportMutation(
    $id: ID!
    $entityType: String!
    $type: String!
    $types: [String]!
  ) {
    stixDomainEntityEdit(id: $id) {
      refreshExport(entityType: $entityType, type: $type) {
        ...StixDomainEntityExportContent_stixDomainEntity
          @arguments(types: $types)
      }
    }
  }
`;

class StixDomainEntityExportContentComponent extends Component {
  componentDidMount() {
    this.subscription = interval$.subscribe(() => {
      this.props.relay.refetch({
        id: this.props.stixDomainEntity.id,
        types: ['stix2-bundle-simple', 'stix2-bundle-full'],
      });
    });
  }

  componentWillUnmount() {
    this.subscription.unsubscribe();
  }

  handleRefreshExport(type) {
    commitMutation({
      mutation: stixDomainEntityExportContentRefreshExportMutation,
      variables: {
        id: this.props.stixDomainEntity.id,
        entityType: this.props.stixDomainEntityType,
        type,
        types: ['stix2-bundle-simple', 'stix2-bundle-full'],
      },
    });
  }

  handleDownload(content) {
    fileDownload(
      Buffer.from(content, 'base64').toString('utf-8'),
      `${this.props.stixDomainEntity.name}.stix2.json`,
    );
  }

  render() {
    const { t, nsdt, stixDomainEntity } = this.props;
    const exportStix2Simple = head(
      filter(
        n => n.export_type === 'stix2-bundle-simple',
        stixDomainEntity.exports,
      ),
    );
    const exportStix2Full = head(
      filter(
        n => n.export_type === 'stix2-bundle-full',
        stixDomainEntity.exports,
      ),
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
                onClick={this.handleRefreshExport.bind(
                  this,
                  'stix2-bundle-simple',
                )}
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
                onClick={this.handleRefreshExport.bind(
                  this,
                  'stix2-bundle-full',
                )}
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

StixDomainEntityExportContentComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  nsdt: PropTypes.func,
  stixDomainEntity: PropTypes.object,
  stixDomainEntityType: PropTypes.string,
};

export const stixDomainEntityExportContentQuery = graphql`
  query StixDomainEntityExportContentQuery($id: String!, $types: [String]!) {
    stixDomainEntity(id: $id) {
      ...StixDomainEntityExportContent_stixDomainEntity
        @arguments(types: $types)
    }
  }
`;

const StixDomainEntityExportContent = createRefetchContainer(
  StixDomainEntityExportContentComponent,
  {
    stixDomainEntity: graphql`
      fragment StixDomainEntityExportContent_stixDomainEntity on StixDomainEntity
        @argumentDefinitions(types: { type: "[String]!" }) {
        id
        name
        entity_type
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
  stixDomainEntityExportContentQuery,
);

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(StixDomainEntityExportContent);
