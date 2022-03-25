/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../../components/i18n';
import NetworkDetails from './NetworkDetails';
import NetworkEdition from './NetworkEdition';
import NetworkPopover from './NetworkPopover';
import NetworkDeletion from './NetworkDeletion';
import StixCoreObjectOrStixCoreRelationshipLastReports from '../../analysis/reports/StixCoreObjectOrStixCoreRelationshipLastReports';
import CyioDomainObjectHeader from '../../common/stix_domain_objects/CyioDomainObjectHeader';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import CyioCoreObjectOrCyioCoreRelationshipNotes from '../../analysis/notes/CyioCoreObjectOrCyioCoreRelationshipNotes';
import CyioDomainObjectAssetOverview from '../../common/stix_domain_objects/CyioDomainObjectAssetOverview';
import CyioCoreObjectExternalReferences from '../../analysis/external_references/CyioCoreObjectExternalReferences';
import CyioCoreObjectLatestHistory from '../../common/stix_core_objects/CyioCoreObjectLatestHistory';
import SimpleStixObjectOrStixRelationshipStixCoreRelationships from '../../common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

class NetworkComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      displayEdit: false,
    };
  }

  handleDisplayEdit() {
    this.setState({ displayEdit: !this.state.displayEdit });
  }

  handleOpenNewCreation() {
    this.props.history.push({
      pathname: '/defender HQ/assets/network',
      openNewCreation: true,
    });
  }

  render() {
    const {
      classes,
      network,
      history,
      location,
      refreshQuery,
    } = this.props;
    return (
      <>
        {!this.state.displayEdit && !location.openEdit ? (
          <div className={classes.container}>
            <CyioDomainObjectHeader
              cyioDomainObject={network}
              history={history}
              PopoverComponent={<NetworkPopover />}
              handleDisplayEdit={this.handleDisplayEdit.bind(this)}
              handleOpenNewCreation={this.handleOpenNewCreation.bind(this)}
              OperationsComponent={<NetworkDeletion />}
            />
            <Grid
              container={true}
              spacing={3}
              classes={{ container: classes.gridContainer }}
            >
              <>
                <Grid item={true} xs={6}>
                  <CyioDomainObjectAssetOverview refreshQuery={refreshQuery} cyioDomainObject={network} />
                </Grid>
                <Grid item={true} xs={6}>
                  <NetworkDetails network={network} />
                </Grid>
              </>
            </Grid>
            <Grid
              container={true}
              spacing={3}
              classes={{ container: classes.gridContainer }}
              style={{ marginTop: 25 }}
            >
              <Grid item={true} xs={6}>
                <CyioCoreObjectExternalReferences
                  externalReferences={network.external_references}
                  cyioCoreObjectId={network.id}
                  refreshQuery={refreshQuery}
                  typename={network.__typename}
                />
              </Grid>
              <Grid item={true} xs={6}>
                <CyioCoreObjectLatestHistory cyioCoreObjectId={network.id} />
              </Grid>
            </Grid>
            <CyioCoreObjectOrCyioCoreRelationshipNotes
              notes={network.notes}
              refreshQuery={refreshQuery}
              typename={network.__typename}
              cyioCoreObjectOrCyioCoreRelationshipId={network.id}
            />
            {/* <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <NetworkEdition networkId={network.id} />
        </Security> */}
          </div>
        ) : (
          // <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <NetworkEdition
            open={this.state.openEdit}
            networkId={network.id}
            history={history}
          />
          // </Security>
        )}
      </>
    );
  }
}

NetworkComponent.propTypes = {
  network: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  refreshQery: PropTypes.func,
};

const Network = createFragmentContainer(NetworkComponent, {
  network: graphql`
    fragment Network_network on NetworkAsset {
      __typename
      id
      name
      asset_tag
      asset_type
      asset_id
      serial_number
      labels {
        __typename
        id
        name
        color
        entity_type
        description
      }
      external_references {
        __typename
        id
        source_name
        description
        entity_type
        url
        hashes {
          value
        }
        external_id
      }
      notes {
        __typename
        id
        # created
        # modified
        entity_type
        labels {
          __typename
          id
          name
          color
          entity_type
          description
        }
        abstract
        content
        authors
      }
      description
      release_date
      vendor_name
      operational_status
      version
      ...NetworkDetails_network
    }
  `,
});

export default compose(inject18n, withStyles(styles))(Network);
