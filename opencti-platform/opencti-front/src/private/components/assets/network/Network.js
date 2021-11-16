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
import StixDomainObjectAssetHeader from '../../common/stix_domain_objects/StixDomainObjectAssetHeader';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analysis/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import StixDomainObjectAssetOverview from '../../common/stix_domain_objects/StixDomainObjectAssetOverview';
import StixCoreObjectExternalReferences from '../../analysis/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
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
      pathname: '/dashboard/assets/network',
      openNewCreation: true,
    });
  }

  render() {
    const {
      classes,
      network,
      history,
      location,
    } = this.props;
    return (
      <>
        {!this.state.displayEdit && !location.openEdit ? (
          <div className={classes.container}>
            <StixDomainObjectAssetHeader
              stixDomainObject={network}
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
                  <StixDomainObjectAssetOverview stixDomainObject={network} />
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
                {/* <StixCoreObjectExternalReferences
              stixCoreObjectId={network.id}
            /> */}
              </Grid>
              <Grid item={true} xs={6}>
                <StixCoreObjectLatestHistory stixCoreObjectId={network.id} />
              </Grid>
            </Grid>
            <StixCoreObjectOrStixCoreRelationshipNotes
              stixCoreObjectOrStixCoreRelationshipId={network.id}
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
};

const Network = createFragmentContainer(NetworkComponent, {
  network: graphql`
    fragment Network_network on IntrusionSet {
      id
      standard_id
      x_opencti_stix_ids
      spec_version
      revoked
      confidence
      created
      modified
      created_at
      updated_at
      createdBy {
        ... on Identity {
          id
          name
          entity_type
        }
      }
      creator {
        id
        name
      }
      objectMarking {
        edges {
          node {
            id
            definition
            x_opencti_color
          }
        }
      }
      objectLabel {
        edges {
          node {
            id
            value
            color
          }
        }
      }
      name
      aliases
    }
  `,
});

export default compose(inject18n, withStyles(styles))(Network);
