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
import NetworkOperations from './NetworkOperations';
import StixCoreObjectOrStixCoreRelationshipLastReports from '../../analysis/reports/StixCoreObjectOrStixCoreRelationshipLastReports';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analysis/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
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
      openEdit: false,
    };
  }

  handleToggleEdit() {
    this.setState({ openEdit: !this.state.openEdit });
  }

  render() {
    const { classes, network, history } = this.props;
    return (
      <div className={classes.container}>
        <StixDomainObjectHeader
          openEdit={() => this.setState({ openEdit: !this.state.openEdit })}
          stixDomainObject={network}
          history={history}
          PopoverComponent={<NetworkPopover />}
          handleToggleEdit={this.handleToggleEdit.bind(this)}
          OperationsComponent={<NetworkOperations />}
        />
          <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          {this.state.openEdit ? (
              <Security needs={[KNOWLEDGE_KNUPDATE]}>
                <NetworkEdition
                  open={this.state.openEdit}
                  networkId={network.id}
                />
              </Security>
          ) : (
            <>
              <Grid item={true} xs={6}>
                <StixDomainObjectOverview stixDomainObject={network} />
              </Grid>
              <Grid item={true} xs={6}>
                <NetworkDetails network={network} />
              </Grid>
            </>
          )}
        </Grid>
        {/* <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 25 }}
        >
          <Grid item={true} xs={6}>
            <SimpleStixObjectOrStixRelationshipStixCoreRelationships
              stixObjectOrStixRelationshipId={network.id}
              stixObjectOrStixRelationshipLink={`/dashboard/assets/network/${network.id}/knowledge`}
            />
          </Grid>
          <Grid item={true} xs={6}>
            <StixCoreObjectOrStixCoreRelationshipLastReports
              stixCoreObjectOrStixCoreRelationshipId={network.id}
            />
          </Grid>
        </Grid> */}
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
