import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { Redirect } from 'react-router-dom';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../../components/i18n';
import DeviceDetails from './DeviceDetails';
import DeviceEdition from './DeviceEdition';
import DevicePopover from './DevicePopover';
import DeviceDeletion from './DeviceDeletion';
import DeviceCreation from './DeviceCreation';
import StixCoreObjectOrStixCoreRelationshipLastReports from '../../analysis/reports/StixCoreObjectOrStixCoreRelationshipLastReports';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
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

class DeviceComponent extends Component {
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
      pathname: '/dashboard/assets/devices',
      openNewCreation: true,
    });
  }

  render() {
    const { classes, device, history } = this.props;
    return (
      <>
        {!this.state.displayEdit ? (
          <div className={classes.container}>
            <StixDomainObjectAssetHeader
              stixDomainObject={device}
              history={history}
              PopoverComponent={<DevicePopover />}
              handleDisplayEdit={this.handleDisplayEdit.bind(this)}
              handleOpenNewCreation={this.handleOpenNewCreation.bind(this)}
              OperationsComponent={<DeviceDeletion />}
            />
            <Grid
              container={true}
              spacing={3}
              classes={{ container: classes.gridContainer }}
            >
              <Grid item={true} xs={6}>
                <StixDomainObjectAssetOverview stixDomainObject={device} />
              </Grid>
              <Grid item={true} xs={6}>
                <DeviceDetails device={device} />
              </Grid>
            </Grid>
            {/* <Grid
                container={true}
                spacing={3}
                classes={{ container: classes.gridContainer }}
                style={{ marginTop: 25 }}
              >
                <Grid item={true} xs={6}>
                  <SimpleStixObjectOrStixRelationshipStixCoreRelationships
                    stixObjectOrStixRelationshipId={device.id}
            stixObjectOrStixRelationshipLink={`/dashboard/assets/devices/${device.id}/knowledge`}
                  />
                </Grid>
                <Grid item={true} xs={6}>
                  <StixCoreObjectOrStixCoreRelationshipLastReports
                    stixCoreObjectOrStixCoreRelationshipId={device.id}
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
                <StixCoreObjectExternalReferences
                  stixCoreObjectId={device.id}
                />
              </Grid>
              <Grid item={true} xs={6}>
                <StixCoreObjectLatestHistory stixCoreObjectId={device.id} />
              </Grid>
            </Grid>
            <StixCoreObjectOrStixCoreRelationshipNotes
              stixCoreObjectOrStixCoreRelationshipId={device.id}
            />
            {/* <Security needs={[KNOWLEDGE_KNUPDATE]}>
                <DeviceEdition deviceId={device.id} />
              </Security> */}
          </div>
        ) : (
          <Security needs={[KNOWLEDGE_KNUPDATE]}>
            <DeviceEdition
              open={this.state.openEdit}
              deviceId={device.id}
              history={history}
            />
          </Security>
        )}
      </>
    );
  }
}

DeviceComponent.propTypes = {
  device: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const Device = createFragmentContainer(DeviceComponent, {
  device: graphql`
    fragment Device_device on ThreatActor {
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

export default compose(inject18n, withStyles(styles))(Device);
