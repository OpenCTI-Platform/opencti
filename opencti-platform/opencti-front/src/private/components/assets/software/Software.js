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
import SoftwareDetails from './SoftwareDetails';
import SoftwareEdition from './SoftwareEdition';
import SoftwarePopover from './SoftwarePopover';
import SoftwareDeletion from './SoftwareDeletion';
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

class SoftwareComponent extends Component {
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
      pathname: '/dashboard/assets/software',
      openNewCreation: true,
    });
  }

  render() {
    const {
      classes,
      software,
      history,
      location,
    } = this.props;
    return (
      <>
        {!this.state.displayEdit && !location.openEdit ? (
          <div className={classes.container}>
            <CyioDomainObjectHeader
              cyioDomainObject={software}
              history={history}
              PopoverComponent={<SoftwarePopover />}
              handleDisplayEdit={this.handleDisplayEdit.bind(this)}
              handleOpenNewCreation={this.handleOpenNewCreation.bind(this)}
              OperationsComponent={<SoftwareDeletion />}
            />
            <Grid
              container={true}
              spacing={3}
              classes={{ container: classes.gridContainer }}
            >
              <Grid item={true} xs={6}>
                <CyioDomainObjectAssetOverview cyioDomainObject={software} />
              </Grid>
              <Grid item={true} xs={6}>
                <SoftwareDetails software={software} />
              </Grid>
            </Grid>
            <Grid
              container={true}
              spacing={3}
              classes={{ container: classes.gridContainer }}
              style={{ marginTop: 25 }}
            >
              <Grid item={true} xs={6}>
                {/* <CyioCoreObjectExternalReferences cyioCoreObjectId={software.id} /> */}
              </Grid>
              <Grid item={true} xs={6}>
                <CyioCoreObjectLatestHistory cyioCoreObjectId={software.id} />
              </Grid>
            </Grid>
            <CyioCoreObjectOrCyioCoreRelationshipNotes
              cyioCoreObjectOrCyioCoreRelationshipId={software.id}
            />
            {/* <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <SoftwareEdition softwareId={software.id} />
        </Security> */}
          </div>
        ) : (
          // <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <SoftwareEdition
            open={this.state.openEdit}
            softwareId={software.id}
            history={history}
          />
          // </Security>
        )}
      </>
    );
  }
}

SoftwareComponent.propTypes = {
  software: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const Software = createFragmentContainer(SoftwareComponent, {
  software: graphql`
    fragment Software_software on SoftwareAsset {
      id
      name
      asset_id
      labels
      description
      version
      vendor_name
      asset_tag
      asset_type
      serial_number
      release_date
      operational_status
      ...SoftwareDetails_software
    }
  `,
});

export default compose(inject18n, withStyles(styles))(Software);
