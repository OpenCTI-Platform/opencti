import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { Redirect } from 'react-router-dom';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../../../components/i18n';
import RemediationDetails from './RemediationDetails';
import RemediationEdition from './RemediationEdition';
import RemediationPopover from './RemediationPopover';
import RemediationDeletion from './RemediationDeletion';
import RemediationCreation from './RemediationCreation';
import StixCoreObjectOrStixCoreRelationshipLastReports from '../../../analysis/reports/StixCoreObjectOrStixCoreRelationshipLastReports';
import StixDomainObjectHeader from '../../../common/stix_domain_objects/StixDomainObjectHeader';
import CyioDomainObjectHeader from '../../../common/stix_domain_objects/CyioDomainObjectHeader';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../../utils/Security';
import CyioCoreObjectOrCyioCoreRelationshipNotes from '../../../analysis/notes/CyioCoreObjectOrCyioCoreRelationshipNotes';
import CyioDomainObjectAssetOverview from '../../../common/stix_domain_objects/CyioDomainObjectAssetOverview';
import StixCoreObjectExternalReferences from '../../../analysis/external_references/StixCoreObjectExternalReferences';
import CyioCoreObjectLatestHistory from '../../../common/stix_core_objects/CyioCoreObjectLatestHistory';
import SimpleStixObjectOrStixRelationshipStixCoreRelationships from '../../../common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

class RemediationComponent extends Component {
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
      pathname: '/dashboard/risk-assessment/risks',
      openNewCreation: true,
    });
  }

  render() {
    const {
      classes,
      remediation,
      history,
      location,
    } = this.props;
    return (
      <>
        {!this.state.displayEdit && !location.openEdit ? (
          <div className={classes.container}>
            <CyioDomainObjectHeader
              cyioDomainObject={remediation}
              history={history}
              PopoverComponent={<RemediationPopover />}
              handleDisplayEdit={this.handleDisplayEdit.bind(this)}
              handleOpenNewCreation={this.handleOpenNewCreation.bind(this)}
              OperationsComponent={<RemediationDeletion />}
            />
            <Grid
              container={true}
              spacing={3}
              classes={{ container: classes.gridContainer }}
            >
              <Grid item={true} xs={6}>
                <CyioDomainObjectAssetOverview cyioDomainObject={remediation} />
              </Grid>
              <Grid item={true} xs={6}>
                <RemediationDetails remediation={remediation} history={history}/>
              </Grid>
            </Grid>
            <Grid
              container={true}
              spacing={3}
              classes={{ container: classes.gridContainer }}
              style={{ marginTop: 25 }}
            >
              <Grid item={true} xs={6}>
                {/* <StixCoreObjectExternalReferences
                  stixCoreObjectId={remediation.id}
                /> */}
              </Grid>
              <Grid item={true} xs={6}>
                <CyioCoreObjectLatestHistory cyioCoreObjectId={remediation.id} />
              </Grid>
            </Grid>
            <CyioCoreObjectOrCyioCoreRelationshipNotes
              cyioCoreObjectOrCyioCoreRelationshipId={remediation.id}
            />
            {/* <Security needs={[KNOWLEDGE_KNUPDATE]}>
                <RemediationEdition remediationId={remediation.id} />
              </Security> */}
          </div>
        ) : (
          // <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <RemediationEdition
            open={this.state.openEdit}
            remediationId={remediation.id}
            history={history}
          />
          // </Security>
        )}
      </>
    );
  }
}

RemediationComponent.propTypes = {
  remediation: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const Remediation = createFragmentContainer(RemediationComponent, {
  remediation: graphql`
    fragment Remediation_remediation on ComputingDeviceAsset {
      id
      name
      asset_id
      asset_type
      asset_tag
      description
      version
      vendor_name
      serial_number
      release_date
      labels
      # responsible_parties
      # operational_status
      ...RemediationDetails_remediation
    }
  `,
});

export default compose(inject18n, withStyles(styles))(Remediation);
