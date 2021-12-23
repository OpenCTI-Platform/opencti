import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { Redirect } from 'react-router-dom';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../../components/i18n';
import RiskDetails from './RiskDetails';
import RiskEdition from './RiskEdition';
import RiskPopover from './RiskPopover';
import RiskDeletion from './RiskDeletion';
import RiskCreation from './RiskCreation';
import StixCoreObjectOrStixCoreRelationshipLastReports from '../../analysis/reports/StixCoreObjectOrStixCoreRelationshipLastReports';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import CyioDomainObjectHeader from '../../common/stix_domain_objects/CyioDomainObjectHeader';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import CyioCoreObjectOrCyioCoreRelationshipNotes from '../../analysis/notes/CyioCoreObjectOrCyioCoreRelationshipNotes';
import RiskOverview from './RiskOverview';
import CyioCoreObjectExternalReferences from '../../analysis/external_references/CyioCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import SimpleStixObjectOrStixRelationshipStixCoreRelationships from '../../common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships';
import TopMenuRisk from '../../nav/TopMenuRisk';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

class RiskComponent extends Component {
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
      risk,
      history,
      location,
    } = this.props;
    console.log('RiskMainContainer', risk);
    return (
      <>
        {!this.state.displayEdit && !location.openEdit ? (
          <div className={classes.container}>
            <CyioDomainObjectHeader
              cyioDomainObject={risk}
              history={history}
              PopoverComponent={<RiskPopover />}
              handleDisplayEdit={this.handleDisplayEdit.bind(this)}
              handleOpenNewCreation={this.handleOpenNewCreation.bind(this)}
              OperationsComponent={<RiskDeletion />}
            />
            <TopMenuRisk />
            <Grid
              container={true}
              spacing={3}
              classes={{ container: classes.gridContainer }}
            >
              <Grid item={true} xs={6}>
                <RiskOverview risk={risk} />
              </Grid>
              <Grid item={true} xs={6}>
                <RiskDetails risk={risk} history={history} />
              </Grid>
            </Grid>
            <Grid
              container={true}
              spacing={3}
              classes={{ container: classes.gridContainer }}
              style={{ marginTop: 25 }}
            >
              <Grid item={true} xs={6}>
                <CyioCoreObjectExternalReferences
                // cyioCoreObjectId={risk.id}
                />
              </Grid>
              <Grid item={true} xs={6}>
                {/* <StixCoreObjectLatestHistory cyioCoreObjectId={risk.id} /> */}
                <CyioCoreObjectOrCyioCoreRelationshipNotes
                  cyioCoreObjectOrCyioCoreRelationshipId={risk.id}
                  marginTop='0px'
                />
              </Grid>
            </Grid>
            {/* <Security needs={[KNOWLEDGE_KNUPDATE]}>
                <RiskEdition riskId={risk.id} />
              </Security> */}
          </div>
        ) : (
          // <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <RiskEdition
            open={this.state.openEdit}
            riskId={risk.id}
            history={history}
          />
          // </Security>
        )}
      </>
    );
  }
}

RiskComponent.propTypes = {
  risk: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const Risk = createFragmentContainer(RiskComponent, {
  risk: graphql`
    fragment Risk_risk on POAMItem {
      id
      name
      ...RiskOverview_risk
      ...RiskDetails_risk
    }
  `,
});

export default compose(inject18n, withStyles(styles))(Risk);
