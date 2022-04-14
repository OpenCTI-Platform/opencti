/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import PropTypes from 'prop-types';
import * as R from 'ramda';
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
import RiskObservation from './RiskObservation';

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
      pathname: '/activities/risk assessment/risks',
      openNewCreation: true,
    });
  }

  render() {
    const {
      classes,
      risk,
      history,
      location,
      refreshQuery,
    } = this.props;
    console.log('RiskMainContainer', risk);
    return (
      <>
        {!this.state.displayEdit && !location.openEdit ? (
          <div className={classes.container}>
            <CyioDomainObjectHeader
              cyioDomainObject={risk}
              history={history}
              disabled={true}
              PopoverComponent={<RiskPopover />}
              handleDisplayEdit={this.handleDisplayEdit.bind(this)}
              handleOpenNewCreation={this.handleOpenNewCreation.bind(this)}
              OperationsComponent={<RiskDeletion />}
            />
            <TopMenuRisk risk={risk.name}/>
            <Grid
              container={true}
              spacing={3}
              classes={{ container: classes.gridContainer }}
            >
              <Grid item={true} xs={6}>
                <RiskOverview risk={risk} refreshQuery={refreshQuery} />
              </Grid>
              <Grid item={true} xs={6}>
                <RiskDetails risk={risk} history={history} />
                <RiskObservation risk={risk}/>
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
                typename={risk.__typename}
                fieldName='links'
                externalReferences={risk.links}
                cyioCoreObjectId={risk.id}
                refreshQuery={refreshQuery}
                />
              </Grid>
              <Grid item={true} xs={6}>
                {/* <StixCoreObjectLatestHistory cyioCoreObjectId={risk.id} /> */}
                <CyioCoreObjectOrCyioCoreRelationshipNotes
                  typename={risk.__typename}
                  fieldName='remarks'
                  notes={risk.remarks}
                  cyioCoreObjectOrCyioCoreRelationshipId={risk.id}
                  marginTop='0px'
                  refreshQuery={refreshQuery}
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
  refreshQuery: PropTypes.func,
};

const Risk = createFragmentContainer(RiskComponent, {
  risk: graphql`
    fragment Risk_risk on Risk {
      __typename
      id
      name
      labels {
        __typename
        id
        name
        color
        entity_type
        description
      }
      links {
        __typename
        id
        # created
        # modified
        external_id     # external id
        source_name     # Title
        description     # description
        url             # URL
        media_type      # Media Type
        entity_type
      }
      remarks {
        __typename
        id
        abstract
        content
        authors
        entity_type
        labels {
          __typename
          id
          name
          color
          entity_type
          description
        }
      }
      ...RiskOverview_risk
      ...RiskDetails_risk
    }
  `,
});

export default R.compose(inject18n, withStyles(styles))(Risk);
