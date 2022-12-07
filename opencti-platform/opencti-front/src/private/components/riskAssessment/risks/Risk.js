/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import PropTypes from 'prop-types';
import * as R from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../../components/i18n';
import RiskDetails from './RiskDetails';
import RiskEdition from './RiskEdition';
import RiskPopover from './RiskPopover';
import RiskDeletion from './RiskDeletion';
import CyioDomainObjectHeader from '../../common/stix_domain_objects/CyioDomainObjectHeader';
import CyioCoreObjectOrCyioCoreRelationshipNotes from '../../analysis/notes/CyioCoreObjectOrCyioCoreRelationshipNotes';
import RiskOverview from './RiskOverview';
import CyioCoreObjectExternalReferences from '../../analysis/external_references/CyioCoreObjectExternalReferences';
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
      pathname: '/activities/risk_assessment/risks',
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
    return (
      <>
        {!this.state.displayEdit && !location.openEdit ? (
          <div className={classes.container}>
            <CyioDomainObjectHeader
              disabled={true}
              name={risk.name}
              history={history}
              cyioDomainObject={risk}
              PopoverComponent={<RiskPopover />}
              OperationsComponent={<RiskDeletion />}
              goBack='/activities/risk_assessment/risks'
              handleDisplayEdit={this.handleDisplayEdit.bind(this)}
              handleOpenNewCreation={this.handleOpenNewCreation.bind(this)}
            />
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
                <RiskObservation risk={risk} history={history} />
              </Grid>
            </Grid>
            <Grid
              container={true}
              spacing={3}
              classes={{ container: classes.gridContainer }}
              style={{ marginTop: 25, marginBottom: 30 }}
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
      }
      ...RiskOverview_risk
      ...RiskDetails_risk
    }
  `,
});

export default R.compose(inject18n, withStyles(styles))(Risk);
