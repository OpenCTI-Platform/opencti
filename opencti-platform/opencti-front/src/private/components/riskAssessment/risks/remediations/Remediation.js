/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../../../components/i18n';
import RiskPopover from '../RiskPopover';
import RemediationDeletion from './RemediationDeletion';
import CyioDomainObjectHeader from '../../../common/stix_domain_objects/CyioDomainObjectHeader';
import CyioCoreObjectOrCyioCoreRelationshipNotes from '../../../analysis/notes/CyioCoreObjectOrCyioCoreRelationshipNotes';
import RemediationGeneralOverview from './RemediationGeneralOverview';
import CyioCoreObjectExternalReferences from '../../../analysis/external_references/CyioCoreObjectExternalReferences';
import RequiredResources from './RequiredResources';
import RelatedTasks from './RelatedTasks';
import RemediationDetailsPopover from './RemediationDetailsPopover';
import RemediationCreation from './RemediationCreation';

const styles = () => ({
  container: {
    margin: '0 0 30px 0',
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
      openCreation: false,
    };
  }

  handleDisplayEdit() {
    this.setState({ displayEdit: !this.state.displayEdit });
  }

  handleCloseEdit() {
    this.setState({ displayEdit: false });
  }

  handleOpen() {
    this.setState({ openCreation: true });
  }

  handleClose() {
    this.setState({ openCreation: false })
  }

  handleOpenCreation() {
    this.setState({ openCreation: false });
  }

  render() {
    const {
      classes,
      remediation,
      refreshQuery,
      risk,
      riskId,
      history,
      location,
    } = this.props;
    return (
      <>
        <div className={classes.container}>
          <CyioDomainObjectHeader
            history={history}
            disablePopover={false}
            name={remediation.name}
            cyioDomainObject={remediation}
            PopoverComponent={<RiskPopover />}
            handleOpenNewCreation={this.handleOpen.bind(this)}
            handleDisplayEdit={this.handleDisplayEdit.bind(this)}
            OperationsComponent={<RemediationDeletion riskId={riskId} />}
            goBack={`/activities/risk_assessment/risks/${risk.id}/remediation`}
          />
          <Grid
            container={true}
            spacing={3}
            classes={{ container: classes.gridContainer }}
          >
            <Grid item={true} xs={12}>
              <RemediationGeneralOverview
                remediation={remediation}
                risk={risk}
              />
            </Grid>
            {/* <Grid item={true} xs={6}>
                <RemediationGeneralDetails remediation={remediation} />
              </Grid> */}
          </Grid>
          <Grid
            container={true}
            spacing={3}
            classes={{ container: classes.gridContainer }}
            style={{ marginTop: 25 }}
          >
            <Grid item={true} xs={6}>
              <RequiredResources history={history} remediationId={remediation.id} />
            </Grid>
            <Grid item={true} xs={6}>
              <RelatedTasks
                toType='OscalTask'
                fromType='RiskResponse'
                history={history}
                remediationId={remediation.id}
              />
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
                typename={remediation.__typename}
                fieldName='links'
                externalReferences={remediation.links}
                cyioCoreObjectId={remediation.id}
                refreshQuery={refreshQuery}
              />
            </Grid>
            <Grid item={true} xs={6}>
              <CyioCoreObjectOrCyioCoreRelationshipNotes
                typename={remediation.__typename}
                notes={remediation.remarks}
                fieldName='remarks'
                cyioCoreObjectOrCyioCoreRelationshipId={remediation.id}
                marginTop='0px'
                refreshQuery={refreshQuery}
              />
            </Grid>
          </Grid>
          {/* <Security needs={[KNOWLEDGE_KNUPDATE]}>
                <RemediationEdition riskId={remediation.id} />
              </Security> */}
          <RemediationDetailsPopover
            displayEdit={this.state.displayEdit}
            handleDisplayEdit={this.handleDisplayEdit.bind(this)}
            remediation={remediation}
            history={history}
            cyioCoreRelationshipId={remediation.id}
            risk={risk}
            riskId={riskId}
            handleCloseEdit={this.handleCloseEdit.bind(this)}
          />
          {this.state.openCreation
            && <RemediationCreation
              remediationId={remediation.id}
              riskId={riskId}
              history={history}
              openCreation={this.state.openCreation}
              handleOpenCreation={this.handleOpenCreation.bind(this)}
              handleCreation={this.handleOpen.bind(this)}
              refreshQuery={refreshQuery}
              location={location}
            />
          }
        </div>
        {/* <RemediationEdition
            open={this.state.openEdit}
            riskId={riskId}
            remediationId={remediation.id}
            history={history}
            remediation={remediation}
          /> */}
      </>
    );
  }
}

RemediationComponent.propTypes = {
  riskId: PropTypes.string,
  remediation: PropTypes.object,
  classes: PropTypes.object,
  risk: PropTypes.object,
  t: PropTypes.func,
  refreshQuery: PropTypes.func,
  location: PropTypes.object,
};

const Remediation = createFragmentContainer(RemediationComponent, {
  remediation: graphql`
    fragment Remediation_remediation on RiskResponse {
      __typename
      id
      name
      description
      modified
      created
      lifecycle
      response_type
      origins{            # source of detection
        id
        origin_actors {
          actor_type
          actor_ref {
            ... on AssessmentPlatform {
              id
              name          # Source
            }
            ... on Component {
              id
              component_type
              name
            }
            ... on OscalParty {
            id
            party_type
            name            # Source
            }
          }
        }
      }
      links {
        __typename
        id
        # created
        # modified
        external_id
        source_name
        description
        url
        media_type
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
      ...RemediationGeneralOverview_remediation
      # ...RemediationGeneralDetails_remediation
    }
  `,
});

export default compose(inject18n, withStyles(styles))(Remediation);
