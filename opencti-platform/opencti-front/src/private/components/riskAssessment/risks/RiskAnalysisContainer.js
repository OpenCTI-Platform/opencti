/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import PropTypes from 'prop-types';
import {
  compose,
  pipe,
  pathOr,
  mergeAll,
} from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../../components/i18n';
import RiskAnalysisThreats from './RiskAnalysisThreats';
import RiskAnalysisEdition from './RiskAnalysisEdition';
import RiskPopover from './RiskPopover';
import RiskDeletion from './RiskDeletion';
import CyioDomainObjectHeader from '../../common/stix_domain_objects/CyioDomainObjectHeader';
import CyioCoreObjectOrCyioCoreRelationshipNotes from '../../analysis/notes/CyioCoreObjectOrCyioCoreRelationshipNotes';
import RiskAnalysisCharacterization from './RiskAnalysisCharacterization';
import CyioCoreObjectExternalReferences from '../../analysis/external_references/CyioCoreObjectExternalReferences';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    // padding: '24px 24px 32px 24px',
    borderRadius: 6,
  },
});

class RiskAnalysisContainerComponent extends Component {
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
      refreshQuery,
      location,
    } = this.props;
    const riskCharacterizations = pipe(
      pathOr([], ['characterizations']),
      mergeAll,
    )(risk);
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
              handleOpenNewCreation={this.handleOpenNewCreation.bind(this)}
            // handleDisplayEdit={this.handleDisplayEdit.bind(this)}
            />
            <Grid
              container={true}
              spacing={3}
              classes={{ container: classes.gridContainer }}
            >
              <Grid item={true} xs={6}>
                <RiskAnalysisCharacterization
                  risk={risk}
                />
              </Grid>
              <Grid item={true} xs={6}>
                <RiskAnalysisThreats risk={risk} history={history} />
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
                  disableAdd={true}
                  typename={riskCharacterizations.__typename}
                  externalReferences={riskCharacterizations.links}
                  fieldName='links'
                  cyioCoreObjectId={riskCharacterizations.id}
                  refreshQuery={refreshQuery}
                  removeIcon={true}
                />
              </Grid>
              <Grid item={true} xs={6}>
                {/* <StixCoreObjectLatestHistory cyioCoreObjectId={risk.id} /> */}
                <CyioCoreObjectOrCyioCoreRelationshipNotes
                  typename={riskCharacterizations.__typename}
                  disableAdd={true}
                  notes={riskCharacterizations.remarks}
                  cyioCoreObjectOrCyioCoreRelationshipId={riskCharacterizations.id}
                  marginTop='0px'
                  fieldName='remarks'
                  refreshQuery={refreshQuery}
                  removeIcon={true}
                />
              </Grid>
            </Grid>
            {/* <Security needs={[KNOWLEDGE_KNUPDATE]}>
                <RiskEdition riskId={risk.id} />
              </Security> */}
          </div>
        ) : (
          // <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <RiskAnalysisEdition
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

RiskAnalysisContainerComponent.propTypes = {
  risk: PropTypes.object,
  riskId: PropTypes.string,
  refreshQuery: PropTypes.func,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const RiskAnalysisContainerFragment = createFragmentContainer(
  RiskAnalysisContainerComponent,
  {
    risk: graphql`
      fragment RiskAnalysisContainer_risk on Risk {
        __typename
        id
        name
        characterizations {
          __typename
          id
          entity_type
          created
          modified
          origins {
            # source of detection
            id
            origin_actors {
              actor_type
              actor_ref {
                ... on AssessmentPlatform {
                  id
                  name # Source
                }
                ... on Component {
                  id
                  component_type
                  name
                }
                ... on OscalParty {
                  id
                  party_type
                  name # Source
                }
              }
            }
          }
          facets {
            id
            entity_type
            risk_state
            source_system
            facet_name
            facet_value
          }
          links {
            id
            source_name
            external_id
            url
          }
          remarks {
            id
            created
            modified
            abstract
            content
            authors
          }
        }
        # threats {
        # }
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(RiskAnalysisContainerFragment);
