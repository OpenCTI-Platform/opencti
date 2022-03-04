/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { QueryRenderer as QR, commitMutation as CM } from 'react-relay';
import { Redirect } from 'react-router-dom';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemText from '@material-ui/core/ListItemText';
import Skeleton from '@material-ui/lab/Skeleton';
import environmentDarkLight from '../../../../relay/environmentDarkLight';
import inject18n from '../../../../components/i18n';
import RiskAnalysisThreats from './RiskAnalysisThreats';
import RiskAnalysisEdition from './RiskAnalysisEdition';
import RiskPopover from './RiskPopover';
import RiskDeletion from './RiskDeletion';
import RiskCreation from './RiskCreation';
import StixCoreObjectOrStixCoreRelationshipLastReports from '../../analysis/reports/StixCoreObjectOrStixCoreRelationshipLastReports';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import CyioDomainObjectHeader from '../../common/stix_domain_objects/CyioDomainObjectHeader';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import CyioCoreObjectOrCyioCoreRelationshipNotes from '../../analysis/notes/CyioCoreObjectOrCyioCoreRelationshipNotes';
import RiskAnalysisCharacterization from './RiskAnalysisCharacterization';
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
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    // padding: '24px 24px 32px 24px',
    borderRadius: 6,
  },
});

export const riskAnalysisContainerQuery = graphql`
  query RiskAnalysisContainerQuery($id: ID!) {
    risk(id: $id) {
      __typename
      id
      links {
        __typename
        id
        created
        modified
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
      ...RiskAnalysisCharacterization_risk
    }
  }
`;

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
      pathname: '/dashboard/risk-assessment/risks',
      openNewCreation: true,
    });
  }

  render() {
    const {
      classes,
      risk,
      history,
      t,
      riskId,
      location,
    } = this.props;
    return (
      <>
        {!this.state.displayEdit && !location.openEdit ? (
          <div className={classes.container}>
            <CyioDomainObjectHeader
              cyioDomainObject={risk}
              history={history}
              disabled={true}
              PopoverComponent={<RiskPopover />}
              // handleDisplayEdit={this.handleDisplayEdit.bind(this)}
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
                <QR
                  environment={environmentDarkLight}
                  query={riskAnalysisContainerQuery}
                  variables={{ id: riskId }}
                  render={({ error, props }) => {
                    console.log('RiskAnalysisCharacterizationProps', props);
                    if (props) {
                      return (
                        <RiskAnalysisCharacterization
                          risk={props.risk}
                        />
                      );
                    }
                    return (
                      <div style={{ height: '100%' }}>
                        <Typography
                          variant="h4"
                          gutterBottom={true}
                        >
                          {t('Characterization')}
                        </Typography>
                        <div className="clearfix" />
                        <Paper className={classes.paper} elevation={2}>
                          <List>
                            {Array.from(Array(7), (e, i) => (
                              <ListItem
                                key={i}
                                dense={true}
                                divider={true}
                                button={false}
                              >
                                <ListItemText
                                  primary={
                                    <Grid container={true} spacing={3} style={{ padding: '5px 0' }}>
                                      <Grid item={true} xs={4}>
                                        <Skeleton
                                          animation="wave"
                                          variant="rect"
                                          width="100%"
                                          height={40}
                                          style={{ marginBottom: 10 }}
                                        />
                                      </Grid>
                                      <Grid item={true} xs={4}>
                                        <Skeleton
                                          animation="wave"
                                          variant="rect"
                                          width="100%"
                                          height={40}
                                          style={{ marginBottom: 10 }}
                                        />
                                      </Grid>
                                      <Grid item={true} xs={4}>
                                        <Skeleton
                                          animation="wave"
                                          variant="rect"
                                          width="100%"
                                          height={40}
                                          style={{ marginBottom: 10 }}
                                        />
                                      </Grid>
                                    </Grid>
                                  }
                                />
                              </ListItem>
                            ))}
                          </List>
                        </Paper>
                      </div>
                    );
                  }}
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
                <QR
                  environment={environmentDarkLight}
                  query={riskAnalysisContainerQuery}
                  variables={{ id: riskId }}
                  render={({ error, props, retry }) => {
                    if (props) {
                      return (
                        <CyioCoreObjectExternalReferences
                          typename={risk.__typename}
                          externalReferences={props.risk.links}
                          cyioCoreObjectId={risk.id}
                          refreshQuery={retry}
                        />
                      );
                    }
                    return (
                      <>
                        <Typography
                          variant="h4"
                          gutterBottom={true}
                        >
                          {t('External Reference')}
                        </Typography>
                        <div className="clearfix" />
                        <Paper style={{ height: '100%' }}>
                        </Paper>
                      </>
                    );
                  }}
                />
              </Grid>
              <Grid item={true} xs={6}>
                {/* <StixCoreObjectLatestHistory cyioCoreObjectId={risk.id} /> */}
                <QR
                  environment={environmentDarkLight}
                  query={riskAnalysisContainerQuery}
                  variables={{ id: riskId }}
                  render={({ error, props, retry }) => {
                    if (props) {
                      return (
                        <CyioCoreObjectOrCyioCoreRelationshipNotes
                          typename={risk.__typename}
                          notes={props.risk.remarks}
                          cyioCoreObjectOrCyioCoreRelationshipId={risk.id}
                          marginTop='0px'
                          refreshQuery={retry}
                        />
                      );
                    }
                    return (
                      <>
                        <Typography
                          variant="h4"
                          gutterBottom={true}
                        >
                          {t('Notes')}
                        </Typography>
                        <div className="clearfix" />
                        <Paper style={{ height: '100%' }}>
                        </Paper>
                      </>
                    );
                  }}
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
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(RiskAnalysisContainerComponent);
