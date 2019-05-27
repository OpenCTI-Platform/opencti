import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Redirect, Switch } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import { compose } from 'ramda';
import { QueryRenderer } from '../relay/environment';
import { ConnectedIntlProvider } from '../components/AppIntlProvider';
import { ConnectedDocumentTitle } from '../components/AppDocumentTitle';
import TopBar from './components/nav/TopBar';
import LeftBar from './components/nav/LeftBar';
import Dashboard from './components/Dashboard';
import StixDomainEntities from './components/StixDomainEntities';
import ExploreVictimology from './components/explore/Victimology';
import ExploreAttackPatterns from './components/explore/AttackPatterns';
// import Workspaces from './components/Workspaces';
import StixObservables from './components/StixObservables';
import RootStixObservable from './components/stix_observable/Root';
import RootWorkspace from './components/workspace/Root';
import ThreatActors from './components/ThreatActors';
import RootThreatActor from './components/threat_actor/Root';
import Sectors from './components/Sectors';
import RootSector from './components/sector/Root';
import IntrusionSets from './components/IntrusionSets';
import RootIntrusionSet from './components/intrusion_set/Root';
import Campaigns from './components/Campaigns';
import RootCampaign from './components/campaign/Root';
import Incidents from './components/Incidents';
import RootIncident from './components/incident/Root';
import Malwares from './components/Malwares';
import RootMalware from './components/malware/Root';
import Reports from './components/Reports';
import RootReport from './components/report/Root';
import ExternalReferences from './components/ExternalReferences';
import AttackPatterns from './components/AttackPatterns';
import RootAttackPattern from './components/attack_pattern/Root';
import Tools from './components/Tools';
import RootTool from './components/tool/Root';
import Vulnerabilities from './components/Vulnerabilities';
import RootVulnerabilities from './components/vulnerability/Root';
import Regions from './components/Regions';
import RootRegion from './components/region/Root';
import Countries from './components/Countries';
import RootCountry from './components/country/Root';
import Cities from './components/Cities';
import Organizations from './components/Organizations';
import RootOrganization from './components/organization/Root';
import Persons from './components/Persons';
import Settings from './components/Settings';
import Users from './components/Users';
import Groups from './components/Groups';
import MarkingDefinitions from './components/MarkingDefinitions';
import KillChainPhases from './components/KillChainPhases';
import Profile from './components/user/Profile';
import Message from '../components/Message';
import { NoMatch, BoundaryRoute } from './components/Error';
import Loader from './Loader';

const styles = theme => ({
  root: {
    height: '100%',
  },
  content: {
    height: '100%',
    flexGrow: 1,
    backgroundColor: theme.palette.background.default,
    padding: '24px 24px 24px 84px',
    minWidth: 0,
  },
  message: {
    display: 'flex',
    alignItems: 'center',
  },
  messageIcon: {
    marginRight: theme.spacing(1),
  },
  toolbar: theme.mixins.toolbar,
});

const rootQuery = graphql`
  query RootQuery {
    me {
      ...AppIntlProvider_me
      ...TopBar_me
      ...LeftBar_me
    }
    settings {
      ...AppIntlProvider_settings
      ...AppDocumentTitle_settings
    }
  }
`;

class Root extends Component {
  render() {
    const { classes } = this.props;
    const paddingRight = 24;
    return (
      <QueryRenderer
        query={rootQuery}
        variables={{}}
        render={({ props }) => {
          if (props) {
            return (
              <ConnectedIntlProvider me={props.me} settings={props.settings}>
                <ConnectedDocumentTitle settings={props.settings}>
                  <div className={classes.root}>
                    <TopBar me={props.me} />
                    <LeftBar me={props.me} />
                    <Message />
                    <main className={classes.content} style={{ paddingRight }}>
                      <div className={classes.toolbar} />
                      <Switch>
                        <BoundaryRoute
                          exact
                          path="/dashboard"
                          component={Dashboard}
                        />
                        <BoundaryRoute
                          exact
                          path="/dashboard/search/:keyword"
                          render={routeProps => (
                            <StixDomainEntities {...routeProps} me={props.me} />
                          )}
                        />
                        <BoundaryRoute
                          exact
                          path="/dashboard/knowledge"
                          render={() => (
                            <Redirect to="/dashboard/knowledge/threat_actors" />
                          )}
                        />
                        <BoundaryRoute
                          exact
                          path="/dashboard/knowledge/threat_actors"
                          component={ThreatActors}
                        />
                        <BoundaryRoute
                          path="/dashboard/knowledge/threat_actors/:threatActorId"
                          render={routeProps => (
                            <RootThreatActor {...routeProps} me={props.me} />
                          )}
                        />
                        <BoundaryRoute
                          exact
                          path="/dashboard/knowledge/sectors"
                          component={Sectors}
                        />
                        <BoundaryRoute
                          path="/dashboard/knowledge/sectors/:sectorId"
                          render={routeProps => (
                            <RootSector {...routeProps} me={props.me} />
                          )}
                        />
                        <BoundaryRoute
                          exact
                          path="/dashboard/knowledge/intrusion_sets"
                          component={IntrusionSets}
                        />
                        <BoundaryRoute
                          path="/dashboard/knowledge/intrusion_sets/:intrusionSetId"
                          render={routeProps => (
                            <RootIntrusionSet {...routeProps} me={props.me} />
                          )}
                        />
                        <BoundaryRoute
                          exact
                          path="/dashboard/knowledge/campaigns"
                          component={Campaigns}
                        />
                        <BoundaryRoute
                          path="/dashboard/knowledge/campaigns/:campaignId"
                          render={routeProps => (
                            <RootCampaign {...routeProps} me={props.me} />
                          )}
                        />
                        <BoundaryRoute
                          exact
                          path="/dashboard/knowledge/incidents"
                          component={Incidents}
                        />
                        <BoundaryRoute
                          path="/dashboard/knowledge/incidents/:incidentId"
                          render={routeProps => (
                            <RootIncident {...routeProps} me={props.me} />
                          )}
                        />
                        <BoundaryRoute
                          exact
                          path="/dashboard/knowledge/malwares"
                          component={Malwares}
                        />
                        <BoundaryRoute
                          path="/dashboard/knowledge/malwares/:malwareId"
                          render={routeProps => (
                            <RootMalware {...routeProps} me={props.me} />
                          )}
                        />
                        <BoundaryRoute
                          exact
                          path="/dashboard/observables"
                          render={() => (
                            <Redirect to="/dashboard/observables/all" />
                          )}
                        />
                        <BoundaryRoute
                          exact
                          path="/dashboard/observables/all"
                          component={StixObservables}
                        />
                        <BoundaryRoute
                          path="/dashboard/observables/all/:observableId"
                          render={routeProps => (
                            <RootStixObservable {...routeProps} me={props.me} />
                          )}
                        />
                        <BoundaryRoute
                          exact
                          path="/dashboard/reports"
                          render={() => (
                            <Redirect to="/dashboard/reports/all" />
                          )}
                        />
                        <BoundaryRoute
                          exact
                          path="/dashboard/reports/all"
                          component={Reports}
                        />
                        <BoundaryRoute
                          exact
                          path="/dashboard/reports/internal"
                          render={routeProps => (
                            <Reports {...routeProps} reportClass="internal" />
                          )}
                        />
                        <BoundaryRoute
                          exact
                          path="/dashboard/reports/external"
                          render={routeProps => (
                            <Reports {...routeProps} reportClass="external" />
                          )}
                        />
                        <BoundaryRoute
                          path="/dashboard/reports/all/:reportId"
                          render={routeProps => (
                            <RootReport {...routeProps} me={props.me} />
                          )}
                        />
                        <BoundaryRoute
                          exact
                          path="/dashboard/reports/references"
                          component={ExternalReferences}
                        />
                        <BoundaryRoute
                          exact
                          path="/dashboard/catalogs"
                          render={() => (
                            <Redirect to="/dashboard/catalogs/attack_patterns" />
                          )}
                        />
                        <BoundaryRoute
                          exact
                          path="/dashboard/catalogs/attack_patterns"
                          component={AttackPatterns}
                        />
                        <BoundaryRoute
                          path="/dashboard/catalogs/attack_patterns/:attackPatternId"
                          render={routeProps => (
                            <RootAttackPattern {...routeProps} me={props.me} />
                          )}
                        />
                        <BoundaryRoute
                          exact
                          path="/dashboard/catalogs/tools"
                          component={Tools}
                        />
                        <BoundaryRoute
                          path="/dashboard/catalogs/tools/:toolId"
                          render={routeProps => (
                            <RootTool {...routeProps} me={props.me} />
                          )}
                        />
                        <BoundaryRoute
                          exact
                          path="/dashboard/catalogs/vulnerabilities"
                          component={Vulnerabilities}
                        />
                        <BoundaryRoute
                          path="/dashboard/catalogs/vulnerabilities/:vulnerabilityId"
                          render={routeProps => (
                            <RootVulnerabilities
                              {...routeProps}
                              me={props.me}
                            />
                          )}
                        />
                        <BoundaryRoute
                          exact
                          path="/dashboard/catalogs/regions"
                          component={Regions}
                        />
                        <BoundaryRoute
                          path="/dashboard/catalogs/regions/:regionId"
                          render={routeProps => (
                            <RootRegion {...routeProps} me={props.me} />
                          )}
                        />
                        <BoundaryRoute
                          exact
                          path="/dashboard/catalogs/countries"
                          component={Countries}
                        />
                        <BoundaryRoute
                          path="/dashboard/catalogs/countries/:countryId"
                          render={routeProps => (
                            <RootCountry {...routeProps} me={props.me} />
                          )}
                        />
                        <BoundaryRoute
                          exact
                          path="/dashboard/catalogs/cities"
                          component={Cities}
                        />
                        <BoundaryRoute
                          exact
                          path="/dashboard/catalogs/organizations"
                          component={Organizations}
                        />
                        <BoundaryRoute
                          path="/dashboard/catalogs/organizations/:organizationId"
                          render={routeProps => (
                            <RootOrganization {...routeProps} me={props.me} />
                          )}
                        />
                        <BoundaryRoute
                          exact
                          path="/dashboard/catalogs/persons"
                          component={Persons}
                        />
                        <BoundaryRoute
                          exact
                          path="/dashboard/explore"
                          render={() => (
                            <Redirect to="/dashboard/explore/victimology" />
                          )}
                        />
                        <BoundaryRoute
                          exact
                          path="/dashboard/explore/victimology"
                          component={ExploreVictimology}
                        />
                        <BoundaryRoute
                          path="/dashboard/explore/victimology/:stixDomainEntityId"
                          component={ExploreVictimology}
                        />
                        <BoundaryRoute
                          exact
                          path="/dashboard/explore/attack_patterns"
                          component={ExploreAttackPatterns}
                        />
                        <BoundaryRoute
                          path="/dashboard/explore/attack_patterns/:stixDomainEntityId"
                          component={ExploreAttackPatterns}
                        />
                        {/* <BoundaryRoute
                          exact
                          path="/dashboard/investigate"
                          component={Workspaces}
                        /> */}
                        <BoundaryRoute
                          exact
                          path="/dashboard/investigate/:workspaceId"
                          component={RootWorkspace}
                        />
                        <BoundaryRoute
                          exact
                          path="/dashboard/settings"
                          component={Settings}
                        />
                        <BoundaryRoute
                          exact
                          path="/dashboard/settings/users"
                          component={Users}
                        />
                        <BoundaryRoute
                          exact
                          path="/dashboard/settings/groups"
                          component={Groups}
                        />
                        <BoundaryRoute
                          exact
                          path="/dashboard/settings/marking"
                          component={MarkingDefinitions}
                        />
                        <BoundaryRoute
                          exact
                          path="/dashboard/settings/killchains"
                          component={KillChainPhases}
                        />
                        <BoundaryRoute
                          exact
                          path="/dashboard/profile"
                          render={routeProps => (
                            <Profile {...routeProps} me={props.me} />
                          )}
                        />
                        <Route component={NoMatch} />
                      </Switch>
                    </main>
                  </div>
                </ConnectedDocumentTitle>
              </ConnectedIntlProvider>
            );
          }
          return <Loader />;
        }}
      />
    );
  }
}

Root.propTypes = {
  classes: PropTypes.object,
  location: PropTypes.object,
};

export default compose(withStyles(styles))(Root);
