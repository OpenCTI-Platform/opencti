/* eslint-disable linebreak-style */
/* eslint-disable */
/* refactor */
import React, { useState } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import { withTheme, withStyles } from '@material-ui/core/styles';
import AppBar from '@material-ui/core/AppBar';
import Toolbar from '@material-ui/core/Toolbar';
import IconButton from '@material-ui/core/IconButton';
import {
  AccountCircleOutlined,
  ExploreOutlined,
  InsertChartOutlined,
} from '@material-ui/icons';
import { UploadOutline } from 'mdi-material-ui';
import Menu from '@material-ui/core/Menu';
import Divider from '@material-ui/core/Divider';
import MenuItem from '@material-ui/core/MenuItem';
import Tooltip from '@material-ui/core/Tooltip';
import { capitalize } from 'lodash';
import Breadcrumbs from '@material-ui/core/Breadcrumbs';
import graphql from 'babel-plugin-relay/macro';
import inject18n from '../../../components/i18n';
import SearchInput from '../../../components/SearchInput';
import TopMenuDashboard from './TopMenuDashboard';
import TopMenuSearch from './TopMenuSearch';
import TopMenuAnalysis from './TopMenuAnalysis';
import TopMenuReport from './TopMenuReport';
import TopMenuNote from './TopMenuNote';
import TopMenuOpinion from './TopMenuOpinion';
import TopMenuExternalReference from './TopMenuExternalReference';
import TopMenuEvents from './TopMenuEvents';
import TopMenuIncident from './TopMenuIncident';
import TopMenuObservedData from './TopMenuObservedData';
import TopMenuObservations from './TopMenuObservations';
import TopMenuIndicator from './TopMenuIndicator';
import TopMenuInfrastructure from './TopMenuInfrastructure';
import TopMenuStixCyberObservable from './TopMenuStixCyberObservable';
import TopMenuArtifact from './TopMenuArtifact';
import TopMenuThreats from './TopMenuThreats';
import TopMenuVSAC from './TopMenuVSAC';
// import TopMenuVsacCompare from './TopMenuVsacCompare';
// import TopMenuVsacExploreResults from './TopMenuVsacExploreResults';
// import TopMenuVsacViewCharts from './TopMenuVsacViewCharts';
import TopMenuAssets from './TopMenuAssets';
import TopMenuDataEntities from './TopMenuDataEntities';
import TopMenuDataRolesEntities from './TopMenuDataRolesEntities';
import TopMenuDataLabelsEntities from './TopMenuDataLabelsEntities';
import TopMenuDataAssessmentPlatformsEntities from './TopMenuDataAssessmentPlatformsEntities';
import TopMenuDataResponsiblePartiesEntities from './TopMenuDataResponsiblePartiesEntities';
import TopMenuDataExternalReferenceEntities from './TopMenuDataExternalReferenceEntities';
import TopMenuDataPartiesEntities from './TopMenuDataPartiesEntities';
import TopMenuDataTasksEntities from './TopMenuDataTasksEntities';
import TopMenuDataNotesEntities from './TopMenuDataNotesEntities';
import TopMenuDataLocationsEntities from './TopMenuDataLocationsEntities';
import TopMenuRiskAssessment from './TopMenuRiskAssessment';
import TopMenuThreatActor from './TopMenuThreatActor';
import TopMenuDevice from './TopMenuDevice';
import TopMenuOverviews from './TopMenuOverviews';
import TopMenuIntrusionSet from './TopMenuIntrusionSet';
import TopMenuNetwork from './TopMenuNetwork';
import TopMenuCampaign from './TopMenuCampaign';
import TopMenuSoftware from './TopMenuSoftware';
import TopMenuRemediations from './TopMenuRemediations';
import TopMenuArsenal from './TopMenuArsenal';
import TopMenuMalware from './TopMenuMalware';
import TopMenuTool from './TopMenuTool';
import TopMenuAttackPattern from './TopMenuAttackPattern';
import TopMenuVulnerability from './TopMenuVulnerability';
import TopMenuEntities from './TopMenuEntities';
import TopMenuSector from './TopMenuSector';
import TopMenuSystem from './TopMenuSystem';
import TopMenuOrganization from './TopMenuOrganization';
import TopMenuIndividual from './TopMenuIndividual';
import TopMenuRegion from './TopMenuRegion';
import TopMenuCountry from './TopMenuCountry';
import TopMenuCity from './TopMenuCity';
import TopMenuPosition from './TopMenuPosition';
import TopMenuData from './TopMenuData';
import TopMenuSettings from './TopMenuSettings';
import TopMenuProfile from './TopMenuProfile';
import { commitMutation } from '../../../relay/environment';
import Security, {
  KNOWLEDGE,
  KNOWLEDGE_KNASKIMPORT,
  EXPLORE,
} from '../../../utils/Security';
import TopMenuCourseOfAction from './TopMenuCourseOfAction';
import TopMenuWorkspacesDashboards from './TopMenuWorkspacesDashboards';
import TopMenuWorkspacesInvestigations from './TopMenuWorkspacesInvestigations';
import Filters from '../common/lists/Filters';

const styles = (theme) => ({
  appBar: {
    width: '100%',
    zIndex: theme.zIndex.drawer + 1,
    backgroundColor: theme.palette.header.background,
    color: theme.palette.header.text,
  },
  flex: {
    flexGrow: 1,
  },
  toolbar: {
    paddingRight: '0',
    alignItems: 'flex-end',
  },
  logo: {
    cursor: 'pointer',
    height: 35,
  },
  menuContainer: {
    float: 'left',
    width: '100%',
    // marginBottom: '20px',
    marginLeft: -20,
    paddingLeft: '20px',
    position: 'relative',
    borderBottom: '1px solid #384057',
  },
  barRight: {
    position: 'absolute',
    right: 5,
    alignItems: 'flex-end',
    height: '100%',
  },
});

const logoutMutation = graphql`
  mutation TopBarMenuLogoutMutation {
    logout
  }
`;

const TopBarMenu = ({
  t, classes, location, history, keyword, theme,
}) => {
  const [menuOpen, setMenuOpen] = useState({ open: false, anchorEl: null });
  const breadCrumbPaths = location.pathname.substr(1).split('/');
  //   let linkPath = '';
  const handleOpenMenu = (event) => {
    event.preventDefault();
    setMenuOpen({ open: true, anchorEl: event.currentTarget });
  };
  const handleCloseMenu = () => {
    setMenuOpen({ open: false, anchorEl: null });
  };
  const handleLogout = () => {
    commitMutation({
      mutation: logoutMutation,
      variables: {},
      onCompleted: () => history.push('/'),
    });
  };
  const handleSearch = (searchKeyword) => {
    if (searchKeyword.length > 0) {
      // With need to double encode because of react router.
      // Waiting for history 5.0 integrated to react router.
      const encodeKey = encodeURIComponent(encodeURIComponent(searchKeyword));
      history.push(`/dashboard/search/${encodeKey}`);
    }
  };
  return (
    <div
      position="relative"
      className={classes.appBar}
      elevation={1}
      style={{ backgroundColor: theme.palette.header.background }}
    >
      <Toolbar
        style={{
          display: location.pathname.includes('/activities/risk assessment/risks') ? 'none' : 'block',
        }}
        className={classes.toolbar}
      >
        <div className={classes.menuContainer}>
          {(location.pathname === '/dashboard'
            || location.pathname === '/dashboard/import') && <TopMenuDashboard />}
          {location.pathname.includes('/dashboard/search') && <TopMenuSearch />}
          {(location.pathname === '/dashboard/analysis'
            || location.pathname.match('/dashboard/analysis/[a-z_]+$')) && (
              <TopMenuAnalysis />
          )}
          {location.pathname.includes('/dashboard/analysis/reports/') && (
            <TopMenuReport />
          )}
          {location.pathname.includes('/dashboard/analysis/notes/') && (
            <TopMenuNote />
          )}
          {location.pathname.includes('/dashboard/analysis/opinions/') && (
            <TopMenuOpinion />
          )}
          {location.pathname.includes(
            '/dashboard/analysis/external_references/',
          ) && <TopMenuExternalReference />}
          {(location.pathname === '/dashboard/events'
            || location.pathname.match('/dashboard/events/[a-z_]+$')) && (
              <TopMenuEvents />
          )}
          {location.pathname.includes('/dashboard/events/incidents/') && (
            <TopMenuIncident />
          )}
          {location.pathname.includes('/dashboard/events/observed_data/') && (
            <TopMenuObservedData />
          )}
          {location.pathname.includes('/dashboard/events/sightings/') && (
            <TopMenuEvents />
          )}
          {(location.pathname === '/dashboard/observations'
            || location.pathname.match('/dashboard/observations/[a-z_]+$')) && (
              <TopMenuObservations />
          )}
          {location.pathname.includes(
            '/dashboard/observations/indicators/',
          ) && <TopMenuIndicator />}
          {location.pathname.includes(
            '/dashboard/observations/infrastructures/',
          ) && <TopMenuInfrastructure />}
          {location.pathname.includes(
            '/dashboard/observations/observables/',
          ) && <TopMenuStixCyberObservable />}
          {location.pathname.includes('/dashboard/observations/artifacts/') && (
            <TopMenuArtifact />
          )}
          {(location.pathname === '/dashboard/threats'
            || location.pathname.match('/dashboard/threats/[a-z_]+$')) && (
              <TopMenuThreats />
          )}
          {location.pathname.includes('/dashboard/threats/threat_actors/') && (
            <TopMenuThreatActor />
          )}
          {location.pathname.includes('/dashboard/threats/intrusion_sets/') && (
            <TopMenuIntrusionSet />
          )}
          {location.pathname.includes('/dashboard/threats/campaigns/') && (
            <TopMenuCampaign />
          )}
          {(location.pathname === '/activities/vulnerability assessment/scans/explore results'
            || location.pathname.match('/activities/vulnerability assessment/scans/explore results')) && (
              <TopMenuVsacExploreResults />
          )}
          {(location.pathname === '/activities/vulnerability assessment/scans/view charts'
            || location.pathname.match('/activities/vulnerability assessment/scans/view charts')) && (
              <TopMenuVsacViewCharts />
          )}
          {(location.pathname === '/activities/vulnerability assessment/scans/compare analysis'
            || location.pathname.match('/activities/vulnerability assessment/scans/compare analysis')) && (
              <TopMenuVsacCompare />
          )}
          {(location.pathname === '/defender HQ/assets'
            || location.pathname.match('/defender HQ/assets/[a-z_]+$')) && (
              <TopMenuAssets />
          )}
          {/* Data Entities Section */}
          {(location.pathname === '/data/entities'
            || location.pathname === '/data/data source') && (
              <TopMenuDataEntities />
          )}
          {(location.pathname === '/data/entities/responsibility'
            || location.pathname === '/data/data source/responsibility') && (
              <TopMenuDataRolesEntities />
          )}
          {(location.pathname === '/data/entities/labels'
            || location.pathname === '/data/data source/labels') && (
              <TopMenuDataLabelsEntities />
          )}
          {(location.pathname === '/data/entities/parties'
            || location.pathname === '/data/data source/parties') && (
              <TopMenuDataPartiesEntities />
          )}
          {(location.pathname === '/data/entities/tasks'
            || location.pathname === '/data/data source/tasks') && (
              <TopMenuDataTasksEntities />
          )}
          {(location.pathname === '/data/entities/notes'
            || location.pathname === '/data/data source/notes') && (
              <TopMenuDataNotesEntities />
          )}
          {(location.pathname === '/data/entities/locations'
            || location.pathname === '/data/data source/locations') && (
              <TopMenuDataLocationsEntities />
          )}
          {(location.pathname === '/data/entities/assessment_platform'
            || location.pathname === '/data/data source/assessment_platform') && (
              <TopMenuDataAssessmentPlatformsEntities />
          )}
          {(location.pathname === '/data/entities/responsible_parties'
            || location.pathname === '/data/data source/responsible_parties') && (
              <TopMenuDataResponsiblePartiesEntities />
          )}
          {(location.pathname === '/data/entities/external_references'
            || location.pathname === '/data/data source/external_references') && (
              <TopMenuDataExternalReferenceEntities />
          )}
          {location.pathname.includes('/defender HQ/assets/devices/') && (
            <TopMenuDevice />
          )}
          {location.pathname.includes('/defender HQ/assets/network/') && (
            <TopMenuNetwork />
          )}
          {location.pathname.includes('/defender HQ/assets/software/') && (
            <TopMenuSoftware />
          )}
          {(location.pathname === '/dashboard/arsenal'
            || location.pathname.match('/dashboard/arsenal/[a-z_]+$')) && (
              <TopMenuArsenal />
          )}
          {location.pathname.includes('/dashboard/arsenal/malwares/') && (
            <TopMenuMalware />
          )}
          {location.pathname.includes('/dashboard/arsenal/tools/') && (
            <TopMenuTool />
          )}
          {location.pathname.includes(
            '/dashboard/arsenal/attack_patterns/',
          ) && <TopMenuAttackPattern />}
          {location.pathname.includes(
            '/dashboard/arsenal/courses_of_action/',
          ) && <TopMenuCourseOfAction />}
          {location.pathname.includes(
            '/dashboard/arsenal/vulnerabilities/',
          ) && <TopMenuVulnerability />}
          {(location.pathname === '/dashboard/entities'
            || location.pathname.match('/dashboard/entities/[a-z_]+$')) && (
              <TopMenuEntities />
          )}
          {location.pathname.includes('/dashboard/entities/sectors/') && (
            <TopMenuSector />
          )}
          {location.pathname.includes('/dashboard/entities/systems/') && (
            <TopMenuSystem />
          )}
          {location.pathname.includes('/dashboard/entities/organizations/') && (
            <TopMenuOrganization />
          )}
          {location.pathname.includes('/dashboard/entities/individuals/') && (
            <TopMenuIndividual />
          )}
          {location.pathname.includes('/dashboard/entities/regions/') && (
            <TopMenuRegion />
          )}
          {location.pathname.includes('/dashboard/entities/countries/') && (
            <TopMenuCountry />
          )}
          {location.pathname.includes('/dashboard/entities/cities/') && (
            <TopMenuCity />
          )}
          {location.pathname.includes('/dashboard/entities/positions/') && (
            <TopMenuPosition />
          )}
          {location.pathname.includes('/dashboard/data') ? <TopMenuData /> : ''}
          {location.pathname.includes('/dashboard/settings') && (
            <TopMenuSettings />
          )}
          {/* {location.pathname.includes('/dashboard/workspaces/dashboards') && (
            <TopMenuWorkspacesDashboards />
          )} */}
          {location.pathname.includes(
            '/dashboard/workspaces/investigations',
          ) && <TopMenuWorkspacesInvestigations />}
          {location.pathname === '/dashboard/profile' ? <TopMenuProfile /> : ''}
        </div>
      </Toolbar>
    </div>
  );
};

TopBarMenu.propTypes = {
  keyword: PropTypes.string,
  theme: PropTypes.object,
  classes: PropTypes.object,
  location: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withRouter,
  withTheme,
  withStyles(styles),
)(TopBarMenu);
