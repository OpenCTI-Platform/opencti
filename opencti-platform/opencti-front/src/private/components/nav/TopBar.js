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
// import TopMenuRisksAnalysis from './TopMenuRisksAnalysis';
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
import TopMenuAssets from './TopMenuAssets';
// import TopMenuRisk from './TopMenuRisk';
// import TopMenuRisksAssessment from './TopMenuRisksAssessment';
import TopMenuThreatActor from './TopMenuThreatActor';
// import TopMenuTracking from './TopMenuTracking';
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
  logoContainer: {

    height: 64,
    width: 290,
    marginLeft: -24,
    paddingTop: 15,
    borderBottom: '1px solid rgba(255, 255, 255, 0.2)',
    backgroundColor: theme.palette.background.nav,

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
    top: 110,
    float: 'left',
    width: '100%',
    // marginLeft: 40,
    paddingLeft: '24px',
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
  mutation TopBarLogoutMutation {
    logout
  }
`;

const TopBar = ({
  t, classes, location, history, keyword, theme,
}) => {
  const [menuOpen, setMenuOpen] = useState({ open: false, anchorEl: null });
  const breadCrumbPaths = location.pathname.substr(1).split('/');
  let linkPath = '';
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
    <AppBar
      position="fixed"
      className={classes.appBar}
      elevation={1}
      style={{ backgroundColor: theme.palette.header.background }}
    >
      <Toolbar className={classes.toolbar}>
        <div className={classes.logoContainer}>
          <Link to="/dashboard">
            <img src={theme.logo} alt="logo" className={classes.logo} />
          </Link>
        </div>
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
          {(location.pathname === '/dashboard/assets'
            || location.pathname.match('/dashboard/assets/[a-z_]+$')) && (
            <TopMenuAssets />
          )}
          {location.pathname.includes('/dashboard/assets/devices/') && (
            <TopMenuDevice />
          )}
          {location.pathname.includes('/dashboard/assets/network/') && (
            <TopMenuNetwork />
          )}
          {location.pathname.includes('/dashboard/assets/software/') && (
            <TopMenuSoftware />
          )}
          {/* {(location.pathname === '/dashboard/risks-assessment'
            || location.pathname.match('/dashboard/risks-assessment/[a-z_]+$')) && (
            <TopMenuRisksAssessment />
          )}
          {location.pathname.includes('/dashboard/risks-assessment/risks/') && (
            <TopMenuRisk />
          )} */}
          {/* {(location.pathname === '/dashboard/risks'
            || location.pathname.match('/dashboard/risks/[a-z_]+$')) && (
            <TopMenuRisks />
          )}
          {location.pathname.includes('/dashboard/risks/overviews/') && (
            <TopMenuOverviews />
          )}
          {location.pathname.includes('/dashboard/risks/analysis/') && (
            <TopMenuRisksAnalysis />
          )}
          {location.pathname.includes('/dashboard/risks/remediations/') && (
            <TopMenuRemediations />
          )}
          {location.pathname.includes('/dashboard/risks/tracking/') && (
            <TopMenuTracking />
          )} */}
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
          {location.pathname.includes('/dashboard/workspaces/dashboards') && (
            <TopMenuWorkspacesDashboards />
          )}
          {location.pathname.includes(
            '/dashboard/workspaces/investigations',
          ) && <TopMenuWorkspacesInvestigations />}
          {location.pathname === '/dashboard/profile' ? <TopMenuProfile /> : ''}
        </div>
        <div className={classes.barRight}>
          <Breadcrumbs aria-label="breadcrumb">
            { breadCrumbPaths.map((path, key) => {
              linkPath = `${linkPath}/${path}`;
              console.log('linkPath', linkPath);
              return (<>
                <Link key={key} underline="hover" color="#000" to={linkPath}>
                { capitalize(path) }
                </Link>
              </>);
            }) }
          </Breadcrumbs>
        </div>
      </Toolbar>
    </AppBar>
  );
};

TopBar.propTypes = {
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
)(TopBar);
