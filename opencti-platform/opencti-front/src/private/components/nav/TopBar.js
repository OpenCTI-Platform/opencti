import React, { useState } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import AppBar from '@material-ui/core/AppBar';
import Toolbar from '@material-ui/core/Toolbar';
import IconButton from '@material-ui/core/IconButton';
import { AccountCircleOutlined } from '@material-ui/icons';
import { UploadOutline } from 'mdi-material-ui';
import Menu from '@material-ui/core/Menu';
import MenuItem from '@material-ui/core/MenuItem';
import Tooltip from '@material-ui/core/Tooltip';
import graphql from 'babel-plugin-relay/macro';
import logo from '../../../resources/images/logo.png';
import inject18n from '../../../components/i18n';
import SearchInput from '../../../components/SearchInput';
import TopMenuDashboard from './TopMenuDashboard';
import TopMenuSearch from './TopMenuSearch';
import TopMenuExplore from './TopMenuExplore';
import TopMenuExploreWorkspace from './TopMenuExploreWorkspace';
import TopMenuInvestigate from './TopMenuInvestigate';
import TopMenuInvestigateWorkspace from './TopMenuInvestigateWorkspace';
import TopMenuKnowledge from './TopMenuThreats';
import TopMenuThreatActor from './TopMenuThreatActor';
import TopMenuSector from './TopMenuSector';
import TopMenuIntrusionSet from './TopMenuIntrusionSet';
import TopMenuCampaign from './TopMenuCampaign';
import TopMenuIncident from './TopMenuIncident';
import TopMenuMalware from './TopMenuMalware';
import TopMenuTechniques from './TopMenuTechniques';
import TopMenuAttackPattern from './TopMenuAttackPattern';
import TopMenuCourseOfAction from './TopMenuCourseOfAction';
import TopMenuTool from './TopMenuTool';
import TopMenuVulnerability from './TopMenuVulnerability';
import TopMenuRegion from './TopMenuRegion';
import TopMenuSignatures from './TopMenuSignatures';
import TopMenuObservable from './TopMenuObservable';
import TopMenuIndicator from './TopMenuIndicator';
import TopMenuReports from './TopMenuReports';
import TopMenuReport from './TopMenuReport';
import TopMenuEntities from './TopMenuEntities';
import TopMenuCountry from './TopMenuCountry';
import TopMenuCity from './TopMenuCity';
import TopMenuOrganization from './TopMenuOrganization';
import TopMenuPerson from './TopMenuPerson';
import TopMenuData from './TopMenuData';
import TopMenuSettings from './TopMenuSettings';
import TopMenuProfile from './TopMenuProfile';
import { commitMutation } from '../../../relay/environment';
import Security, {
  KNOWLEDGE,
  KNOWLEDGE_KNASKIMPORT,
} from '../../../utils/Security';

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
  logoButton: {
    marginLeft: -20,
    marginRight: 20,
  },
  logo: {
    cursor: 'pointer',
    height: 35,
  },
  menuContainer: {
    float: 'left',
  },
  barRight: {
    position: 'absolute',
    right: 5,
  },
  searchContainer: {
    display: 'inline-block',
    verticalAlign: 'middle',
    marginRight: 20,
  },
  button: {
    display: 'inline-block',
  },
});

const logoutMutation = graphql`
  mutation TopBarLogoutMutation {
    logout
  }
`;

const TopBar = ({
  t, classes, location, history, keyword,
}) => {
  const [menuOpen, setMenuOpen] = useState({ open: false, anchorEl: null });
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
      onCompleted: () => history.push('/login?message=You have successfully logged out.'),
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
      style={{ backgroundColor: '#1b2226' }}
    >
      <Toolbar>
        <IconButton
          classes={{ root: classes.logoButton }}
          color="inherit"
          aria-label="Menu"
          component={Link}
          to="/dashboard"
        >
          <img src={logo} alt="logo" className={classes.logo} />
        </IconButton>
        <div className={classes.menuContainer}>
          {location.pathname === '/dashboard'
          || location.pathname === '/dashboard/entities'
          || location.pathname === '/dashboard/import' ? (
            <TopMenuDashboard />
            ) : (
              ''
            )}
          {location.pathname.includes('/dashboard/search/') ? (
            <TopMenuSearch />
          ) : (
            ''
          )}
          {location.pathname === '/dashboard/explore' ? <TopMenuExplore /> : ''}
          {location.pathname.includes('/dashboard/explore/') ? (
            <TopMenuExploreWorkspace />
          ) : (
            ''
          )}
          {location.pathname === '/dashboard/investigate' ? (
            <TopMenuInvestigate />
          ) : (
            ''
          )}
          {location.pathname.includes('/dashboard/investigate/') ? (
            <TopMenuInvestigateWorkspace />
          ) : (
            ''
          )}
          {location.pathname === '/dashboard/threats'
          || location.pathname.match('/dashboard/threats/[a-z_]+$') ? (
            <TopMenuKnowledge />
            ) : (
              ''
            )}
          {location.pathname.includes('/dashboard/threats/threat_actors/') ? (
            <TopMenuThreatActor />
          ) : (
            ''
          )}
          {location.pathname.includes('/dashboard/threats/intrusion_sets/') ? (
            <TopMenuIntrusionSet />
          ) : (
            ''
          )}
          {location.pathname.includes('/dashboard/threats/campaigns/') ? (
            <TopMenuCampaign />
          ) : (
            ''
          )}
          {location.pathname.includes('/dashboard/threats/incidents/') ? (
            <TopMenuIncident />
          ) : (
            ''
          )}
          {location.pathname.includes('/dashboard/threats/malwares/') ? (
            <TopMenuMalware />
          ) : (
            ''
          )}
          {location.pathname === '/dashboard/techniques'
          || location.pathname.match('/dashboard/techniques/[a-z_]+$') ? (
            <TopMenuTechniques />
            ) : (
              ''
            )}
          {location.pathname.includes(
            '/dashboard/techniques/attack_patterns/',
          ) ? (
            <TopMenuAttackPattern />
            ) : (
              ''
            )}
          {location.pathname.includes(
            '/dashboard/techniques/courses_of_action/',
          ) ? (
            <TopMenuCourseOfAction />
            ) : (
              ''
            )}
          {location.pathname.includes('/dashboard/techniques/tools/') ? (
            <TopMenuTool />
          ) : (
            ''
          )}
          {location.pathname.includes(
            '/dashboard/techniques/vulnerabilities/',
          ) ? (
            <TopMenuVulnerability />
            ) : (
              ''
            )}
          {location.pathname === '/dashboard/signatures'
          || location.pathname.match('/dashboard/signatures/[a-z1-9_]+$') ? (
            <TopMenuSignatures />
            ) : (
              ''
            )}
          {location.pathname.includes('/dashboard/signatures/observables/') ? (
            <TopMenuObservable />
          ) : (
            ''
          )}
          {location.pathname.includes('/dashboard/signatures/indicators/') ? (
            <TopMenuIndicator />
          ) : (
            ''
          )}
          {location.pathname === '/dashboard/reports'
          || location.pathname.match('/dashboard/reports/[a-zA-Z1-9_-]+$') ? (
            <TopMenuReports />
            ) : (
              ''
            )}
          {location.pathname.includes('/dashboard/reports/all/') ? (
            <TopMenuReport />
          ) : (
            ''
          )}
          {location.pathname === '/dashboard/entities'
          || location.pathname.match('/dashboard/entities/[a-z_]+$') ? (
            <TopMenuEntities />
            ) : (
              ''
            )}
          {location.pathname.includes('/dashboard/entities/sectors/') ? (
            <TopMenuSector />
          ) : (
            ''
          )}
          {location.pathname.includes('/dashboard/entities/regions/') ? (
            <TopMenuRegion />
          ) : (
            ''
          )}
          {location.pathname.includes('/dashboard/entities/countries/') ? (
            <TopMenuCountry />
          ) : (
            ''
          )}
          {location.pathname.includes('/dashboard/entities/cities/') ? (
            <TopMenuCity />
          ) : (
            ''
          )}
          {location.pathname.includes('/dashboard/entities/organizations/') ? (
            <TopMenuOrganization />
          ) : (
            ''
          )}
          {location.pathname.includes('/dashboard/entities/persons/') ? (
            <TopMenuPerson />
          ) : (
            ''
          )}
          {location.pathname === '/dashboard/data'
          || location.pathname.match('/dashboard/data/[a-z_]+$') ? (
            <TopMenuData />
            ) : (
              ''
            )}
          {location.pathname.includes('/dashboard/settings') ? (
            <TopMenuSettings />
          ) : (
            ''
          )}
          {location.pathname === '/dashboard/profile' ? <TopMenuProfile /> : ''}
        </div>
        <div className={classes.barRight}>
          <Security needs={[KNOWLEDGE]}>
            <div className={classes.searchContainer}>
              <SearchInput onSubmit={handleSearch} keyword={keyword} />
            </div>
          </Security>
          <Security needs={[KNOWLEDGE_KNASKIMPORT]}>
            <Tooltip title={t('Data import')}>
              <IconButton
                component={Link}
                to="/dashboard/import"
                variant={
                  location.pathname === '/dashboard/import'
                    ? 'contained'
                    : 'text'
                }
                color={
                  location.pathname === '/dashboard/import'
                    ? 'primary'
                    : 'inherit'
                }
                classes={{ root: classes.button }}
              >
                <UploadOutline fontSize="large" />
              </IconButton>
            </Tooltip>
          </Security>
          <IconButton
            size="medium"
            classes={{ root: classes.button }}
            aria-owns={menuOpen.open ? 'menu-appbar' : null}
            aria-haspopup="true"
            onClick={handleOpenMenu}
            color="inherit"
          >
            <AccountCircleOutlined fontSize="large" />
          </IconButton>
          <Menu
            id="menu-appbar"
            style={{ marginTop: 40, zIndex: 2100 }}
            anchorEl={menuOpen.anchorEl}
            open={menuOpen.open}
            onClose={handleCloseMenu}
          >
            <MenuItem
              component={Link}
              to="/dashboard/profile"
              onClick={handleCloseMenu}
            >
              {t('Profile')}
            </MenuItem>
            <MenuItem onClick={handleLogout}>{t('Logout')}</MenuItem>
          </Menu>
        </div>
      </Toolbar>
    </AppBar>
  );
};

TopBar.propTypes = {
  keyword: PropTypes.string,
  classes: PropTypes.object,
  location: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(inject18n, withRouter, withStyles(styles))(TopBar);
