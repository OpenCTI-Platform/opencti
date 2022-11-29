/* eslint-disable */
/* refactor */
import React, { useState } from 'react';
import * as PropTypes from 'prop-types';
import {
  withRouter,
  Link,
} from 'react-router-dom';
import { compose } from 'ramda';
import { withTheme, withStyles } from '@material-ui/core/styles';
import AppBar from '@material-ui/core/AppBar';
import Toolbar from '@material-ui/core/Toolbar';
import IconButton from '@material-ui/core/IconButton';
import {
  AccountCircleOutlined,
  ExploreOutlined,
  InsertChartOutlined,
  Info,
} from '@material-ui/icons';
import FindInPageIcon from '@material-ui/icons/FindInPage';
import DashboardIcon from '@material-ui/icons/Dashboard';
import Menu from '@material-ui/core/Menu';
import Divider from '@material-ui/core/Divider';
import MenuItem from '@material-ui/core/MenuItem';
import Tooltip from '@material-ui/core/Tooltip';
import graphql from 'babel-plugin-relay/macro';
import Typography from '@material-ui/core/Typography';
import Breadcrumbs from '@material-ui/core/Breadcrumbs';
import inject18n from '../../../components/i18n';
import Grid from '@material-ui/core/Grid';
import { commitMutation } from '../../../relay/environment';
import Security, {
  KNOWLEDGE,
  KNOWLEDGE_KNASKIMPORT,
  EXPLORE,
} from '../../../utils/Security';
import Filters from '../common/lists/Filters';
import ExportPoam from '../../../components/ExportPoam';
import Export from '../../../components/Export';
import AboutModal from '../../../components/AboutModal';
import DashboardSettings from '../DashboardSettings';

const styles = (theme) => ({
  appBar: {
    width: '100%',
    backgroundColor: theme.palette.header.background,
    color: theme.palette.header.text,
  },
  flex: {
    flexGrow: 1,
  },
  logoContainer: {
    height: 64,
    width: 255,
    marginLeft: -24,
    paddingTop: 15,
    borderBottom: '1px solid rgba(255, 255, 255, 0.2)',
    backgroundColor: theme.palette.background.nav,
  },
  logo: {
    cursor: 'pointer',
    height: 20,
    marginTop: 10,
    marginLeft: 10,

  },
  menuContainer: {
    float: 'left',
    display: 'flex',
    alignItems: 'center',
    marginLeft: '17rem',
    transition: theme.transitions.create('margin', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
  },
  menuContainerClose: {
    float: 'left',
    display: 'flex',
    alignItems: 'center',
    marginLeft: '5.55rem',
    transition: theme.transitions.create('margin', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.leavingScreen,
    }),
  },
  barRight: {
    position: 'absolute',
    right: 5,
    verticalAlign: 'middle',
    height: '100%',
  },
  barContainer: {
    display: 'flex',
    float: 'left',
    paddingTop: 10,
  },
  divider: {
    display: 'table-cell',
    float: 'left',
    height: '100%',
    margin: '0 5px 0 5px',
  },
  searchContainer: {
    display: 'table-cell',
    float: 'left',
    marginRight: 5,
    paddingTop: 9,
  },
  button: {
    display: 'table-cell',
    float: 'left',
  },
});

const logoutMutation = graphql`
  mutation TopBarBreadcrumbsLogoutMutation {
    logout
  }
`;

const TopBarBreadcrumbs = ({
  t,
  classes,
  location,
  history,
  keyword,
  theme,
  risk,
  remediation,
  handleChangeDashboard,
  dashboard,
  riskId,
  drawer,
}) => {
  const pathParts = location.pathname.split('/').filter((entry) => entry !== '');

  const [menuOpen, setMenuOpen] = useState({ open: false, anchorEl: null });
  const buildBreadCrumbs = (array) => {
    let url = '';
    const crumbArry = [];
    for (let x = 0; x < array.length; x += 1) {
      url += ('/').concat(array[x]);
      const obj = { label: array[x], path: url };
      crumbArry.push(obj);
    }
    return crumbArry;
  };

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
      onCompleted: () => {
        history.push('/');
        localStorage.removeItem('token');
      },
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

  const breadCrumbs = buildBreadCrumbs(pathParts);
  return (
    <AppBar
      position="fixed"
      className={classes.appBar}
      elevation={1}
      style={{ backgroundColor: theme.palette.header.background }}
    >
      <Toolbar>
        <div className={drawer ? classes.menuContainerClose : classes.menuContainer}>
          <Breadcrumbs aria-label="breadcrumb">
            {breadCrumbs.map((crumb, i, array) => {
              if (crumb.label === riskId) {
                crumb.label = risk;
              }
              if (remediation) {
                if (crumb.label === 'remediation' && breadCrumbs.length === 6) {
                  breadCrumbs[i + 1].label = remediation.name;
                }
              }
              if (i === array.length - 1) {
                return (<Typography color="textPrimary" style={{ textTransform: 'capitalize' }}>{crumb.label}</Typography>);
              }
              return (<Link color="inherit"
                key={i}
                to={crumb.path}
                onClick={(e) => { e.preventDefault(); history.push(crumb.path); }}
                style={{ textTransform: 'capitalize' }}
              >
                {crumb.label}
              </Link>);
            })}
          </Breadcrumbs>
          {(location.pathname === '/dashboard') && (
            <DashboardSettings
              dashboard={dashboard}
              handleChangeDashboard={handleChangeDashboard}
            />
          )}
        </div>
        <div className={classes.barRight}>
          <div className={classes.barContainer}>
            <Security needs={[KNOWLEDGE]}>
              {/* <div className={classes.searchContainer}>
                <SearchInput disabled={true} onSubmit={handleSearch} keyword={keyword} />
              </div> */}
              <Filters
                variant="dialog"
                availableFilterKeys={[
                  'entity_type',
                  'markedBy',
                  'labelledBy',
                  'createdBy',
                  'confidence_gt',
                  'x_opencti_organization_type',
                  'created_start_date',
                  'created_end_date',
                  'created_at_start_date',
                  'created_at_end_date',
                ]}
                currentFilters={{}}
                // disabled={location.pathname.includes('/dashboard/search')}
                disabled={true}
              />
            </Security>
          </div>
          <Divider className={classes.divider} orientation="vertical" />
          <div className={classes.barContainer}>
            <Security needs={[EXPLORE]}>
              <Tooltip title={t('Investigations')}>
                <IconButton
                  component={Link}
                  to="/dashboard/workspaces/investigations"
                  variant={
                    location.pathname.includes(
                      '/dashboard/workspaces/investigations',
                    )
                      ? 'contained'
                      : 'text'
                  }
                  color={
                    location.pathname.includes(
                      '/dashboard/workspaces/investigations',
                    )
                      ? 'secondary'
                      : 'inherit'
                  }
                  classes={{ root: classes.button }}
                >
                  <ExploreOutlined fontSize="medium" />
                </IconButton>
              </Tooltip>
            </Security>
            <Grid container={true} spacing={0}>
              <Grid item={true} xs='auto'>
                <Tooltip title={t('Dashboard')}>
                  <IconButton
                    component={Link}
                    to='/dashboard'
                    classes={{ root: classes.button }}
                  >
                    <DashboardIcon fontSize="medium" />
                  </IconButton>
                </Tooltip>
              </Grid>
              <Grid item={true} xs='auto'>
                <AboutModal
                  history={history}
                  location={location}
                />
              </Grid>
              <Grid item={true} xs='auto'>
                <Tooltip title={t('Custom dashboards')}>
                  <IconButton
                    component={Link}
                    to="/dashboard/workspaces/dashboards"
                    classes={{ root: classes.button }}
                  >
                    <InsertChartOutlined fontSize="medium" />
                  </IconButton>
                </Tooltip>
              </Grid>
              <Grid item={true} xs='auto'>
                <Tooltip title={t('Find in Page')}>
                  <IconButton
                    disabled={true}
                    component={Link}
                    classes={{ root: classes.button }}
                  >
                    <FindInPageIcon fontSize="medium" />
                  </IconButton>
                </Tooltip>
              </Grid>
              <Grid item={true} xs='auto'>
                <ExportPoam />
              </Grid>
              <Grid item={true} xs='auto'>
                <Export />
              </Grid>
              <Grid item={true} xs='auto'>
                <IconButton
                  size="medium"
                  classes={{ root: classes.button }}
                  aria-owns={menuOpen.open ? 'menu-appbar' : null}
                  aria-haspopup="true"
                  onClick={handleOpenMenu}
                  data-cy='menu'
                >
                  <AccountCircleOutlined fontSize="medium" />
                </IconButton>
              </Grid>
            </Grid>
            <Menu
              id="menu-appbar"
              style={{ marginTop: 40, zIndex: 2100 }}
              anchorEl={menuOpen.anchorEl}
              open={menuOpen.open}
              onClose={handleCloseMenu}
            >
              <MenuItem
                disabled={true}
                component={Link}
                to="/dashboard/profile"
                onClick={handleCloseMenu}
              >
                {t('Profile')}
              </MenuItem>
              <MenuItem onClick={handleLogout} data-cy='logout'>{t('Logout')}</MenuItem>
            </Menu>
          </div>
        </div>
      </Toolbar>
    </AppBar>
  );
};

TopBarBreadcrumbs.propTypes = {
  riskId: PropTypes.string,
  risk: PropTypes.string,
  remediation: PropTypes.object,
  dashboard: PropTypes.string,
  handleChangeDashboard: PropTypes.func,
  keyword: PropTypes.string,
  theme: PropTypes.object,
  classes: PropTypes.object,
  location: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
  drawer: PropTypes.bool,
};

export default compose(
  inject18n,
  withRouter,
  withTheme,
  withStyles(styles),
)(TopBarBreadcrumbs);
