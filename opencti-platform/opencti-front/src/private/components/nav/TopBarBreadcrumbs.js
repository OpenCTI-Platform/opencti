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
import NoteAddIcon from '@material-ui/icons/NoteAdd';
import PublishIcon from '@material-ui/icons/Publish';
import FindInPageIcon from '@material-ui/icons/FindInPage';
import DashboardIcon from '@material-ui/icons/Dashboard';
import { UploadOutline } from 'mdi-material-ui';
import Menu from '@material-ui/core/Menu';
import Divider from '@material-ui/core/Divider';
import MenuItem from '@material-ui/core/MenuItem';
import Tooltip from '@material-ui/core/Tooltip';
import graphql from 'babel-plugin-relay/macro';
import inject18n from '../../../components/i18n';
import SearchInput from '../../../components/SearchInput';
import { commitMutation } from '../../../relay/environment';
import Security, {
  KNOWLEDGE,
  KNOWLEDGE_KNASKIMPORT,
  EXPLORE,
} from '../../../utils/Security';
import Filters from '../common/lists/Filters';
import Typography from '@material-ui/core/Typography';
import Breadcrumbs from '@material-ui/core/Breadcrumbs';

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
    marginLeft: 40,
  },
  barRight: {
    position: 'absolute',
    right: 5,
    verticalAlign: 'middle',
    height: '100%',
  },
  barContainer: {
    display: 'table-cell',
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
  t, classes, location, history, keyword, theme,
}) => {

  const pathParts = location.pathname.split("/").filter(entry => entry !== "");

  const [menuOpen, setMenuOpen] = useState({ open: false, anchorEl: null });

  const buildBreadCrumbs = (array) => {

    let url = "/";
    let crumbArry = [];

    for (let x = 0; x < array.length; x++) {

      url += array[x] + "/";
      let obj = { label: array[x], path: url }

      crumbArry.push(obj);

    }

    return crumbArry;

  }
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
        <div className={classes.logoContainer}>
          <Link to="/dashboard">
            <img src={theme.logo} alt="logo" className={classes.logo} />
          </Link>
        </div>
        <div className={classes.menuContainer}>
          <Breadcrumbs aria-label="breadcrumb">
            {breadCrumbs.map((crumb, i, array) => {
              if (i === array.length - 1) {
                return (<Typography color="textPrimary" style={{ textTransform: 'capitalize' }}>{crumb.label}</Typography>)
              } else {
                return (<Link color="inherit"
                  to={crumb.path}
                  onClick={(e) => { e.preventDefault(); history.push(crumb.path); }}
                  style={{ textTransform: 'capitalize' }}
                >
                  {crumb.label}
                </Link>)
              }
            })}
          </Breadcrumbs>
        </div>
        <div className={classes.barRight}>
          <div className={classes.barContainer}>
            <Security needs={[KNOWLEDGE]}>
              <div className={classes.searchContainer}>
                <SearchInput disabled={true} onSubmit={handleSearch} keyword={keyword} />
              </div>
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
              <Tooltip title={t('Custom dashboards')}>
                <IconButton
                  component={Link}
                  to="/dashboard/workspaces/dashboards"
                  variant={
                    location.pathname.includes(
                      '/dashboard/workspaces/dashboards',
                    )
                      ? 'contained'
                      : 'text'
                  }
                  color={
                    location.pathname.includes(
                      '/dashboard/workspaces/dashboards',
                    )
                      ? 'secondary'
                      : 'inherit'
                  }
                  classes={{ root: classes.button }}
                >
                  <InsertChartOutlined fontSize="default" />
                </IconButton>
              </Tooltip>
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
                  <ExploreOutlined fontSize="default" />
                </IconButton>
              </Tooltip>
            </Security>
            <Tooltip title={t('Dashboard')}>
              <IconButton
                component={Link}
                classes={{ root: classes.button }}
              >
                <DashboardIcon fontSize="default" />
              </IconButton>
            </Tooltip>
            <Tooltip title={t('Find in Page')}>
              <IconButton
                disabled={true}
                component={Link}
                classes={{ root: classes.button }}
              >
                <FindInPageIcon fontSize="default" />
              </IconButton>
            </Tooltip>
            <Tooltip title={t('Data Import')}>
              <IconButton
                disabled={true}
                component={Link}
                classes={{ root: classes.button }}
              >
                <PublishIcon fontSize="default" />
              </IconButton>
            </Tooltip>
            <Tooltip title={t('Add Note')}>
              <IconButton
                disabled={true}
                component={Link}
                classes={{ root: classes.button }}
              >
                <NoteAddIcon fontSize="default" />
              </IconButton>
            </Tooltip>
            <IconButton
              size="medium"
              classes={{ root: classes.button }}
              aria-owns={menuOpen.open ? 'menu-appbar' : null}
              aria-haspopup="true"
              onClick={handleOpenMenu}
              color="inherit"
            >
              <AccountCircleOutlined fontSize="default" />
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
        </div>
      </Toolbar>
    </AppBar>
  );
};

TopBarBreadcrumbs.propTypes = {
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
)(TopBarBreadcrumbs);
