import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose, any, includes } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Drawer from '@material-ui/core/Drawer';
import MenuList from '@material-ui/core/MenuList';
import MenuItem from '@material-ui/core/MenuItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import ListSubheader from '@material-ui/core/ListSubheader';
import { BugReport, WifiTetheringOutlined } from '@material-ui/icons';
import {
  Gauge,
  LockPattern,
  Application,
  Target,
  SourcePull,
  Biohazard,
  Fire,
} from 'mdi-material-ui';
import inject18n from '../../../../components/i18n';

const styles = (theme) => ({
  drawer: {
    minHeight: '100vh',
    width: 240,
    position: 'fixed',
    overflow: 'auto',
    padding: 0,
    backgroundColor: theme.palette.background.navLight,
  },
  toolbar: theme.mixins.toolbar,
});

class StixCoreObjectKnowledgeBar extends Component {
  render() {
    const {
      t,
      location,
      classes,
      stixCoreObjectLink,
      availableSections,
    } = this.props;
    const isInAvailableSection = (sections) => any((filter) => includes(filter, sections), availableSections);
    return (
      <Drawer
        variant="permanent"
        anchor="right"
        classes={{ paper: classes.drawer }}
      >
        <div className={classes.toolbar} />
        <MenuList component="nav">
          <MenuItem
            component={Link}
            to={`${stixCoreObjectLink}/knowledge/overview`}
            selected={
              location.pathname === `${stixCoreObjectLink}/knowledge/overview`
            }
            dense={false}
            classes={{ root: classes.item }}
          >
            <ListItemIcon>
              <Gauge />
            </ListItemIcon>
            <ListItemText primary={t('Overview')} />
          </MenuItem>
        </MenuList>
        {isInAvailableSection(['attribution', 'victimology']) ? (
          <MenuList
            component="nav"
            subheader={
              <ListSubheader component="div" id="nested-list-subheader">
                {t('Strategic')}
              </ListSubheader>
            }
          >
            {includes('attribution', availableSections) ? (
              <MenuItem
                component={Link}
                to={`${stixCoreObjectLink}/knowledge/attribution`}
                selected={
                  location.pathname
                  === `${stixCoreObjectLink}/knowledge/attribution`
                }
                dense={false}
                classes={{ root: classes.item }}
              >
                <ListItemIcon>
                  <SourcePull />
                </ListItemIcon>
                <ListItemText primary={t('Attribution')} />
              </MenuItem>
            ) : (
              ''
            )}
            {includes('victimology', availableSections) ? (
              <MenuItem
                component={Link}
                to={`${stixCoreObjectLink}/knowledge/victimology`}
                selected={
                  location.pathname
                  === `${stixCoreObjectLink}/knowledge/victimology`
                }
                dense={false}
                classes={{ root: classes.item }}
              >
                <ListItemIcon>
                  <Target />
                </ListItemIcon>
                <ListItemText primary={t('Victimology')} />
              </MenuItem>
            ) : (
              ''
            )}
          </MenuList>
        ) : (
          ''
        )}
        {isInAvailableSection(['incidents', 'observed_data', 'sightings']) ? (
          <MenuList
            component="nav"
            subheader={
              <ListSubheader component="div" id="nested-list-subheader">
                {t('Events')}
              </ListSubheader>
            }
          >
            {includes('incidents', availableSections) ? (
              <MenuItem
                component={Link}
                to={`${stixCoreObjectLink}/knowledge/incidents`}
                selected={
                  location.pathname
                  === `${stixCoreObjectLink}/knowledge/incidents`
                }
                dense={false}
                classes={{ root: classes.item }}
              >
                <ListItemIcon>
                  <Fire />
                </ListItemIcon>
                <ListItemText primary={t('Incidents')} />
              </MenuItem>
            ) : (
              ''
            )}
            {includes('observed_data', availableSections) ? (
              <MenuItem
                component={Link}
                to={`${stixCoreObjectLink}/knowledge/observed_data`}
                selected={
                  location.pathname
                  === `${stixCoreObjectLink}/knowledge/observed_data`
                }
                dense={false}
                classes={{ root: classes.item }}
              >
                <ListItemIcon>
                  <WifiTetheringOutlined />
                </ListItemIcon>
                <ListItemText primary={t('Observed data')} />
              </MenuItem>
            ) : (
              ''
            )}
          </MenuList>
        ) : (
          ''
        )}

        <MenuList component="nav">
          <MenuItem
            component={Link}
            to={`${stixCoreObjectLink}/knowledge/malwares`}
            selected={
              location.pathname === `${stixCoreObjectLink}/knowledge/malwares`
            }
            dense={false}
            classes={{ root: classes.item }}
          >
            <ListItemIcon>
              <Biohazard />
            </ListItemIcon>
            <ListItemText primary={t('Malwares')} />
          </MenuItem>
          <MenuItem
            component={Link}
            to={`${stixCoreObjectLink}/knowledge/ttp`}
            selected={
              location.pathname === `${stixCoreObjectLink}/knowledge/ttp`
            }
            dense={false}
            classes={{ root: classes.item }}
          >
            <ListItemIcon>
              <LockPattern />
            </ListItemIcon>
            <ListItemText primary={t('Attack patterns')} />
          </MenuItem>
          <MenuItem
            component={Link}
            to={`${stixCoreObjectLink}/knowledge/tools`}
            selected={
              location.pathname === `${stixCoreObjectLink}/knowledge/tools`
            }
            dense={false}
            classes={{ root: classes.item }}
          >
            <ListItemIcon>
              <Application />
            </ListItemIcon>
            <ListItemText primary={t('Tools')} />
          </MenuItem>
          <MenuItem
            component={Link}
            to={`${stixCoreObjectLink}/knowledge/vulnerabilities`}
            selected={
              location.pathname
              === `${stixCoreObjectLink}/knowledge/vulnerabilities`
            }
            dense={false}
            classes={{ root: classes.item }}
          >
            <ListItemIcon>
              <BugReport />
            </ListItemIcon>
            <ListItemText primary={t('Vulnerabilities')} />
          </MenuItem>
        </MenuList>
      </Drawer>
    );
  }
}

StixCoreObjectKnowledgeBar.propTypes = {
  id: PropTypes.string,
  stixCoreObjectLink: PropTypes.string,
  availableSections: PropTypes.array,
  classes: PropTypes.object,
  location: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(StixCoreObjectKnowledgeBar);
