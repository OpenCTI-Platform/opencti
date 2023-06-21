import React from 'react';
import PropTypes from 'prop-types';
import { Link, useLocation } from 'react-router-dom';
import { any, includes } from 'ramda';
import Drawer from '@mui/material/Drawer';
import makeStyles from '@mui/styles/makeStyles';
import MenuList from '@mui/material/MenuList';
import MenuItem from '@mui/material/MenuItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListSubheader from '@mui/material/ListSubheader';
import {
  VisibilityOutlined,
  WifiTetheringOutlined,
  BugReportOutlined,
  AccountBalanceOutlined,
  DomainOutlined,
  FlagOutlined,
  GroupOutlined,
  LinkOutlined,
  WebAssetOutlined,
  TerminalOutlined,
  SurroundSoundOutlined,
  PublicOutlined,
  MapOutlined,
  SpeakerNotesOutlined,
  RouterOutlined,
} from '@mui/icons-material';
import {
  Gauge,
  LockPattern,
  Target,
  SourcePull,
  Biohazard,
  Fire,
  DiamondOutline,
  ChessKnight,
  HexagonMultipleOutline,
  ShieldSearch,
  SourceFork,
  CityVariantOutline,
  FlaskOutline,
  LaptopAccount,
  GlobeModel,
} from 'mdi-material-ui';
import { useFormatter } from '../../../../components/i18n';
import useAuth from '../../../../utils/hooks/useAuth';
import { useSettingsMessagesBannerHeight } from '../../settings/settings_messages/SettingsMessagesBanner';

const useStyles = makeStyles((theme) => ({
  drawer: {
    minHeight: '100vh',
    width: 200,
    position: 'fixed',
    overflow: 'auto',
    padding: 0,
    backgroundColor: theme.palette.background.navLight,
  },
  item: {
    height: 38,
  },
  toolbar: theme.mixins.toolbar,
}));

const StixCoreObjectKnowledgeBar = ({ stixCoreObjectLink, availableSections }) => {
  const { t } = useFormatter();
  const classes = useStyles();
  const location = useLocation();
  const { bannerSettings } = useAuth();
  const isInAvailableSection = (sections) => any((filter) => includes(filter, sections), availableSections);
  const settingsMessagesBannerHeight = useSettingsMessagesBannerHeight();
  return (
      <Drawer variant="permanent" anchor="right" classes={{ paper: classes.drawer }}>
        <div className={classes.toolbar} />
        <MenuList style={{ paddingBottom: 0, marginTop: bannerSettings.bannerHeightNumber + settingsMessagesBannerHeight }} component="nav">
          <MenuItem
            component={Link}
            to={`${stixCoreObjectLink}/overview`}
            selected={location.pathname === `${stixCoreObjectLink}/overview`}
            dense={false}
            classes={{ root: classes.item }}
          >
            <ListItemIcon style={{ minWidth: 35 }}>
              <Gauge />
            </ListItemIcon>
            <ListItemText primary={t('Overview')} />
          </MenuItem>
          {isInAvailableSection(['sectors', 'organizations', 'individuals']) ? (
            <MenuList
              style={{ paddingBottom: 0 }}
              component="nav"
              subheader={
                <ListSubheader style={{ height: 35 }}>
                  {t('Entities')}
                </ListSubheader>
              }
            >
              {includes('sectors', availableSections) && (
                <MenuItem
                  component={Link}
                  to={`${stixCoreObjectLink}/sectors`}
                  selected={
                    location.pathname === `${stixCoreObjectLink}/sectors`
                  }
                  dense={false}
                  classes={{ root: classes.item }}
                >
                  <ListItemIcon style={{ minWidth: 35 }}>
                    <DomainOutlined />
                  </ListItemIcon>
                  <ListItemText primary={t('Sectors')} />
                </MenuItem>
              )}
              {includes('regions', availableSections) && (
                <MenuItem
                  component={Link}
                  to={`${stixCoreObjectLink}/regions`}
                  selected={
                    location.pathname === `${stixCoreObjectLink}/regions`
                  }
                  dense={false}
                  classes={{ root: classes.item }}
                >
                  <ListItemIcon style={{ minWidth: 35 }}>
                    <PublicOutlined />
                  </ListItemIcon>
                  <ListItemText primary={t('Regions')} />
                </MenuItem>
              )}
              {includes('countries', availableSections) && (
                <MenuItem
                  component={Link}
                  to={`${stixCoreObjectLink}/countries`}
                  selected={
                    location.pathname === `${stixCoreObjectLink}/countries`
                  }
                  dense={false}
                  classes={{ root: classes.item }}
                >
                  <ListItemIcon style={{ minWidth: 35 }}>
                    <FlagOutlined />
                  </ListItemIcon>
                  <ListItemText primary={t('Countries')} />
                </MenuItem>
              )}
              {includes('areas', availableSections) && (
                <MenuItem
                  component={Link}
                  to={`${stixCoreObjectLink}/areas`}
                  selected={location.pathname === `${stixCoreObjectLink}/areas`}
                  dense={false}
                  classes={{ root: classes.item }}
                >
                  <ListItemIcon style={{ minWidth: 35 }}>
                    <MapOutlined />
                  </ListItemIcon>
                  <ListItemText primary={t('Areas')} />
                </MenuItem>
              )}
              {includes('cities', availableSections) && (
                <MenuItem
                  component={Link}
                  to={`${stixCoreObjectLink}/cities`}
                  selected={
                    location.pathname === `${stixCoreObjectLink}/cities`
                  }
                  dense={false}
                  classes={{ root: classes.item }}
                >
                  <ListItemIcon style={{ minWidth: 35 }}>
                    <CityVariantOutline />
                  </ListItemIcon>
                  <ListItemText primary={t('Cities')} />
                </MenuItem>
              )}
              {includes('organizations', availableSections) && (
                <MenuItem
                  component={Link}
                  to={`${stixCoreObjectLink}/organizations`}
                  selected={
                    location.pathname === `${stixCoreObjectLink}/organizations`
                  }
                  dense={false}
                  classes={{ root: classes.item }}
                >
                  <ListItemIcon style={{ minWidth: 35 }}>
                    <AccountBalanceOutlined />
                  </ListItemIcon>
                  <ListItemText primary={t('Organizations')} />
                </MenuItem>
              )}
              {includes('individuals', availableSections) && (
                <MenuItem
                  component={Link}
                  to={`${stixCoreObjectLink}/individuals`}
                  selected={
                    location.pathname === `${stixCoreObjectLink}/individuals`
                  }
                  dense={false}
                  classes={{ root: classes.item }}
                >
                  <ListItemIcon style={{ minWidth: 35 }}>
                    <GroupOutlined />
                  </ListItemIcon>
                  <ListItemText primary={t('Individuals')} />
                </MenuItem>
              )}
              {includes('locations', availableSections) && (
                <MenuItem
                  component={Link}
                  to={`${stixCoreObjectLink}/locations`}
                  selected={
                    location.pathname === `${stixCoreObjectLink}/locations`
                  }
                  dense={false}
                  classes={{ root: classes.item }}
                >
                  <ListItemIcon style={{ minWidth: 35 }}>
                    <GlobeModel />
                  </ListItemIcon>
                  <ListItemText primary={t('Locations')} />
                </MenuItem>
              )}
              {includes('used_tools', availableSections) && (
                <MenuItem
                  component={Link}
                  to={`${stixCoreObjectLink}/used_tools`}
                  selected={
                    location.pathname === `${stixCoreObjectLink}/used_tools`
                  }
                  dense={false}
                  classes={{ root: classes.item }}
                >
                  <ListItemIcon style={{ minWidth: 35 }}>
                    <WebAssetOutlined />
                  </ListItemIcon>
                  <ListItemText primary={t('Used tools')} />
                </MenuItem>
              )}
            </MenuList>
          ) : (
            <div>
              {includes('sectors', availableSections) && (
                <MenuItem
                  component={Link}
                  to={`${stixCoreObjectLink}/sectors`}
                  selected={
                    location.pathname === `${stixCoreObjectLink}/sectors`
                  }
                  dense={false}
                  classes={{ root: classes.item }}
                >
                  <ListItemIcon style={{ minWidth: 35 }}>
                    <DomainOutlined />
                  </ListItemIcon>
                  <ListItemText primary={t('Sectors')} />
                </MenuItem>
              )}
              {includes('regions', availableSections) && (
                <MenuItem
                  component={Link}
                  to={`${stixCoreObjectLink}/regions`}
                  selected={
                    location.pathname === `${stixCoreObjectLink}/regions`
                  }
                  dense={false}
                  classes={{ root: classes.item }}
                >
                  <ListItemIcon style={{ minWidth: 35 }}>
                    <PublicOutlined />
                  </ListItemIcon>
                  <ListItemText primary={t('Regions')} />
                </MenuItem>
              )}
              {includes('countries', availableSections) && (
                <MenuItem
                  component={Link}
                  to={`${stixCoreObjectLink}/countries`}
                  selected={
                    location.pathname === `${stixCoreObjectLink}/countries`
                  }
                  dense={false}
                  classes={{ root: classes.item }}
                >
                  <ListItemIcon style={{ minWidth: 35 }}>
                    <FlagOutlined />
                  </ListItemIcon>
                  <ListItemText primary={t('Countries')} />
                </MenuItem>
              )}
              {includes('areas', availableSections) && (
                <MenuItem
                  component={Link}
                  to={`${stixCoreObjectLink}/areas`}
                  selected={location.pathname === `${stixCoreObjectLink}/areas`}
                  dense={false}
                  classes={{ root: classes.item }}
                >
                  <ListItemIcon style={{ minWidth: 35 }}>
                    <MapOutlined />
                  </ListItemIcon>
                  <ListItemText primary={t('Areas')} />
                </MenuItem>
              )}
              {includes('cities', availableSections) && (
                <MenuItem
                  component={Link}
                  to={`${stixCoreObjectLink}/cities`}
                  selected={
                    location.pathname === `${stixCoreObjectLink}/cities`
                  }
                  dense={false}
                  classes={{ root: classes.item }}
                >
                  <ListItemIcon style={{ minWidth: 35 }}>
                    <CityVariantOutline />
                  </ListItemIcon>
                  <ListItemText primary={t('Cities')} />
                </MenuItem>
              )}
              {includes('locations', availableSections) && (
                <MenuItem
                  component={Link}
                  to={`${stixCoreObjectLink}/locations`}
                  selected={
                    location.pathname === `${stixCoreObjectLink}/locations`
                  }
                  dense={false}
                  classes={{ root: classes.item }}
                >
                  <ListItemIcon style={{ minWidth: 35 }}>
                    <GlobeModel />
                  </ListItemIcon>
                  <ListItemText primary={t('Locations')} />
                </MenuItem>
              )}
              {includes('organizations', availableSections) && (
                <MenuItem
                  component={Link}
                  to={`${stixCoreObjectLink}/organizations`}
                  selected={
                    location.pathname === `${stixCoreObjectLink}/organizations`
                  }
                  dense={false}
                  classes={{ root: classes.item }}
                >
                  <ListItemIcon style={{ minWidth: 35 }}>
                    <AccountBalanceOutlined />
                  </ListItemIcon>
                  <ListItemText primary={t('Organizations')} />
                </MenuItem>
              )}
              {includes('individuals', availableSections) && (
                <MenuItem
                  component={Link}
                  to={`${stixCoreObjectLink}/individuals`}
                  selected={
                    location.pathname === `${stixCoreObjectLink}/individuals`
                  }
                  dense={false}
                  classes={{ root: classes.item }}
                >
                  <ListItemIcon style={{ minWidth: 35 }}>
                    <GroupOutlined />
                  </ListItemIcon>
                  <ListItemText primary={t('Individuals')} />
                </MenuItem>
              )}
              {includes('used_tools', availableSections) && (
                <MenuItem
                  component={Link}
                  to={`${stixCoreObjectLink}/used_tools`}
                  selected={
                    location.pathname === `${stixCoreObjectLink}/used_tools`
                  }
                  dense={false}
                  classes={{ root: classes.item }}
                >
                  <ListItemIcon style={{ minWidth: 35 }}>
                    <WebAssetOutlined />
                  </ListItemIcon>
                  <ListItemText primary={t('Used tools')} />
                </MenuItem>
              )}
            </div>
          )}
        </MenuList>
        {isInAvailableSection([
          'targets',
          'attribution',
          'victimology',
          'intrusion_sets',
          'campaigns',
        ]) ? (
          <MenuList
            style={{ paddingBottom: 0 }}
            component="nav"
            subheader={
              <ListSubheader style={{ height: 35 }}>
                {t('Threats')}
              </ListSubheader>
            }
          >
            {includes('threats', availableSections) && (
              <MenuItem
                component={Link}
                to={`${stixCoreObjectLink}/threats`}
                selected={location.pathname === `${stixCoreObjectLink}/threats`}
                dense={false}
                classes={{ root: classes.item }}
              >
                <ListItemIcon style={{ minWidth: 35 }}>
                  <FlaskOutline />
                </ListItemIcon>
                <ListItemText primary={t('All threats')} />
              </MenuItem>
            )}
            {includes('attribution', availableSections) && (
              <MenuItem
                component={Link}
                to={`${stixCoreObjectLink}/attribution`}
                selected={
                  location.pathname === `${stixCoreObjectLink}/attribution`
                }
                dense={false}
                classes={{ root: classes.item }}
              >
                <ListItemIcon style={{ minWidth: 35 }}>
                  <SourcePull />
                </ListItemIcon>
                <ListItemText primary={t('Attribution')} />
              </MenuItem>
            )}
            {includes('victimology', availableSections) && (
              <MenuItem
                component={Link}
                to={`${stixCoreObjectLink}/victimology`}
                selected={
                  location.pathname === `${stixCoreObjectLink}/victimology`
                }
                dense={false}
                classes={{ root: classes.item }}
              >
                <ListItemIcon style={{ minWidth: 35 }}>
                  <Target />
                </ListItemIcon>
                <ListItemText primary={t('Victimology')} />
              </MenuItem>
            )}
            {includes('threat_actors', availableSections) && (
              <MenuItem
                component={Link}
                to={`${stixCoreObjectLink}/threat_actors`}
                selected={
                  location.pathname === `${stixCoreObjectLink}/threat_actors`
                }
                dense={false}
                classes={{ root: classes.item }}
              >
                <ListItemIcon style={{ minWidth: 35 }}>
                  <LaptopAccount />
                </ListItemIcon>
                <ListItemText primary={t('Threat actors group')} />
              </MenuItem>
            )}
            {includes('intrusion_sets', availableSections) && (
              <MenuItem
                component={Link}
                to={`${stixCoreObjectLink}/intrusion_sets`}
                selected={
                  location.pathname === `${stixCoreObjectLink}/intrusion_sets`
                }
                dense={false}
                classes={{ root: classes.item }}
              >
                <ListItemIcon style={{ minWidth: 35 }}>
                  <DiamondOutline />
                </ListItemIcon>
                <ListItemText primary={t('Intrusion sets')} />
              </MenuItem>
            )}
            {includes('campaigns', availableSections) && (
              <MenuItem
                component={Link}
                to={`${stixCoreObjectLink}/campaigns`}
                selected={
                  location.pathname === `${stixCoreObjectLink}/campaigns`
                }
                dense={false}
                classes={{ root: classes.item }}
              >
                <ListItemIcon style={{ minWidth: 35 }}>
                  <ChessKnight />
                </ListItemIcon>
                <ListItemText primary={t('Campaigns')} />
              </MenuItem>
            )}
          </MenuList>
          ) : (
            ''
          )}
        {isInAvailableSection([
          'variants',
          'malwares',
          'tools',
          'vulnerabilities',
          'channels',
        ]) && (
          <MenuList
            style={{ paddingBottom: 0 }}
            component="nav"
            subheader={
              <ListSubheader style={{ height: 35 }}>
                {t('Arsenal')}
              </ListSubheader>
            }
          >
            {includes('variants', availableSections) && (
              <MenuItem
                component={Link}
                to={`${stixCoreObjectLink}/variants`}
                selected={
                  location.pathname === `${stixCoreObjectLink}/variants`
                }
                dense={false}
                classes={{ root: classes.item }}
              >
                <ListItemIcon style={{ minWidth: 35 }}>
                  <SourceFork />
                </ListItemIcon>
                <ListItemText primary={t('Variants')} />
              </MenuItem>
            )}
            {includes('malwares', availableSections) && (
              <MenuItem
                component={Link}
                to={`${stixCoreObjectLink}/malwares`}
                selected={
                  location.pathname === `${stixCoreObjectLink}/malwares`
                }
                dense={false}
                classes={{ root: classes.item }}
              >
                <ListItemIcon style={{ minWidth: 35 }}>
                  <Biohazard />
                </ListItemIcon>
                <ListItemText primary={t('Malwares')} />
              </MenuItem>
            )}
            {includes('channels', availableSections) && (
              <MenuItem
                component={Link}
                to={`${stixCoreObjectLink}/channels`}
                selected={
                  location.pathname === `${stixCoreObjectLink}/channels`
                }
                dense={false}
                classes={{ root: classes.item }}
              >
                <ListItemIcon style={{ minWidth: 35 }}>
                  <SurroundSoundOutlined />
                </ListItemIcon>
                <ListItemText primary={t('Channels')} />
              </MenuItem>
            )}
            {includes('tools', availableSections) && (
              <MenuItem
                component={Link}
                to={`${stixCoreObjectLink}/tools`}
                selected={location.pathname === `${stixCoreObjectLink}/tools`}
                dense={false}
                classes={{ root: classes.item }}
              >
                <ListItemIcon style={{ minWidth: 35 }}>
                  <TerminalOutlined />
                </ListItemIcon>
                <ListItemText primary={t('Tools')} />
              </MenuItem>
            )}
            {includes('vulnerabilities', availableSections) && (
              <MenuItem
                component={Link}
                to={`${stixCoreObjectLink}/vulnerabilities`}
                selected={
                  location.pathname === `${stixCoreObjectLink}/vulnerabilities`
                }
                dense={false}
                classes={{ root: classes.item }}
              >
                <ListItemIcon style={{ minWidth: 35 }}>
                  <BugReportOutlined />
                </ListItemIcon>
                <ListItemText primary={t('Vulnerabilities')} />
              </MenuItem>
            )}
          </MenuList>
        )}
        {isInAvailableSection(['attack_patterns', 'narratives']) && (
          <MenuList
            style={{ paddingBottom: 0 }}
            component="nav"
            subheader={
              <ListSubheader style={{ height: 35 }}>
                {t('Techniques')}
              </ListSubheader>
            }
          >
            {includes('attack_patterns', availableSections) && (
              <MenuItem
                component={Link}
                to={`${stixCoreObjectLink}/attack_patterns`}
                selected={
                  location.pathname === `${stixCoreObjectLink}/attack_patterns`
                }
                dense={false}
                classes={{ root: classes.item }}
              >
                <ListItemIcon style={{ minWidth: 35 }}>
                  <LockPattern />
                </ListItemIcon>
                <ListItemText primary={t('Attack patterns')} />
              </MenuItem>
            )}
            {includes('narratives', availableSections) && (
              <MenuItem
                component={Link}
                to={`${stixCoreObjectLink}/narratives`}
                selected={
                  location.pathname === `${stixCoreObjectLink}/narratives`
                }
                dense={false}
                classes={{ root: classes.item }}
              >
                <ListItemIcon style={{ minWidth: 35 }}>
                  <SpeakerNotesOutlined />
                </ListItemIcon>
                <ListItemText primary={t('Narratives')} />
              </MenuItem>
            )}
          </MenuList>
        )}
        {isInAvailableSection([
          'observables',
          'indicators',
          'observables',
          'infrastructures',
        ]) && (
          <MenuList
            style={{ paddingBottom: 0 }}
            component="nav"
            subheader={
              <ListSubheader style={{ height: 35 }}>
                {t('Observations')}
              </ListSubheader>
            }
          >
            {includes('observables', availableSections) && (
              <MenuItem
                component={Link}
                to={`${stixCoreObjectLink}/observables`}
                selected={
                  location.pathname === `${stixCoreObjectLink}/observables`
                }
                dense={false}
                classes={{ root: classes.item }}
              >
                <ListItemIcon style={{ minWidth: 35 }}>
                  <HexagonMultipleOutline />
                </ListItemIcon>
                <ListItemText primary={t('Observables')} />
              </MenuItem>
            )}
            {includes('indicators', availableSections) && (
              <MenuItem
                component={Link}
                to={`${stixCoreObjectLink}/indicators`}
                selected={
                  location.pathname === `${stixCoreObjectLink}/indicators`
                }
                dense={false}
                classes={{ root: classes.item }}
              >
                <ListItemIcon style={{ minWidth: 35 }}>
                  <ShieldSearch />
                </ListItemIcon>
                <ListItemText primary={t('Indicators')} />
              </MenuItem>
            )}
            {includes('infrastructures', availableSections) && (
              <MenuItem
                component={Link}
                to={`${stixCoreObjectLink}/infrastructures`}
                selected={
                  location.pathname === `${stixCoreObjectLink}/infrastructures`
                }
                dense={false}
                classes={{ root: classes.item }}
              >
                <ListItemIcon style={{ minWidth: 35 }}>
                  <RouterOutlined />
                </ListItemIcon>
                <ListItemText primary={t('Infrastructures')} />
              </MenuItem>
            )}
          </MenuList>
        )}
        {isInAvailableSection(['incidents', 'observed_data', 'sightings']) && (
          <MenuList
            style={{ paddingBottom: 0 }}
            component="nav"
            subheader={
              <ListSubheader style={{ height: 35 }}>
                {t('Events')}
              </ListSubheader>
            }
          >
            {includes('incidents', availableSections) && (
              <MenuItem
                component={Link}
                to={`${stixCoreObjectLink}/incidents`}
                selected={
                  location.pathname === `${stixCoreObjectLink}/incidents`
                }
                dense={false}
                classes={{ root: classes.item }}
              >
                <ListItemIcon style={{ minWidth: 35 }}>
                  <Fire />
                </ListItemIcon>
                <ListItemText primary={t('Incidents')} />
              </MenuItem>
            )}
            {includes('observed_data', availableSections) && (
              <MenuItem
                component={Link}
                to={`${stixCoreObjectLink}/observed_data`}
                selected={
                  location.pathname === `${stixCoreObjectLink}/observed_data`
                }
                dense={false}
                classes={{ root: classes.item }}
              >
                <ListItemIcon style={{ minWidth: 35 }}>
                  <WifiTetheringOutlined />
                </ListItemIcon>
                <ListItemText primary={t('Observed data')} />
              </MenuItem>
            )}
            {includes('sightings', availableSections) && (
              <MenuItem
                component={Link}
                to={`${stixCoreObjectLink}/sightings`}
                selected={
                  location.pathname === `${stixCoreObjectLink}/sightings`
                }
                dense={false}
                classes={{ root: classes.item }}
              >
                <ListItemIcon style={{ minWidth: 35 }}>
                  <VisibilityOutlined />
                </ListItemIcon>
                <ListItemText primary={t('Sightings')} />
              </MenuItem>
            )}
          </MenuList>
        )}
        <MenuList style={{ paddingBottom: 0 }} sx={{ marginBottom: bannerSettings.bannerHeight }}
          component="nav"
          subheader={
            <ListSubheader style={{ height: 35 }}>{t('Other')}</ListSubheader>
          }
        >
          <MenuItem
            component={Link}
            to={`${stixCoreObjectLink}/related`}
            selected={location.pathname === `${stixCoreObjectLink}/related`}
            dense={false}
            classes={{ root: classes.item }}
          >
            <ListItemIcon style={{ minWidth: 35 }}>
              <LinkOutlined />
            </ListItemIcon>
            <ListItemText primary={t('Related entities')} />
          </MenuItem>
        </MenuList>
      </Drawer>
  );
};

StixCoreObjectKnowledgeBar.propTypes = {
  id: PropTypes.string,
  stixCoreObjectLink: PropTypes.string,
  availableSections: PropTypes.array,
};

export default StixCoreObjectKnowledgeBar;
