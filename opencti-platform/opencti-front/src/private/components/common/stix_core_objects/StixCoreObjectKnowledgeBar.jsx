import React from 'react';
import PropTypes from 'prop-types';
import * as R from 'ramda';
import { Link, useLocation } from 'react-router-dom';
import Drawer from '@mui/material/Drawer';
import makeStyles from '@mui/styles/makeStyles';
import MenuList from '@mui/material/MenuList';
import MenuItem from '@mui/material/MenuItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListSubheader from '@mui/material/ListSubheader';
import { useFormatter } from '../../../../components/i18n';
import useAuth from '../../../../utils/hooks/useAuth';
import { useSettingsMessagesBannerHeight } from '../../settings/settings_messages/SettingsMessagesBanner';
import ItemIcon from '../../../../components/ItemIcon';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
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
    fontSize: 9,
  },
  toolbar: theme.mixins.toolbar,
}));

const StixCoreObjectKnowledgeBar = ({
  stixCoreObjectLink,
  availableSections,
  stixCoreObjectsDistribution,
  attribution = [],
}) => {
  const { t_i18n, n } = useFormatter();
  const classes = useStyles();
  const location = useLocation();
  const { bannerSettings } = useAuth();
  const isInAvailableSection = (sections) => R.any((filter) => R.includes(filter, sections), availableSections);
  const settingsMessagesBannerHeight = useSettingsMessagesBannerHeight();
  const statistics = stixCoreObjectsDistribution ? R.indexBy(R.prop('label'), stixCoreObjectsDistribution) : {};
  const statisticsThreats = R.sum(R.values(R.pick(['Threat-Actor-Individual', 'Threat-Actor-Group', 'Intrusion-Set', 'Campaign', 'Incident'], statistics)).map((o) => o.value));
  const statisticsThreatActors = R.sum(R.values(R.pick(['Threat-Actor-Individual', 'Threat-Actor-Group'], statistics)).map((o) => o.value));
  const statisticsVictims = R.sum(R.values(R.pick(['Sector', 'Organization', 'Individual', 'Region', 'Country', 'City', 'Position', 'Administrative-Area'], statistics)).map((o) => o.value));
  const statisticsAttributions = R.sum(R.values(R.pick(attribution, statistics)).map((o) => o.value));
  const statisticsLocations = R.sum(R.values(R.pick(['Region', 'Country', 'City', 'Position', 'Administrative-Area'], statistics)).map((o) => o.value));
  return (
    <Drawer
      variant="permanent"
      anchor="right"
      classes={{ paper: classes.drawer }}
    >
      <div className={classes.toolbar} />
      <MenuList
        style={{
          paddingBottom: 0,
          marginTop:
            bannerSettings.bannerHeightNumber + settingsMessagesBannerHeight,
        }}
        component="nav"
      >
        <MenuItem
          component={Link}
          to={`${stixCoreObjectLink}/overview`}
          selected={location.pathname === `${stixCoreObjectLink}/overview`}
          dense={true}
          classes={{ root: classes.item }}
        >
          <ListItemIcon style={{ minWidth: 28 }}>
            <ItemIcon size="small" type="overview" />
          </ListItemIcon>
          <ListItemText primary={t_i18n('Overview')} />
        </MenuItem>
        {isInAvailableSection(['sectors', 'organizations', 'individuals']) ? (
          <MenuList
            style={{ paddingBottom: 0 }}
            component="nav"
            subheader={
              <ListSubheader style={{ height: 35 }}>
                {t_i18n('Entities')}
              </ListSubheader>
            }
          >
            {R.includes('sectors', availableSections) && (
              <MenuItem
                component={Link}
                to={`${stixCoreObjectLink}/sectors`}
                selected={location.pathname === `${stixCoreObjectLink}/sectors`}
                dense={true}
                classes={{ root: classes.item }}
              >
                <ListItemIcon style={{ minWidth: 28 }}>
                  <ItemIcon size="small" type="Sector" />
                </ListItemIcon>
                <ListItemText primary={`${t_i18n('Sectors')}${statistics.Sector && statistics.Sector.value > 0 ? ` (${n(statistics.Sector.value)})` : ''}`} />
              </MenuItem>
            )}
            {R.includes('regions', availableSections) && (
              <MenuItem
                component={Link}
                to={`${stixCoreObjectLink}/regions`}
                selected={location.pathname === `${stixCoreObjectLink}/regions`}
                dense={true}
                classes={{ root: classes.item }}
              >
                <ListItemIcon style={{ minWidth: 28 }}>
                  <ItemIcon size="small" type="Region" />
                </ListItemIcon>
                <ListItemText primary={`${t_i18n('Regions')}${statistics.Region && statistics.Region.value > 0 ? ` (${n(statistics.Region.value)})` : ''}`} />
              </MenuItem>
            )}
            {R.includes('countries', availableSections) && (
              <MenuItem
                component={Link}
                to={`${stixCoreObjectLink}/countries`}
                selected={
                  location.pathname === `${stixCoreObjectLink}/countries`
                }
                dense={true}
                classes={{ root: classes.item }}
              >
                <ListItemIcon style={{ minWidth: 28 }}>
                  <ItemIcon size="small" type="Country" />
                </ListItemIcon>
                <ListItemText primary={`${t_i18n('Countries')}${statistics.Country && statistics.Country.value > 0 ? ` (${n(statistics.Country.value)})` : ''}`} />
              </MenuItem>
            )}
            {R.includes('areas', availableSections) && (
              <MenuItem
                component={Link}
                to={`${stixCoreObjectLink}/areas`}
                selected={location.pathname === `${stixCoreObjectLink}/areas`}
                dense={true}
                classes={{ root: classes.item }}
              >
                <ListItemIcon style={{ minWidth: 28 }}>
                  <ItemIcon size="small" type="Administrative-Area" />
                </ListItemIcon>
                <ListItemText primary={`${t_i18n('Areas')}${statistics['Administrative-Area'] && statistics['Administrative-Area'].value > 0 ? ` (${n(statistics['Administrative-Area'].value)})` : ''}`} />
              </MenuItem>
            )}
            {R.includes('cities', availableSections) && (
              <MenuItem
                component={Link}
                to={`${stixCoreObjectLink}/cities`}
                selected={location.pathname === `${stixCoreObjectLink}/cities`}
                dense={true}
                classes={{ root: classes.item }}
              >
                <ListItemIcon style={{ minWidth: 28 }}>
                  <ItemIcon size="small" type="City" />
                </ListItemIcon>
                <ListItemText primary={`${t_i18n('Cities')}${statistics.City && statistics.City.value > 0 ? ` (${n(statistics.City.value)})` : ''}`} />
              </MenuItem>
            )}
            {R.includes('organizations', availableSections) && (
              <MenuItem
                component={Link}
                to={`${stixCoreObjectLink}/organizations`}
                selected={
                  location.pathname === `${stixCoreObjectLink}/organizations`
                }
                dense={true}
                classes={{ root: classes.item }}
              >
                <ListItemIcon style={{ minWidth: 28 }}>
                  <ItemIcon size="small" type="Organization" />
                </ListItemIcon>
                <ListItemText primary={`${t_i18n('Organizations')}${statistics.Organization && statistics.Organization.value > 0 ? ` (${n(statistics.Organization.value)})` : ''}`} />
              </MenuItem>
            )}
            {R.includes('individuals', availableSections) && (
              <MenuItem
                component={Link}
                to={`${stixCoreObjectLink}/individuals`}
                selected={
                  location.pathname === `${stixCoreObjectLink}/individuals`
                }
                dense={true}
                classes={{ root: classes.item }}
              >
                <ListItemIcon style={{ minWidth: 28 }}>
                  <ItemIcon size="small" type="Individual" />
                </ListItemIcon>
                <ListItemText primary={`${t_i18n('Individuals')}${statistics.Individual && statistics.Individual.value > 0 ? ` (${n(statistics.Individual.value)})` : ''}`} />
              </MenuItem>
            )}
            {R.includes('locations', availableSections) && (
              <MenuItem
                component={Link}
                to={`${stixCoreObjectLink}/locations`}
                selected={
                  location.pathname === `${stixCoreObjectLink}/locations`
                }
                dense={true}
                classes={{ root: classes.item }}
              >
                <ListItemIcon style={{ minWidth: 28 }}>
                  <ItemIcon size="small" type="location" />
                </ListItemIcon>
                <ListItemText primary={`${t_i18n('Locations')}${statisticsLocations > 0 ? ` (${n(statisticsLocations)})` : ''}`} />
              </MenuItem>
            )}
            {R.includes('used_tools', availableSections) && (
              <MenuItem
                component={Link}
                to={`${stixCoreObjectLink}/used_tools`}
                selected={
                  location.pathname === `${stixCoreObjectLink}/used_tools`
                }
                dense={true}
                classes={{ root: classes.item }}
              >
                <ListItemIcon style={{ minWidth: 28 }}>
                  <ItemIcon size="small" type="Tool" />
                </ListItemIcon>
                <ListItemText primary={t_i18n('Used tools')} />
              </MenuItem>
            )}
          </MenuList>
        ) : (
          <>
            {R.includes('sectors', availableSections) && (
              <MenuItem
                component={Link}
                to={`${stixCoreObjectLink}/sectors`}
                selected={location.pathname === `${stixCoreObjectLink}/sectors`}
                dense={true}
                classes={{ root: classes.item }}
              >
                <ListItemIcon style={{ minWidth: 28 }}>
                  <ItemIcon size="small" type="Sector" />
                </ListItemIcon>
                <ListItemText primary={`${t_i18n('Sectors')}${statistics.Sector && statistics.Sector.value > 0 ? ` (${n(statistics.Sector.value)})` : ''}`} />
              </MenuItem>
            )}
            {R.includes('regions', availableSections) && (
              <MenuItem
                component={Link}
                to={`${stixCoreObjectLink}/regions`}
                selected={location.pathname === `${stixCoreObjectLink}/regions`}
                dense={true}
                classes={{ root: classes.item }}
              >
                <ListItemIcon style={{ minWidth: 28 }}>
                  <ItemIcon size="small" type="Region" />
                </ListItemIcon>
                <ListItemText primary={`${t_i18n('Regions')}${statistics.Region && statistics.Region.value > 0 ? ` (${n(statistics.Region.value)})` : ''}`} />
              </MenuItem>
            )}
            {R.includes('countries', availableSections) && (
              <MenuItem
                component={Link}
                to={`${stixCoreObjectLink}/countries`}
                selected={
                  location.pathname === `${stixCoreObjectLink}/countries`
                }
                dense={true}
                classes={{ root: classes.item }}
              >
                <ListItemIcon style={{ minWidth: 28 }}>
                  <ItemIcon size="small" type="Country" />
                </ListItemIcon>
                <ListItemText primary={`${t_i18n('Countries')}${statistics.Country && statistics.Country.value > 0 ? ` (${n(statistics.Country.value)})` : ''}`} />
              </MenuItem>
            )}
            {R.includes('areas', availableSections) && (
              <MenuItem
                component={Link}
                to={`${stixCoreObjectLink}/areas`}
                selected={location.pathname === `${stixCoreObjectLink}/areas`}
                dense={true}
                classes={{ root: classes.item }}
              >
                <ListItemIcon style={{ minWidth: 28 }}>
                  <ItemIcon size="small" type="Administrative-Area" />
                </ListItemIcon>
                <ListItemText primary={`${t_i18n('Areas')}${statistics['Administrative-Area'] && statistics['Administrative-Area'].value > 0 ? ` (${n(statistics['Administrative-Area'].value)})` : ''}`} />
              </MenuItem>
            )}
            {R.includes('cities', availableSections) && (
              <MenuItem
                component={Link}
                to={`${stixCoreObjectLink}/cities`}
                selected={location.pathname === `${stixCoreObjectLink}/cities`}
                dense={true}
                classes={{ root: classes.item }}
              >
                <ListItemIcon style={{ minWidth: 28 }}>
                  <ItemIcon size="small" type="City" />
                </ListItemIcon>
                <ListItemText primary={`${t_i18n('Cities')}${statistics.City && statistics.City.value > 0 ? ` (${n(statistics.City.value)})` : ''}`} />
              </MenuItem>
            )}
            {R.includes('locations', availableSections) && (
              <MenuItem
                component={Link}
                to={`${stixCoreObjectLink}/locations`}
                selected={
                  location.pathname === `${stixCoreObjectLink}/locations`
                }
                dense={true}
                classes={{ root: classes.item }}
              >
                <ListItemIcon style={{ minWidth: 28 }}>
                  <ItemIcon size="small" type="Location" />
                </ListItemIcon>
                <ListItemText primary={`${t_i18n('Locations')}${statisticsLocations > 0 ? ` (${n(statisticsLocations)})` : ''}`} />
              </MenuItem>
            )}
            {R.includes('organizations', availableSections) && (
              <MenuItem
                component={Link}
                to={`${stixCoreObjectLink}/organizations`}
                selected={
                  location.pathname === `${stixCoreObjectLink}/organizations`
                }
                dense={true}
                classes={{ root: classes.item }}
              >
                <ListItemIcon style={{ minWidth: 28 }}>
                  <ItemIcon size="small" type="Organization" />
                </ListItemIcon>
                <ListItemText primary={`${t_i18n('Organizations')}${statistics.Organization && statistics.Organization.value > 0 ? ` (${n(statistics.Organization.value)})` : ''}`} />
              </MenuItem>
            )}
            {R.includes('individuals', availableSections) && (
              <MenuItem
                component={Link}
                to={`${stixCoreObjectLink}/individuals`}
                selected={
                  location.pathname === `${stixCoreObjectLink}/individuals`
                }
                dense={true}
                classes={{ root: classes.item }}
              >
                <ListItemIcon style={{ minWidth: 28 }}>
                  <ItemIcon size="small" type="Individual" />
                </ListItemIcon>
                <ListItemText primary={`${t_i18n('Individuals')}${statistics.Individual && statistics.Individual.value > 0 ? ` (${n(statistics.Individual.value)})` : ''}`} />
              </MenuItem>
            )}
            {R.includes('used_tools', availableSections) && (
              <MenuItem
                component={Link}
                to={`${stixCoreObjectLink}/used_tools`}
                selected={
                  location.pathname === `${stixCoreObjectLink}/used_tools`
                }
                dense={true}
                classes={{ root: classes.item }}
              >
                <ListItemIcon style={{ minWidth: 28 }}>
                  <ItemIcon size="small" type="Tool" />
                </ListItemIcon>
                <ListItemText primary={t_i18n('Used tools')} />
              </MenuItem>
            )}
          </>
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
            <ListSubheader style={{ height: 35 }}>{t_i18n('Threats')}</ListSubheader>
          }
        >
          {R.includes('threats', availableSections) && (
            <MenuItem
              component={Link}
              to={`${stixCoreObjectLink}/threats`}
              selected={location.pathname === `${stixCoreObjectLink}/threats`}
              dense={true}
              classes={{ root: classes.item }}
            >
              <ListItemIcon style={{ minWidth: 28 }}>
                <ItemIcon size="small" type="threats" />
              </ListItemIcon>
              <ListItemText primary={`${t_i18n('All threats')}${statisticsThreats > 0 ? ` (${n(statisticsThreats)})` : ''}`} />
            </MenuItem>
          )}
          {R.includes('attribution', availableSections) && (
            <MenuItem
              component={Link}
              to={`${stixCoreObjectLink}/attribution`}
              selected={
                location.pathname === `${stixCoreObjectLink}/attribution`
              }
              dense={true}
              classes={{ root: classes.item }}
            >
              <ListItemIcon style={{ minWidth: 28 }}>
                <ItemIcon size="small" type="attribution" />
              </ListItemIcon>
              <ListItemText primary={`${t_i18n('Attribution')}${statisticsAttributions > 0 ? ` (${n(statisticsAttributions)})` : ''}`} />
            </MenuItem>
          )}
          {R.includes('victimology', availableSections) && (
            <MenuItem
              component={Link}
              to={`${stixCoreObjectLink}/victimology`}
              selected={
                location.pathname === `${stixCoreObjectLink}/victimology`
              }
              dense={true}
              classes={{ root: classes.item }}
            >
              <ListItemIcon style={{ minWidth: 28 }}>
                <ItemIcon size="small" type="victimology" />
              </ListItemIcon>
              <ListItemText primary={`${t_i18n('Victimology')}${statisticsVictims > 0 ? ` (${n(statisticsVictims)})` : ''}`} />
            </MenuItem>
          )}
          {R.includes('threat_actors', availableSections) && (
            <MenuItem
              component={Link}
              to={`${stixCoreObjectLink}/threat_actors`}
              selected={
                location.pathname === `${stixCoreObjectLink}/threat_actors`
              }
              dense={true}
              classes={{ root: classes.item }}
            >
              <ListItemIcon style={{ minWidth: 28 }}>
                <ItemIcon size="small" type="Threat-Actor-Individual" />
              </ListItemIcon>
              <ListItemText primary={`${t_i18n('Threat actors')}${statisticsThreatActors > 0 ? ` (${n(statisticsThreatActors)})` : ''}`} />
            </MenuItem>
          )}
          {R.includes('intrusion_sets', availableSections) && (
            <MenuItem
              component={Link}
              to={`${stixCoreObjectLink}/intrusion_sets`}
              selected={
                location.pathname === `${stixCoreObjectLink}/intrusion_sets`
              }
              dense={true}
              classes={{ root: classes.item }}
            >
              <ListItemIcon style={{ minWidth: 28 }}>
                <ItemIcon size="small" type="Intrusion-Set" />
              </ListItemIcon>
              <ListItemText primary={`${t_i18n('Intrusion sets')}${statistics['Intrusion-Set'] && statistics['Intrusion-Set'].value > 0 ? ` (${n(statistics['Intrusion-Set'].value)})` : ''}`} />
            </MenuItem>
          )}
          {R.includes('campaigns', availableSections) && (
            <MenuItem
              component={Link}
              to={`${stixCoreObjectLink}/campaigns`}
              selected={location.pathname === `${stixCoreObjectLink}/campaigns`}
              dense={true}
              classes={{ root: classes.item }}
            >
              <ListItemIcon style={{ minWidth: 28 }}>
                <ItemIcon size="small" type="Campaign" />
              </ListItemIcon>
              <ListItemText primary={`${t_i18n('Campaigns')}${statistics.Campaign && statistics.Campaign.value > 0 ? ` (${n(statistics.Campaign.value)})` : ''}`} />
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
            <ListSubheader style={{ height: 35 }}>{t_i18n('Arsenal')}</ListSubheader>
          }
        >
          {R.includes('variants', availableSections) && (
            <MenuItem
              component={Link}
              to={`${stixCoreObjectLink}/variants`}
              selected={location.pathname === `${stixCoreObjectLink}/variants`}
              dense={true}
              classes={{ root: classes.item }}
            >
              <ListItemIcon style={{ minWidth: 28 }}>
                <ItemIcon size="small" type="variant" />
              </ListItemIcon>
              <ListItemText primary={`${t_i18n('Variants')}${statistics.Malware && statistics.Malware.value > 0 ? ` (${n(statistics.Malware.value)})` : ''}`} />
            </MenuItem>
          )}
          {R.includes('malwares', availableSections) && (
            <MenuItem
              component={Link}
              to={`${stixCoreObjectLink}/malwares`}
              selected={location.pathname === `${stixCoreObjectLink}/malwares`}
              dense={true}
              classes={{ root: classes.item }}
            >
              <ListItemIcon style={{ minWidth: 28 }}>
                <ItemIcon size="small" type="Malware" />
              </ListItemIcon>
              <ListItemText primary={`${t_i18n('Malwares')}${statistics.Malware && statistics.Malware.value > 0 ? ` (${n(statistics.Malware.value)})` : ''}`} />
            </MenuItem>
          )}
          {R.includes('channels', availableSections) && (
            <MenuItem
              component={Link}
              to={`${stixCoreObjectLink}/channels`}
              selected={location.pathname === `${stixCoreObjectLink}/channels`}
              dense={true}
              classes={{ root: classes.item }}
            >
              <ListItemIcon style={{ minWidth: 28 }}>
                <ItemIcon size="small" type="Channel" />
              </ListItemIcon>
              <ListItemText primary={`${t_i18n('Channels')}${statistics.Channel && statistics.Channel.value > 0 ? ` (${n(statistics.Channel.value)})` : ''}`} />
            </MenuItem>
          )}
          {R.includes('tools', availableSections) && (
            <MenuItem
              component={Link}
              to={`${stixCoreObjectLink}/tools`}
              selected={location.pathname === `${stixCoreObjectLink}/tools`}
              dense={true}
              classes={{ root: classes.item }}
            >
              <ListItemIcon style={{ minWidth: 28 }}>
                <ItemIcon size="small" type="tool" />
              </ListItemIcon>
              <ListItemText primary={`${t_i18n('Tools')}${statistics.Tool && statistics.Tool.value > 0 ? ` (${n(statistics.Tool.value)})` : ''}`} />
            </MenuItem>
          )}
          {R.includes('vulnerabilities', availableSections) && (
            <MenuItem
              component={Link}
              to={`${stixCoreObjectLink}/vulnerabilities`}
              selected={
                location.pathname === `${stixCoreObjectLink}/vulnerabilities`
              }
              dense={true}
              classes={{ root: classes.item }}
            >
              <ListItemIcon style={{ minWidth: 28 }}>
                <ItemIcon size="small" type="Vulnerability" />
              </ListItemIcon>
              <ListItemText primary={`${t_i18n('Vulnerabilities')}${statistics.Vulnerability && statistics.Vulnerability.value > 0 ? ` (${n(statistics.Vulnerability.value)})` : ''}`} />
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
              {t_i18n('Techniques')}
            </ListSubheader>
          }
        >
          {R.includes('attack_patterns', availableSections) && (
            <MenuItem
              component={Link}
              to={`${stixCoreObjectLink}/attack_patterns`}
              selected={
                location.pathname === `${stixCoreObjectLink}/attack_patterns`
              }
              dense={true}
              classes={{ root: classes.item }}
            >
              <ListItemIcon style={{ minWidth: 28 }}>
                <ItemIcon size="small" type="Attack-Pattern" />
              </ListItemIcon>
              <ListItemText primary={`${t_i18n('Attack patterns')}${statistics['Attack-Pattern'] && statistics['Attack-Pattern'].value > 0 ? ` (${n(statistics['Attack-Pattern'].value)})` : ''}`} />
            </MenuItem>
          )}
          {R.includes('narratives', availableSections) && (
            <MenuItem
              component={Link}
              to={`${stixCoreObjectLink}/narratives`}
              selected={
                location.pathname === `${stixCoreObjectLink}/narratives`
              }
              dense={true}
              classes={{ root: classes.item }}
            >
              <ListItemIcon style={{ minWidth: 28 }}>
                <ItemIcon size="small" type="Narrative" />
              </ListItemIcon>
              <ListItemText primary={`${t_i18n('Narratives')}${statistics.Narrative && statistics.Narrative.value > 0 ? ` (${n(statistics.Narrative.value)})` : ''}`} />
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
              {t_i18n('Observations')}
            </ListSubheader>
          }
        >
          {R.includes('indicators', availableSections) && (
            <MenuItem
              component={Link}
              to={`${stixCoreObjectLink}/indicators`}
              selected={
                location.pathname === `${stixCoreObjectLink}/indicators`
              }
              dense={true}
              classes={{ root: classes.item }}
            >
              <ListItemIcon style={{ minWidth: 28 }}>
                <ItemIcon size="small" type="Indicator" />
              </ListItemIcon>
              <ListItemText primary={`${t_i18n('Indicators')}${statistics.Indicator && statistics.Indicator.value > 0 ? ` (${n(statistics.Indicator.value)})` : ''}`} />
            </MenuItem>
          )}
          {R.includes('observables', availableSections) && (
            <MenuItem
              component={Link}
              to={`${stixCoreObjectLink}/observables`}
              selected={
                location.pathname === `${stixCoreObjectLink}/observables`
              }
              dense={true}
              classes={{ root: classes.item }}
            >
              <ListItemIcon style={{ minWidth: 28 }}>
                <ItemIcon size="small" type="Stix-Cyber-Observable" />
              </ListItemIcon>
              <ListItemText primary={t_i18n('Observables')} />
            </MenuItem>
          )}
          {R.includes('infrastructures', availableSections) && (
            <MenuItem
              component={Link}
              to={`${stixCoreObjectLink}/infrastructures`}
              selected={
                location.pathname === `${stixCoreObjectLink}/infrastructures`
              }
              dense={true}
              classes={{ root: classes.item }}
            >
              <ListItemIcon style={{ minWidth: 28 }}>
                <ItemIcon size="small" type="Infrastructure" />
              </ListItemIcon>
              <ListItemText primary={`${t_i18n('Infrastructures')}${statistics.Infrastructure && statistics.Infrastructure.value > 0 ? ` (${n(statistics.Infrastructure.value)})` : ''}`} />
            </MenuItem>
          )}
        </MenuList>
      )}
      {isInAvailableSection(['incidents', 'observed_data', 'sightings']) && (
        <MenuList
          style={{ paddingBottom: 0 }}
          component="nav"
          subheader={
            <ListSubheader style={{ height: 35 }}>{t_i18n('Events')}</ListSubheader>
          }
        >
          {R.includes('incidents', availableSections) && (
            <MenuItem
              component={Link}
              to={`${stixCoreObjectLink}/incidents`}
              selected={location.pathname === `${stixCoreObjectLink}/incidents`}
              dense={true}
              classes={{ root: classes.item }}
            >
              <ListItemIcon style={{ minWidth: 28 }}>
                <ItemIcon size="small" type="Incident" />
              </ListItemIcon>
              <ListItemText primary={`${t_i18n('Incidents')}${statistics.Incident && statistics.Incident.value > 0 ? ` (${n(statistics.Incident.value)})` : ''}`} />
            </MenuItem>
          )}
          {R.includes('observed_data', availableSections) && (
            <MenuItem
              component={Link}
              to={`${stixCoreObjectLink}/observed_data`}
              selected={
                location.pathname === `${stixCoreObjectLink}/observed_data`
              }
              dense={true}
              classes={{ root: classes.item }}
            >
              <ListItemIcon style={{ minWidth: 28 }}>
                <ItemIcon size="small" type="Observed-Data" />
              </ListItemIcon>
              <ListItemText primary={`${t_i18n('Observed data')}${statistics['Observed-Data'] && statistics['Observed-Data'].value > 0 ? ` (${n(statistics['Observed-Data'].value)})` : ''}`} />
            </MenuItem>
          )}
          {R.includes('sightings', availableSections) && (
            <MenuItem
              component={Link}
              to={`${stixCoreObjectLink}/sightings`}
              selected={location.pathname === `${stixCoreObjectLink}/sightings`}
              dense={true}
              classes={{ root: classes.item }}
            >
              <ListItemIcon style={{ minWidth: 28 }}>
                <ItemIcon size="small" type="sighting" />
              </ListItemIcon>
              <ListItemText primary={t_i18n('Sightings')} />
            </MenuItem>
          )}
        </MenuList>
      )}
      <MenuList
        style={{ paddingBottom: 0 }}
        sx={{ marginBottom: bannerSettings.bannerHeight }}
        component="nav"
        subheader={
          <ListSubheader style={{ height: 35 }}>{t_i18n('Other')}</ListSubheader>
        }
      >
        <MenuItem
          component={Link}
          to={`${stixCoreObjectLink}/related`}
          selected={location.pathname === `${stixCoreObjectLink}/related`}
          dense={true}
          classes={{ root: classes.item }}
        >
          <ListItemIcon style={{ minWidth: 28 }}>
            <ItemIcon size="small" type="related" />
          </ListItemIcon>
          <ListItemText primary={t_i18n('Related entities')} />
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
