import React from 'react';
import PropTypes from 'prop-types';
import { Link, useLocation } from 'react-router-dom';
import Drawer from '@mui/material/Drawer';
import makeStyles from '@mui/styles/makeStyles';
import MenuList from '@mui/material/MenuList';
import MenuItem from '@mui/material/MenuItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListSubheader from '@mui/material/ListSubheader';
import { graphql, useFragment } from 'react-relay';
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

const stixCoreObjectKnowledgeBarFragment = graphql`
  fragment StixCoreObjectKnowledgeBar_stixCoreObject on StixCoreObject {
    # distribution of entities without "related to" relationship
    relationshipsWithoutRelatedToDistribution: stixCoreRelationshipsDistribution(
      field: "entity_type"
      operation: count
      relationship_type: [
        "part-of"
        "cooperates-with"
        "employed-by"
        "derived-from"
        "attributed-to"
        "participates-in"
        "uses"
        "authored-by"
        "targets"
        "compromises"
        "located-at"
      ]
    ) {
      label
      value
    }
    # distribution for observable and indicator type
    stixCoreObjectsDistribution(
      field: "entity_type",
      operation: count,
      ) {
      label
      value
    }
    relatedEntities: stixCoreRelationships(relationship_type: "related-to") {
      pageInfo {
        globalCount
      }
    }
  }
`;

const StixCoreObjectKnowledgeBar = ({
  stixCoreObjectLink,
  availableSections,
  data,
  attribution,
}) => {
  const { t_i18n, n } = useFormatter();
  const classes = useStyles();
  const location = useLocation();
  const { bannerSettings, schema } = useAuth();
  const isInAvailableSection = (sections) => availableSections.some((filter) => sections.includes(filter));
  const { relationshipsWithoutRelatedToDistribution, stixCoreObjectsDistribution, relatedEntities } = useFragment(
    stixCoreObjectKnowledgeBarFragment,
    data,
  );
  const settingsMessagesBannerHeight = useSettingsMessagesBannerHeight();

  const indexEntities = (objectsDistribution) => (objectsDistribution
    ? objectsDistribution.reduce((acc, item) => ({ ...acc, [item.label]: item }), {})
    : {});

  const statisticsRelationship = indexEntities(relationshipsWithoutRelatedToDistribution);
  const statisticsCoreObjects = indexEntities(stixCoreObjectsDistribution);

  const sumEntitiesByKeys = (keys, stats) => keys
    .map((key) => stats[key]?.value || 0)
    .reduce((acc, val) => acc + val, 0);

  const statisticsThreats = sumEntitiesByKeys(['Threat-Actor-Individual', 'Threat-Actor-Group', 'Intrusion-Set', 'Campaign', 'Incident'], statisticsRelationship);
  const statisticsThreatActors = sumEntitiesByKeys(['Threat-Actor-Individual', 'Threat-Actor-Group'], statisticsRelationship);
  const statisticsVictims = sumEntitiesByKeys(['Sector', 'Organization', 'Individual', 'Region', 'Country', 'City', 'Position', 'Administrative-Area'], statisticsRelationship);
  const statisticsAttributions = sumEntitiesByKeys(attribution ?? [], statisticsRelationship);
  const statisticsLocations = sumEntitiesByKeys(['Region', 'Country', 'City', 'Position', 'Administrative-Area'], statisticsRelationship);
  const statisticsObservables = sumEntitiesByKeys([...schema.scos.map((s) => s.id), 'Stixfile', 'Ipv4-Addr', 'Ipv6-Addr'], statisticsCoreObjects);
  const statisticsRelatedEntities = relatedEntities ? relatedEntities.pageInfo.globalCount : 0;

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
            {availableSections.includes('sectors') && (
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
                <ListItemText primary={`${t_i18n('Sectors')}${statisticsRelationship.Sector && statisticsRelationship.Sector.value > 0 ? ` (${n(statisticsRelationship.Sector.value)})` : ''}`} />
              </MenuItem>
            )}
            {availableSections.includes('regions') && (
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
                <ListItemText primary={`${t_i18n('Regions')}${statisticsRelationship.Region && statisticsRelationship.Region.value > 0 ? ` (${n(statisticsRelationship.Region.value)})` : ''}`} />
              </MenuItem>
            )}
            {availableSections.includes('countries') && (
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
                <ListItemText primary={`${t_i18n('Countries')}${statisticsRelationship.Country && statisticsRelationship.Country.value > 0 ? ` (${n(statisticsRelationship.Country.value)})` : ''}`} />
              </MenuItem>
            )}
            {availableSections.includes('areas') && (
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
                <ListItemText primary={`${t_i18n('Areas')}${statisticsRelationship['Administrative-Area'] && statisticsRelationship['Administrative-Area'].value > 0 ? ` (${n(statisticsRelationship['Administrative-Area'].value)})` : ''}`} />
              </MenuItem>
            )}
            {availableSections.includes('cities') && (
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
                <ListItemText primary={`${t_i18n('Cities')}${statisticsRelationship.City && statisticsRelationship.City.value > 0 ? ` (${n(statisticsRelationship.City.value)})` : ''}`} />
              </MenuItem>
            )}
            {availableSections.includes('organizations') && (
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
                <ListItemText primary={`${t_i18n('Organizations')}${statisticsRelationship.Organization && statisticsRelationship.Organization.value > 0 ? ` (${n(statisticsRelationship.Organization.value)})` : ''}`} />
              </MenuItem>
            )}
            {availableSections.includes('individuals') && (
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
                <ListItemText primary={`${t_i18n('Individuals')}${statisticsRelationship.Individual && statisticsRelationship.Individual.value > 0 ? ` (${n(statisticsRelationship.Individual.value)})` : ''}`} />
              </MenuItem>
            )}
            {availableSections.includes('locations') && (
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
            {availableSections.includes('used_tools') && (
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
            {availableSections.includes('sectors') && (
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
                <ListItemText primary={`${t_i18n('Sectors')}${statisticsRelationship.Sector && statisticsRelationship.Sector.value > 0 ? ` (${n(statisticsRelationship.Sector.value)})` : ''}`} />
              </MenuItem>
            )}
            {availableSections.includes('regions') && (
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
                <ListItemText primary={`${t_i18n('Regions')}${statisticsRelationship.Region && statisticsRelationship.Region.value > 0 ? ` (${n(statisticsRelationship.Region.value)})` : ''}`} />
              </MenuItem>
            )}
            {availableSections.includes('countries') && (
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
                <ListItemText primary={`${t_i18n('Countries')}${statisticsRelationship.Country && statisticsRelationship.Country.value > 0 ? ` (${n(statisticsRelationship.Country.value)})` : ''}`} />
              </MenuItem>
            )}
            {availableSections.includes('areas') && (
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
                <ListItemText primary={`${t_i18n('Areas')}${statisticsRelationship['Administrative-Area'] && statisticsRelationship['Administrative-Area'].value > 0 ? ` (${n(statisticsRelationship['Administrative-Area'].value)})` : ''}`} />
              </MenuItem>
            )}
            {availableSections.includes('cities') && (
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
                <ListItemText primary={`${t_i18n('Cities')}${statisticsRelationship.City && statisticsRelationship.City.value > 0 ? ` (${n(statisticsRelationship.City.value)})` : ''}`} />
              </MenuItem>
            )}
            {availableSections.includes('locations') && (
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
            {availableSections.includes('organizations') && (
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
                <ListItemText primary={`${t_i18n('Organizations')}${statisticsRelationship.Organization && statisticsRelationship.Organization.value > 0 ? ` (${n(statisticsRelationship.Organization.value)})` : ''}`} />
              </MenuItem>
            )}
            {availableSections.includes('individuals') && (
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
                <ListItemText primary={`${t_i18n('Individuals')}${statisticsRelationship.Individual && statisticsRelationship.Individual.value > 0 ? ` (${n(statisticsRelationship.Individual.value)})` : ''}`} />
              </MenuItem>
            )}
            {availableSections.includes('used_tools') && (
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
          {availableSections.includes('threats') && (
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
          {availableSections.includes('attribution') && (
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
          {availableSections.includes('victimology') && (
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
          {availableSections.includes('threat_actors') && (
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
          {availableSections.includes('intrusion_sets') && (
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
              <ListItemText primary={`${t_i18n('Intrusion sets')}${statisticsRelationship['Intrusion-Set'] && statisticsRelationship['Intrusion-Set'].value > 0 ? ` (${n(statisticsRelationship['Intrusion-Set'].value)})` : ''}`} />
            </MenuItem>
          )}
          {availableSections.includes('campaigns') && (
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
              <ListItemText primary={`${t_i18n('Campaigns')}${statisticsRelationship.Campaign && statisticsRelationship.Campaign.value > 0 ? ` (${n(statisticsRelationship.Campaign.value)})` : ''}`} />
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
          {availableSections.includes('variants') && (
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
              <ListItemText primary={`${t_i18n('Variants')}${statisticsRelationship.Malware && statisticsRelationship.Malware.value > 0 ? ` (${n(statisticsRelationship.Malware.value)})` : ''}`} />
            </MenuItem>
          )}
          {availableSections.includes('malwares') && (
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
              <ListItemText primary={`${t_i18n('Malwares')}${statisticsRelationship.Malware && statisticsRelationship.Malware.value > 0 ? ` (${n(statisticsRelationship.Malware.value)})` : ''}`} />
            </MenuItem>
          )}
          {availableSections.includes('channels') && (
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
              <ListItemText primary={`${t_i18n('Channels')}${statisticsRelationship.Channel && statisticsRelationship.Channel.value > 0 ? ` (${n(statisticsRelationship.Channel.value)})` : ''}`} />
            </MenuItem>
          )}
          {availableSections.includes('tools') && (
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
              <ListItemText primary={`${t_i18n('Tools')}${statisticsRelationship.Tool && statisticsRelationship.Tool.value > 0 ? ` (${n(statisticsRelationship.Tool.value)})` : ''}`} />
            </MenuItem>
          )}
          {availableSections.includes('vulnerabilities') && (
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
              <ListItemText primary={`${t_i18n('Vulnerabilities')}${statisticsRelationship.Vulnerability && statisticsRelationship.Vulnerability.value > 0 ? ` (${n(statisticsRelationship.Vulnerability.value)})` : ''}`} />
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
          {availableSections.includes('attack_patterns') && (
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
              <ListItemText primary={`${t_i18n('Attack patterns')}${statisticsRelationship['Attack-Pattern'] && statisticsRelationship['Attack-Pattern'].value > 0 ? ` (${n(statisticsRelationship['Attack-Pattern'].value)})` : ''}`} />
            </MenuItem>
          )}
          {availableSections.includes('narratives') && (
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
              <ListItemText primary={`${t_i18n('Narratives')}${statisticsRelationship.Narrative && statisticsRelationship.Narrative.value > 0 ? ` (${n(statisticsRelationship.Narrative.value)})` : ''}`} />
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
          {availableSections.includes('indicators') && (
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
              <ListItemText primary={`${t_i18n('Indicators')}${statisticsCoreObjects.Indicator && statisticsCoreObjects.Indicator.value > 0 ? ` (${n(statisticsCoreObjects.Indicator.value)})` : ''}`} />
            </MenuItem>
          )}
          {availableSections.includes('observables') && (
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
              <ListItemText primary={`${t_i18n('Observables')}${statisticsObservables > 0 ? ` (${n(statisticsObservables)})` : ''}`} />
            </MenuItem>
          )}
          {availableSections.includes('infrastructures') && (
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
              <ListItemText primary={`${t_i18n('Infrastructures')}${statisticsRelationship.Infrastructure && statisticsRelationship.Infrastructure.value > 0 ? ` (${n(statisticsRelationship.Infrastructure.value)})` : ''}`} />
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
          {availableSections.includes('incidents') && (
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
              <ListItemText primary={`${t_i18n('Incidents')}${statisticsRelationship.Incident && statisticsRelationship.Incident.value > 0 ? ` (${n(statisticsRelationship.Incident.value)})` : ''}`} />
            </MenuItem>
          )}
          {availableSections.includes('observed_data') && (
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
              <ListItemText primary={`${t_i18n('Observed data')}${statisticsRelationship['Observed-Data'] && statisticsRelationship['Observed-Data'].value > 0 ? ` (${n(statisticsRelationship['Observed-Data'].value)})` : ''}`} />
            </MenuItem>
          )}
          {availableSections.includes('sightings') && (
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
          <ListItemText primary={`${t_i18n('Related entities')}${statisticsRelatedEntities > 0 ? ` (${n(statisticsRelatedEntities)})` : ''}`} />
        </MenuItem>
      </MenuList>
    </Drawer>
  );
};

StixCoreObjectKnowledgeBar.propTypes = {
  id: PropTypes.string,
  stixCoreObjectLink: PropTypes.string,
  availableSections: PropTypes.array,
  data: PropTypes.object,
  attribution: PropTypes.arrayOf(PropTypes.string),
};

export default StixCoreObjectKnowledgeBar;
