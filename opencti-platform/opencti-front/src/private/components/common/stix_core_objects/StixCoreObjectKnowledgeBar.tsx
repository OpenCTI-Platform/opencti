import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import Drawer from '@mui/material/Drawer';
import MenuList from '@mui/material/MenuList';
import MenuItem from '@mui/material/MenuItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListSubheader from '@mui/material/ListSubheader';
import { graphql, useFragment } from 'react-relay';
import {
  StixCoreObjectKnowledgeBar_stixCoreObject$data,
  StixCoreObjectKnowledgeBar_stixCoreObject$key,
} from '@components/common/stix_core_objects/__generated__/StixCoreObjectKnowledgeBar_stixCoreObject.graphql';
import { useTheme } from '@mui/styles';
import Box from '@mui/material/Box';
import { useFormatter } from '../../../../components/i18n';
import useAuth from '../../../../utils/hooks/useAuth';
import { useSettingsMessagesBannerHeight } from '../../settings/settings_messages/SettingsMessagesBanner';
import ItemIcon from '../../../../components/ItemIcon';
import type { Theme } from '../../../../components/Theme';

const stixCoreObjectKnowledgeBarFragment = graphql`
  fragment StixCoreObjectKnowledgeBar_stixCoreObject on StixCoreObject
  @argumentDefinitions(
    relatedRelationshipTypes: { type: "[String]", defaultValue: ["related-to"] }
  ) {
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
        "variant-of"
      ]
    ) {
      label
      value
    }
    # distribution of entities with relatedRelationshipTypes ("related to" relationship by default)
    relationshipsRelatedDistribution: stixCoreRelationshipsDistribution(
      field: "entity_type"
      operation: count
      relationship_type: $relatedRelationshipTypes
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
  }
`;

type ObjectsDistribution = StixCoreObjectKnowledgeBar_stixCoreObject$data['relationshipsWithoutRelatedToDistribution']
| StixCoreObjectKnowledgeBar_stixCoreObject$data['relationshipsRelatedDistribution']
| StixCoreObjectKnowledgeBar_stixCoreObject$data['stixCoreObjectsDistribution'];

interface StixCoreObjectKnowledgeBarProps {
  stixCoreObjectLink: string;
  availableSections: string[];
  data: StixCoreObjectKnowledgeBar_stixCoreObject$key;
  attribution?: string[];
}

interface SectionConfig {
  title: string;
  items: {
    label: string;
    iconType: string;
    path: string;
    count: number;
  }[];
}

interface KnowledgeBarProps {
  to: string;
  iconType: string;
  label: string;
  count: number;
}

const KnowledgeBarItem = ({ to, iconType, label, count }: KnowledgeBarProps) => {
  const location = useLocation();
  const { t_i18n, n } = useFormatter();

  return (
    <MenuItem
      component={Link}
      to={to}
      selected={location.pathname === to}
      dense={true}
      sx={{ height: 38, fontSize: 9 }}
    >
      <ListItemIcon style={{ minWidth: 28 }}>
        <ItemIcon size="small" type={iconType} />
      </ListItemIcon>
      <ListItemText primary={`${t_i18n(label)}${count > 0 ? ` (${n(count)})` : ''}`} />
    </MenuItem>
  );
};

const StixCoreObjectKnowledgeBar = ({
  stixCoreObjectLink,
  availableSections,
  data,
  attribution,
}: StixCoreObjectKnowledgeBarProps) => {
  const theme = useTheme<Theme>();
  const { bannerSettings, schema } = useAuth();
  const settingsMessagesBannerHeight = useSettingsMessagesBannerHeight();
  const {
    relationshipsWithoutRelatedToDistribution,
    relationshipsRelatedDistribution,
    stixCoreObjectsDistribution,
  } = useFragment(stixCoreObjectKnowledgeBarFragment, data);

  const indexEntities = (distribution: ObjectsDistribution) : Record<string, number> => (
    distribution?.reduce((acc, item) => ({
      ...acc,
      ...(item?.label ? { [item.label]: item.value || 0 } : {}),
    }), {}) || {}
  );

  const distributions = {
    withoutRelated: indexEntities(relationshipsWithoutRelatedToDistribution),
    related: indexEntities(relationshipsRelatedDistribution),
    coreObjects: indexEntities(stixCoreObjectsDistribution),
  };

  const sumEntitiesByKeys = (source: Record<string, number>, keys?: string[]) => {
    if (keys) {
      return keys.reduce((sum, key) => sum + (source[key] || 0), 0);
    }
    return Object.values(source).reduce((sum: number, val) => sum + val, 0);
  };

  const sectionsConfig: SectionConfig[] = [
    {
      title: 'Entities',
      items: [
        {
          label: 'Sectors',
          iconType: 'Sector',
          path: 'sectors',
          count: distributions.coreObjects.Sector || 0,
        },
        {
          label: 'Regions',
          iconType: 'Region',
          path: 'regions',
          count: distributions.coreObjects.Region || 0,
        },
        {
          label: 'Countries',
          iconType: 'Country',
          path: 'countries',
          count: distributions.coreObjects.Country || 0,
        },
        {
          label: 'Areas',
          iconType: 'Administrative-Area',
          path: 'areas',
          count: distributions.coreObjects['Administrative-Area'] || 0,
        },
        {
          label: 'Cities',
          iconType: 'City',
          path: 'cities',
          count: distributions.coreObjects.City || 0,
        },
        {
          label: 'Organizations',
          iconType: 'Organization',
          path: 'organizations',
          count: distributions.coreObjects.Organization || 0,
        },
        {
          label: 'Individuals',
          iconType: 'Individual',
          path: 'individuals',
          count: distributions.coreObjects.Individual || 0,
        },
        {
          label: 'Locations',
          iconType: 'Location',
          path: 'locations',
          count: sumEntitiesByKeys(
            distributions.withoutRelated,
            ['Region', 'Country', 'City', 'Position', 'Administrative-Area'],
          ),
        },
        {
          label: 'Used tools',
          iconType: 'Tool',
          path: 'used_tools',
          count: distributions.coreObjects.Tool || 0,
        },
      ].filter((item) => availableSections.includes(item.path)),
    },
    {
      title: 'Threats',
      items: [
        {
          label: 'All threats',
          iconType: 'threats',
          path: 'threats',
          count: sumEntitiesByKeys(
            distributions.withoutRelated,
            ['Threat-Actor-Individual', 'Threat-Actor-Group', 'Intrusion-Set', 'Campaign', 'Incident'],
          ),
        },
        {
          label: 'Attribution',
          iconType: 'attribution',
          path: 'attribution',
          count: sumEntitiesByKeys(distributions.withoutRelated, attribution ?? []),
        },
        {
          label: 'Victimology',
          iconType: 'victimology',
          path: 'victimology',
          count: sumEntitiesByKeys(
            distributions.withoutRelated,
            ['Event', 'System', 'Sector', 'Organization', 'Individual', 'Region', 'Country', 'City', 'Position'],
          ),
        },
        {
          label: 'Threat actors',
          iconType: 'Threat-Actor-Individual',
          path: 'threat_actors',
          count: sumEntitiesByKeys(
            distributions.withoutRelated,
            ['Threat-Actor-Individual', 'Threat-Actor-Group'],
          ),
        },
        {
          label: 'Intrusion sets',
          iconType: 'Intrusion-Set',
          path: 'intrusion_sets',
          count: distributions.withoutRelated['Intrusion-Set'] || 0,
        },
        {
          label: 'Campaigns',
          iconType: 'Campaign',
          path: 'campaigns',
          count: distributions.withoutRelated.Campaign || 0,
        },
      ].filter((item) => availableSections.includes(item.path)),
    },
    {
      title: 'Arsenal',
      items: [
        {
          label: 'Variants',
          iconType: 'variant',
          path: 'variants',
          count: distributions.withoutRelated.Malware || 0,
        },
        {
          label: 'Malwares',
          iconType: 'Malware',
          path: 'malwares',
          count: distributions.withoutRelated.Malware || 0,
        },
        {
          label: 'Channels',
          iconType: 'Channel',
          path: 'channels',
          count: distributions.withoutRelated.Channel || 0,
        },
        {
          label: 'Tools',
          iconType: 'tool',
          path: 'tools',
          count: distributions.withoutRelated.Tool || 0,
        },
        {
          label: 'Vulnerabilities',
          iconType: 'Vulnerability',
          path: 'vulnerabilities',
          count: distributions.withoutRelated.Vulnerability || 0,
        },
      ].filter((item) => availableSections.includes(item.path)),
    },
    {
      title: 'Techniques',
      items: [
        {
          label: 'Attack patterns',
          iconType: 'Attack-Pattern',
          path: 'attack_patterns',
          count: distributions.coreObjects['Attack-Pattern'] || 0,
        },
        {
          label: 'Narratives',
          iconType: 'Narrative',
          path: 'narratives',
          count: distributions.withoutRelated.Narrative || 0,
        },
      ].filter((item) => availableSections.includes(item.path)),
    },
    {
      title: 'Observations',
      items: [
        {
          label: 'Indicators',
          iconType: 'Indicator',
          path: 'indicators',
          count: distributions.coreObjects.Indicator || 0,
        },
        {
          label: 'Observables',
          iconType: 'Stix-Cyber-Observable',
          path: 'observables',
          count: sumEntitiesByKeys(distributions.related, [...schema.scos.map((s) => s.id), 'Stixfile', 'Ipv4-Addr', 'Ipv6-Addr']),
        },
        {
          label: 'Infrastructures',
          iconType: 'Infrastructure',
          path: 'infrastructures',
          count: distributions.withoutRelated.Infrastructure || 0,
        },
      ].filter((item) => availableSections.includes(item.path)),
    },
    {
      title: 'Events',
      items: [
        {
          label: 'Incidents',
          iconType: 'Incident',
          path: 'incidents',
          count: distributions.withoutRelated.Incident || 0,
        },
        {
          label: 'Observed data',
          iconType: 'Observed-Data',
          path: 'observed_data',
          count: distributions.withoutRelated['Observed-Data'] || 0,
        },
        {
          label: 'Sightings',
          iconType: 'sighting',
          path: 'sightings',
          count: 0,
        },
      ].filter((item) => availableSections.includes(item.path)),
    },
    {
      title: 'Other',
      items: [
        {
          label: 'Related entities',
          iconType: 'related',
          path: 'related',
          count: sumEntitiesByKeys(distributions.related),
        },
      ],
    },
  ];

  return (
    <Drawer
      variant="permanent"
      anchor="right"
      sx={{
        '& .MuiPaper-root': {
          minHeight: '100vh',
          width: 200,
          position: 'fixed',
          overflow: 'auto',
          padding: 0,
          zIndex: 2,
          background: theme.palette.background.nav,
        },
      }}
    >
      <Box sx={{ ...theme.mixins.toolbar }} />
      <MenuList
        component="nav"
        style={{
          marginTop: bannerSettings.bannerHeightNumber + settingsMessagesBannerHeight,
          paddingBottom: 0,
        }}
      >
        <KnowledgeBarItem
          to={`${stixCoreObjectLink}/overview`}
          iconType="overview"
          label="Overview"
          count={0}
        />
        {sectionsConfig.map((section, index) => (
          section.items.length > 0 && (
            <MenuList component="nav" key={index} style={{ paddingBlock: 0 }}>
              {section.title && (
                <ListSubheader style={{ height: 35 }}>
                  {section.title}
                </ListSubheader>
              )}
              {section.items.map(({ path, label, iconType, count }) => (
                <KnowledgeBarItem
                  key={label}
                  to={`${stixCoreObjectLink}/${path}`}
                  iconType={iconType}
                  label={label}
                  count={count}
                />
              ))}
            </MenuList>
          )
        ))}
      </MenuList>
    </Drawer>
  );
};

export default StixCoreObjectKnowledgeBar;
