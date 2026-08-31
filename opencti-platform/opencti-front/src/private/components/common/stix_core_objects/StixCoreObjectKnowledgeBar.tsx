import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import Drawer from '@mui/material/Drawer';
import { NavbarItem, NavbarTitle } from '@filigran/design-system';
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
import useDraftContext from '../../../../utils/hooks/useDraftContext';
import { RIGHT_BAR_LAYER, fdsLayerClass, layerInputVars } from '../../../../utils/fdsLayer';

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
        "belongs-to"
        "technology"
        "technology-to"
        "technology-from"
        "interpreted-by"
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
    count?: number;
  }[];
}

interface KnowledgeBarProps {
  to: string;
  iconType: string;
  label: string;
  count: number;
}

/**
 * One row of the tab-scoped right bar.
 *
 * `NavbarItem` is the library's single navigation row — the same component the
 * left rail uses, and the one Figma places in this bar (node 7472:48226,
 * instances named `navbar menu item`). It carries the 36px height, the 14px
 * label and the hover/selected tones; the bar only has to declare its layer
 * for those tones to resolve (see the Drawer paper below).
 *
 * `asChild` slots the router `Link` in as the row itself, which means the icon
 * and the label are composed here rather than passed as props — Slot cannot
 * inject markup inside an arbitrary child. Selection is the native
 * `aria-current="page"`, which is what the row styles off.
 */
const KnowledgeBarItem = ({ to, iconType, label, count }: KnowledgeBarProps) => {
  const location = useLocation();
  const { t_i18n, n } = useFormatter();
  const text = `${t_i18n(label)}${count > 0 ? ` (${n(count)})` : ''}`;

  return (
    <NavbarItem asChild tooltipLabel={text}>
      <Link to={to} aria-current={location.pathname === to ? 'page' : undefined}>
        <span aria-hidden="true" className="flex shrink-0 items-center justify-center">
          <ItemIcon size="small" type={iconType} />
        </span>
        <span className="flex-1 truncate text-left">{text}</span>
      </Link>
    </NavbarItem>
  );
};

const StixCoreObjectKnowledgeBar = ({
  stixCoreObjectLink,
  availableSections,
  data,
  attribution,
}: StixCoreObjectKnowledgeBarProps) => {
  const theme = useTheme<Theme>();
  const draftContext = useDraftContext();
  const { bannerSettings, schema } = useAuth();
  const settingsMessagesBannerHeight = useSettingsMessagesBannerHeight();
  const {
    relationshipsWithoutRelatedToDistribution,
    relationshipsRelatedDistribution,
    stixCoreObjectsDistribution,
  } = useFragment(stixCoreObjectKnowledgeBarFragment, data);

  const indexEntities = (distribution: ObjectsDistribution): Record<string, number> => (
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
      title: 'All entities',
      items: [
        {
          label: 'All',
          iconType: 'All',
          path: 'all',
        },
      ],
    },
    {
      title: 'Entities',
      items: [
        {
          label: 'Sectors',
          iconType: 'Sector',
          path: 'sectors',
          count: distributions.withoutRelated.Sector || 0,
        },
        {
          label: 'Regions',
          iconType: 'Region',
          path: 'regions',
          count: distributions.withoutRelated.Region || 0,
        },
        {
          label: 'Countries',
          iconType: 'Country',
          path: 'countries',
          count: distributions.withoutRelated.Country || 0,
        },
        {
          label: 'Areas',
          iconType: 'Administrative-Area',
          path: 'areas',
          count: distributions.withoutRelated['Administrative-Area'] || 0,
        },
        {
          label: 'Cities',
          iconType: 'City',
          path: 'cities',
          count: distributions.withoutRelated.City || 0,
        },
        {
          label: 'Organizations',
          iconType: 'Organization',
          path: 'organizations',
          count: distributions.withoutRelated.Organization || 0,
        },
        {
          label: 'Individuals',
          iconType: 'Individual',
          path: 'individuals',
          count: distributions.withoutRelated.Individual || 0,
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
          count: distributions.withoutRelated.Tool || 0,
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
          count: distributions.withoutRelated['Attack-Pattern'] || 0,
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
          count: sumEntitiesByKeys(distributions.coreObjects, [...schema.scos.map((s) => s.id), 'Stixfile', 'Ipv4-Addr', 'Ipv6-Addr']),
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
      // Position is deliberately untouched: fixed to the right edge, full
      // height, content laid out beside it — the arrangement the product has
      // always had. Only the inside of the bar is redesigned (Figma node
      // 7472:48226).
      slotProps={{
        paper: {
          // The layer comes from the shared helper, not a literal: the class
          // and `layerInputVars` must sit on the SAME node for the three input
          // aliases to resolve at this layer (LIBRARY-FEEDBACK #57), and
          // hardcoding the string here would have been a second copy of a
          // mechanism that already exists. `slotProps.paper`, not the
          // deprecated `PaperProps`.
          className: fdsLayerClass(RIGHT_BAR_LAYER),
          sx: { ...layerInputVars },
        },
      }}
      sx={{
        '& .MuiPaper-root': {
          minHeight: '100vh',
          width: 200,
          position: 'fixed',
          overflow: 'auto',
          padding: 0,
          zIndex: theme.zIndex.appBar - 1,
          paddingBottom: draftContext ? '69px' : 0, // Add 69px in case DraftToolbar is opened
          // The bar is an elevation layer of its own: `layer-1` on the paper
          // repoints --bg-elevation-default to #0d172b and
          // --bg-elevation-highlight to #182a4e, so the rows' own hover and
          // selected tones land on the right step without being restated here.
          // Both hexes are pinned by the Figma node, which is how the layer is
          // known to be 1 rather than 0 (#070d18) — a bare alias would resolve
          // layer 0.
          background: 'var(--bg-elevation-default)',
          borderLeft: '1px solid var(--border-elevation-subtle-soft)',
        },
      }}
    >
      <Box sx={{ ...theme.mixins.toolbar }} />
      <nav
        style={{
          marginTop: bannerSettings.bannerHeightNumber + settingsMessagesBannerHeight,
          marginBottom: bannerSettings.bannerHeightNumber,
          paddingTop: 4, // the 4px slot inset of the Figma node
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
            <React.Fragment key={index}>
              {section.title && (
                // `as="p"`: this bar is page chrome rendered next to the
                // entity's own heading outline, so a real <h2> here would
                // inject an out-of-order heading (WCAG 1.3.1). The caption
                // typography and the disabled tone are unchanged either way.
                <NavbarTitle as="p">{section.title}</NavbarTitle>
              )}
              {section.items.map(({ path, label, iconType, count }) => (
                <KnowledgeBarItem
                  key={label}
                  to={`${stixCoreObjectLink}/${path}`}
                  iconType={iconType}
                  label={label}
                  count={count ?? 0}
                />
              ))}
            </React.Fragment>
          )
        ))}
      </nav>
    </Drawer>
  );
};

export default StixCoreObjectKnowledgeBar;
