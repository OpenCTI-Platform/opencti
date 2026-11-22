import { Icon } from '@filigran/design-system';
import type { NavSection } from '../common/menus/menuEntry';
import { home } from './Home.entries';
import { customDashboards, investigations, publicDashboards } from '../workspaces/Workspaces.entries';
import { pir } from '../pir/Pir.entries';
import analyses from '../analyses/Analyses.entries';
import cases from '../cases/Cases.entries';
import events from '../events/Events.entries';
import observations from '../observations/Observations.entries';
import threats from '../threats/Threats.entries';
import arsenal from '../arsenal/Arsenal.entries';
import techniques from '../techniques/Techniques.entries';
import entities from '../entities/Entities.entries';
import locations from '../locations/Locations.entries';
import { integrations } from '../integrations/Integrations.entries';
import { dataEntities, dataRelationships, trash } from '../data/Data.entries';
import dataImport from '../data/ImportMenu.entries';
import dataProcessing from '../data/ProcessingMenu.entries';
import dataSharing from '../data/SharingMenu.entries';
import dataRestriction from '../data/restriction/RestrictionMenu.entries';
import dataHealth from '../data/health/HealthMenu.entries';
import { experience, fileIndexing, parameters } from '../settings/Settings.entries';
import settingsAccesses from '../settings/AccessesMenu.entries';
import settingsCustomization from '../settings/CustomizationMenu.entries';
import settingsVocabularies from '../settings/LabelsVocabulariesMenu.entries';
import settingsActivity from '../settings/ActivityMenu.entries';

// Left bar structure (blocks, sections, order), in display order. It references the entries themselves: they own the
// label, icon and access rules of their page, and a section is visible when one of its pages is. A page reachable
// from nowhere here is caught by navSections.test.ts.
export const navSections: NavSection[] = [
  { id: 'home', group: 'main', page: home },
  {
    id: 'dashboards',
    group: 'main',
    label: 'Dashboards',
    icon: <Icon name="layout-dashboard" size={16} />,
    items: [customDashboards, publicDashboards],
  },
  { id: 'investigations', group: 'main', page: investigations },
  { id: 'pir', group: 'main', page: pir },

  { id: 'analyses', group: 'knowledge', label: 'Analyses', icon: <Icon name="clipboard-list" size={16} />, items: analyses },
  { id: 'cases', group: 'knowledge', label: 'Cases', icon: <Icon name="briefcase" size={16} />, items: cases },
  { id: 'events', group: 'knowledge', label: 'Events', icon: <Icon name="calendar-days" size={16} />, items: events },
  { id: 'observations', group: 'knowledge', label: 'Observations', icon: <Icon name="custom/binocular" size={16} />, items: observations },

  { id: 'threats', group: 'threat-landscape', label: 'Threats', icon: <Icon name="custom/threat-actor-individual" size={16} />, items: threats },
  { id: 'arsenal', group: 'threat-landscape', label: 'Arsenal', icon: <Icon name="layers" size={16} />, items: arsenal },
  { id: 'techniques', group: 'threat-landscape', label: 'Techniques', icon: <Icon name="custom/attack-pattern" size={16} />, items: techniques },
  { id: 'entities', group: 'threat-landscape', label: 'Entities', icon: <Icon name="folder" size={16} />, items: entities },
  { id: 'locations', group: 'threat-landscape', label: 'Locations', icon: <Icon name="earth" size={16} />, items: locations },

  { id: 'integrations', group: 'data', page: integrations },
  {
    id: 'data',
    group: 'data',
    label: 'Data',
    icon: <Icon name="database" size={16} />,
    items: [
      dataEntities,
      dataRelationships,
      { label: 'Import', entries: dataImport },
      { label: 'Processing', entries: dataProcessing },
      { label: 'Data sharing', entries: dataSharing },
      { label: 'Restriction', entries: dataRestriction },
      { label: 'Health', entries: dataHealth },
      trash,
    ],
  },

  {
    id: 'settings',
    group: 'settings',
    label: 'Settings',
    icon: <Icon name="settings" size={16} />,
    items: [
      parameters,
      { label: 'Security', entries: settingsAccesses },
      { label: 'Customization', entries: settingsCustomization },
      { label: 'Taxonomies', entries: settingsVocabularies },
      { label: 'Activity', entries: settingsActivity },
      fileIndexing,
      experience,
    ],
  },
];
