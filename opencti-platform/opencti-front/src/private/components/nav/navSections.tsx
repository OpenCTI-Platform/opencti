import { AssignmentOutlined, CasesOutlined, ConstructionOutlined, InsertChartOutlinedOutlined, LayersOutlined } from '@mui/icons-material';
import { Binoculars, CogOutline, Database, FlaskOutline, FolderTableOutline, GlobeModel, Timetable } from 'mdi-material-ui';
import type { MenuEntry, NavSection, NavSectionItem } from '../common/menus/menuEntry';
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
    icon: <InsertChartOutlinedOutlined />,
    items: [customDashboards, publicDashboards],
  },
  { id: 'investigations', group: 'main', page: investigations },
  { id: 'pir', group: 'main', page: pir },

  { id: 'analyses', group: 'knowledge', label: 'Analyses', icon: <AssignmentOutlined />, items: analyses },
  { id: 'cases', group: 'knowledge', label: 'Cases', icon: <CasesOutlined />, items: cases },
  { id: 'events', group: 'knowledge', label: 'Events', icon: <Timetable />, items: events },
  { id: 'observations', group: 'knowledge', label: 'Observations', icon: <Binoculars />, items: observations },

  { id: 'threats', group: 'threat-landscape', label: 'Threats', icon: <FlaskOutline />, items: threats },
  { id: 'arsenal', group: 'threat-landscape', label: 'Arsenal', icon: <LayersOutlined />, items: arsenal },
  { id: 'techniques', group: 'threat-landscape', label: 'Techniques', icon: <ConstructionOutlined />, items: techniques },
  { id: 'entities', group: 'threat-landscape', label: 'Entities', icon: <FolderTableOutline />, items: entities },
  { id: 'locations', group: 'threat-landscape', label: 'Locations', icon: <GlobeModel />, items: locations },

  { id: 'integrations', group: 'data', page: integrations },
  {
    id: 'data',
    group: 'data',
    label: 'Data',
    icon: <Database />,
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
    icon: <CogOutline />,
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

// A section item is a page, or a group of pages (a sub-menu).
const itemEntries = (item: NavSectionItem): MenuEntry[] => ('path' in item ? [item] : item.entries);

/** Every page of a section, in left bar order. */
export const sectionEntries = (id: string): MenuEntry[] => navSections
  .filter((section) => section.id === id)
  .flatMap((section) => ('items' in section ? section.items.flatMap(itemEntries) : [section.page]));
