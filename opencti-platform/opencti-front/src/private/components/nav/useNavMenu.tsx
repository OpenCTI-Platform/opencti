import {
  AccountBalanceOutlined,
  ArchitectureOutlined,
  AssignmentOutlined,
  BiotechOutlined,
  BugReportOutlined,
  CasesOutlined,
  ConstructionOutlined,
  DescriptionOutlined,
  DiamondOutlined,
  DomainOutlined,
  EventOutlined,
  ExploreOutlined,
  ExtensionOutlined,
  FlagOutlined,
  Home,
  InsertChartOutlinedOutlined,
  LayersOutlined,
  LocalOfferOutlined,
  MapOutlined,
  PersonOutlined,
  PlaceOutlined,
  PublicOutlined,
  SecurityOutlined,
  SourceOutlined,
  SpeakerNotesOutlined,
  StorageOutlined,
  StreamOutlined,
  SubjectOutlined,
  SurroundSoundOutlined,
  TaskAltOutlined,
  TrackChanges,
  VisibilityOutlined,
  WebAssetOutlined,
  WifiTetheringOutlined,
  WorkspacesOutlined,
} from '@mui/icons-material';
import {
  AccountMultipleOutline,
  ArchiveOutline,
  Biohazard,
  Binoculars,
  BriefcaseEditOutline,
  BriefcaseEyeOutline,
  BriefcaseRemoveOutline,
  BriefcaseSearchOutline,
  ChessKnight,
  CityVariantOutline,
  CogOutline,
  Database,
  Fire,
  FlaskOutline,
  FolderTableOutline,
  GlobeModel,
  HexagonOutline,
  LaptopAccount,
  LockPattern,
  ProgressWrench,
  ServerNetwork,
  ShieldSearch,
  Timetable,
} from 'mdi-material-ui';
import React from 'react';
import { useFormatter } from '../../../components/i18n';
import useAuth from '../../../utils/hooks/useAuth';
import { useHiddenEntities, useIsHiddenEntities } from '../../../utils/hooks/useEntitySettings';
import useGranted, {
  AUTOMATION_AUTMANAGE,
  BYPASS,
  CSVMAPPERS,
  EXPLORE,
  INGESTION,
  INGESTION_SETINGESTIONS,
  INVESTIGATION,
  KNOWLEDGE,
  KNOWLEDGE_KNASKIMPORT,
  KNOWLEDGE_KNUPDATE,
  KNOWLEDGE_KNUPDATE_KNDELETE,
  MODULES,
  PIRAPI,
  SETTINGS_FILEINDEXING,
  SETTINGS_SECURITYACTIVITY,
  SETTINGS_SETACCESSES,
  SETTINGS_SETAUTH,
  SETTINGS_SETCASETEMPLATES,
  SETTINGS_SETCUSTOMIZATION,
  SETTINGS_SETDISSEMINATION,
  SETTINGS_SETKILLCHAINPHASES,
  SETTINGS_SETLABELS,
  SETTINGS_SETMANAGEXTMHUB,
  SETTINGS_SETMARKINGS,
  SETTINGS_SETPARAMETERS,
  SETTINGS_SETSTATUSTEMPLATES,
  SETTINGS_SETVOCABULARIES,
  SETTINGS_SUPPORT,
  TAXIIAPI,
  VIRTUAL_ORGANIZATION_ADMIN,
} from '../../../utils/hooks/useGranted';
import useHelper from '../../../utils/hooks/useHelper';
import useImportAccess from '../../../utils/hooks/useImportAccess';

/** A navigable row nested under a top-level entry. */
export interface NavSubItem {
  link: string;
  label: string;
  icon?: React.ReactNode;
  /** Match the route exactly instead of by prefix. */
  exact?: boolean;
  /**
   * Entity type this row exposes. Used to drop the row when the platform
   * administrator has hidden that type in entity settings — the second of the
   * three permission mechanisms this menu superposes.
   */
  type?: string;
  /** Capability-based visibility, already resolved by the caller. */
  granted?: boolean;
}

/** A top-level navigation entry, with or without a submenu. */
export interface NavItem {
  /**
   * Stable identifier. Doubles as the persisted expanded-submenu key, so it
   * must keep matching the values already stored under `selectedMenu` for a
   * returning user's rail to open the same way it did before this migration.
   */
  id: string;
  label: string;
  icon: React.ReactNode;
  link: string;
  exact?: boolean;
  subItems?: NavSubItem[];
}

/** A run of entries rendered between two separators. */
export interface NavGroup {
  id: string;
  items: NavItem[];
}

/**
 * The shape the tree is *declared* in, before filtering. Entries guarded by a
 * permission are written `permission && {...}`, which yields `false` when the
 * permission is missing; `filterNavGroups` compacts them away.
 */
export interface RawNavGroup {
  id: string;
  items: (NavItem | false | null | undefined)[];
}

/**
 * Builds the navigation tree, fully filtered.
 *
 * The tree used to be an untyped inline JSX structure inside the rail
 * component, with three permission mechanisms superposed on it: `<Security>`
 * wrappers around groups, `granted` booleans on individual rows, and
 * `useIsHiddenEntities` on entity-bearing rows — plus feature flags and a
 * draft context that replaces the menu wholesale. Expressing it as data lets
 * every one of those be applied here, once, and unit-tested without
 * rendering; the component below is then only concerned with presentation.
 *
 * `<Security needs={[A, B]}>` is OR-semantics (`matchAll` defaults to false),
 * so each wrapper becomes a single `useGranted([...])` call with the same
 * list, which is why the capability arrays are reproduced verbatim.
 */
const useNavMenu = (): NavGroup[] => {
  const { t_i18n } = useFormatter();
  const { me: { draftContext } } = useAuth();
  const { isFeatureEnable, isTrashEnable } = useHelper();
  const { hasOnlyAccessToImportDraftTab } = useImportAccess();
  const hiddenEntities = useHiddenEntities();

  const isGrantedToKnowledge = useGranted([KNOWLEDGE]);
  const isGrantedToImport = useGranted([KNOWLEDGE_KNASKIMPORT]) || hasOnlyAccessToImportDraftTab;
  const isGrantedToProcessing = useGranted([KNOWLEDGE_KNUPDATE, AUTOMATION_AUTMANAGE, CSVMAPPERS]);
  const isGrantedToSharing = useGranted([TAXIIAPI]);
  const isGrantedToManage = useGranted([BYPASS]);
  const isGrantedToParameters = useGranted([SETTINGS_SETPARAMETERS]);
  const isGrantedToLabels = useGranted([SETTINGS_SETLABELS]);
  const isGrantedToVocabularies = useGranted([SETTINGS_SETVOCABULARIES]);
  const isGrantedToKillChainPhases = useGranted([SETTINGS_SETKILLCHAINPHASES]);
  const isGrantedToCaseTemplates = useGranted([SETTINGS_SETCASETEMPLATES]);
  const isGrantedToStatusTemplates = useGranted([SETTINGS_SETSTATUSTEMPLATES]);
  const isGrantedToTaxonomies = isGrantedToLabels
    || isGrantedToVocabularies
    || isGrantedToKillChainPhases
    || isGrantedToCaseTemplates
    || isGrantedToStatusTemplates;
  const isGrantedToFileIndexing = useGranted([SETTINGS_FILEINDEXING]);
  const isGrantedToExperience = useGranted([SETTINGS_SETPARAMETERS, SETTINGS_SUPPORT, SETTINGS_SETMANAGEXTMHUB]);
  const isGrantedToDelete = useGranted([KNOWLEDGE_KNUPDATE_KNDELETE]);
  const isOrganizationAdmin = useGranted([VIRTUAL_ORGANIZATION_ADMIN]);
  const isGrantedToCustomization = useGranted([SETTINGS_SETCUSTOMIZATION]);
  const isGrantedToSecurity = useGranted([SETTINGS_SETMARKINGS, SETTINGS_SETACCESSES, SETTINGS_SETDISSEMINATION, SETTINGS_SETAUTH]);
  const isGrantedToAudit = useGranted([SETTINGS_SECURITYACTIVITY]);
  const isDataHealthEnabled = isFeatureEnable('DATA_SANITY_MANAGER');

  // `<Security>` wrappers, one per group, verbatim capability lists.
  const canSeeExplore = useGranted([EXPLORE]);
  const canSeeInvestigation = useGranted([INVESTIGATION]);
  const canSeePir = useGranted([PIRAPI]);
  const canSeeKnowledge = useGranted([KNOWLEDGE]);
  const canSeeIntegrations = useGranted([MODULES, INGESTION, INGESTION_SETINGESTIONS]);
  const canSeeData = useGranted([MODULES, KNOWLEDGE, TAXIIAPI, CSVMAPPERS, INGESTION]);
  const canSeeSettings = useGranted([
    VIRTUAL_ORGANIZATION_ADMIN,
    SETTINGS_SETPARAMETERS,
    SETTINGS_SETACCESSES,
    SETTINGS_SETAUTH,
    SETTINGS_SETMARKINGS,
    SETTINGS_SETDISSEMINATION,
    SETTINGS_SETCUSTOMIZATION,
    SETTINGS_SETLABELS,
    SETTINGS_SETVOCABULARIES,
    SETTINGS_SETCASETEMPLATES,
    SETTINGS_SETSTATUSTEMPLATES,
    SETTINGS_SETKILLCHAINPHASES,
    SETTINGS_SECURITYACTIVITY,
    SETTINGS_FILEINDEXING,
    SETTINGS_SUPPORT,
    SETTINGS_SETMANAGEXTMHUB,
  ]);

  const hideAnalyses = useIsHiddenEntities('Report', 'Grouping', 'Note', 'Malware-Analysis', 'Security-Coverage');
  const hideEvents = useIsHiddenEntities('stix-sighting-relationship', 'Incident', 'Observed-Data');
  const hideObservations = useIsHiddenEntities('Stix-Cyber-Observable', 'Artifact', 'Indicator', 'Infrastructure');
  const hideThreats = useIsHiddenEntities('Threat-Actor-Group', 'Threat-Actor-Individual', 'Intrusion-Set', 'Campaign');
  const hideEntities = useIsHiddenEntities('Sector', 'Event', 'Organization', 'Security-platforms', 'System', 'Individual');
  const hideCases = useIsHiddenEntities('Case-Incident', 'Feedback', 'Case-Rfi', 'Case-Rft', 'Task');
  const hideArsenal = useIsHiddenEntities('Malware', 'Channel', 'Tool', 'Vulnerability');
  const hideTechniques = useIsHiddenEntities('Attack-Pattern', 'Narrative', 'Course-Of-Action', 'Data-Component', 'Data-Source');
  const hideLocations = useIsHiddenEntities('Region', 'Administrative-Area', 'Country', 'City', 'Position');

  const inDraft = !!draftContext;

  const groups: (RawNavGroup | false)[] = [
    {
      id: 'main',
      items: [
        !inDraft && {
          id: 'home', label: t_i18n('Home'), icon: <Home />, link: '/dashboard', exact: true,
        },
        !inDraft && canSeeExplore && {
          id: 'dashboards',
          label: t_i18n('Dashboards'),
          icon: <InsertChartOutlinedOutlined />,
          link: '/dashboard/workspaces/dashboards',
          subItems: [
            // No `exact`: a dashboard's own page is `/…/dashboards/<id>`, and an
            // exact match left the sub-item inactive the moment you opened one.
            // Prefix matching is safe between these two links because
            // `/…/dashboards_public` does not start with `/…/dashboards/`.
            { granted: canSeeExplore, type: 'Dashboard', link: '/dashboard/workspaces/dashboards', label: t_i18n('Custom dashboards') },
            { granted: canSeeExplore, type: 'Dashboard', link: '/dashboard/workspaces/dashboards_public', label: t_i18n('Public dashboards') },
          ],
        },
        !inDraft && canSeeInvestigation && {
          id: 'investigations', label: t_i18n('Investigations'), icon: <ExploreOutlined />, link: '/dashboard/workspaces/investigations',
        },
        inDraft && {
          id: 'draft-overview',
          label: t_i18n('Draft overview'),
          icon: <ArchitectureOutlined />,
          link: `/dashboard/data/import/draft/${draftContext?.id}`,
        },
        !inDraft && canSeePir && {
          id: 'pir', label: t_i18n('PIR'), icon: <TrackChanges />, link: '/dashboard/pirs',
        },
      ],
    },
    {
      id: 'knowledge',
      items: canSeeKnowledge ? [
        !hideAnalyses && {
          id: 'analyses',
          label: t_i18n('Analyses'),
          icon: <AssignmentOutlined />,
          link: '/dashboard/analyses',
          subItems: [
            { type: 'Report', link: '/dashboard/analyses/reports', label: t_i18n('Reports'), icon: <DescriptionOutlined fontSize="small" /> },
            { type: 'Grouping', link: '/dashboard/analyses/groupings', label: t_i18n('Groupings'), icon: <WorkspacesOutlined fontSize="small" /> },
            { type: 'Malware-Analysis', link: '/dashboard/analyses/malware_analyses', label: t_i18n('Malware analyses'), icon: <BiotechOutlined fontSize="small" /> },
            { type: 'Security-Coverage', link: '/dashboard/analyses/security_coverages', label: t_i18n('Security coverages'), icon: <SecurityOutlined fontSize="small" /> },
            { type: 'Note', link: '/dashboard/analyses/notes', label: t_i18n('Notes'), icon: <SubjectOutlined fontSize="small" /> },
            { type: 'External-Reference', link: '/dashboard/analyses/external_references', label: t_i18n('External references'), icon: <LocalOfferOutlined fontSize="small" /> },
          ],
        },
        !hideCases && {
          id: 'cases',
          label: t_i18n('Cases'),
          icon: <CasesOutlined />,
          link: '/dashboard/cases',
          subItems: [
            { type: 'Case-Incident', link: '/dashboard/cases/incidents', label: t_i18n('Incident responses'), icon: <BriefcaseEyeOutline fontSize="small" /> },
            { type: 'Case-Rfi', link: '/dashboard/cases/rfis', label: t_i18n('Requests for information'), icon: <BriefcaseSearchOutline fontSize="small" /> },
            { type: 'Case-Rft', link: '/dashboard/cases/rfts', label: t_i18n('Requests for takedown'), icon: <BriefcaseRemoveOutline fontSize="small" /> },
            { type: 'Task', link: '/dashboard/cases/tasks', label: t_i18n('Tasks'), icon: <TaskAltOutlined fontSize="small" /> },
            { type: 'Feedback', link: '/dashboard/cases/feedbacks', label: t_i18n('Feedbacks'), icon: <BriefcaseEditOutline fontSize="small" /> },
          ],
        },
        !hideEvents && {
          id: 'events',
          label: t_i18n('Events'),
          icon: <Timetable />,
          link: '/dashboard/events',
          subItems: [
            { type: 'Incident', link: '/dashboard/events/incidents', label: t_i18n('Incidents'), icon: <Fire fontSize="small" /> },
            { type: 'stix-sighting-relationship', link: '/dashboard/events/sightings', label: t_i18n('Sightings'), icon: <VisibilityOutlined fontSize="small" /> },
            { type: 'Observed-Data', link: '/dashboard/events/observed_data', label: t_i18n('Observed datas'), icon: <WifiTetheringOutlined fontSize="small" /> },
          ],
        },
        !hideObservations && {
          id: 'observations',
          label: t_i18n('Observations'),
          icon: <Binoculars />,
          link: '/dashboard/observations',
          subItems: [
            { type: 'Stix-Cyber-Observable', link: '/dashboard/observations/observables', label: t_i18n('Observables'), icon: <HexagonOutline fontSize="small" /> },
            { type: 'Artifact', link: '/dashboard/observations/artifacts', label: t_i18n('Artifacts'), icon: <ArchiveOutline fontSize="small" /> },
            { type: 'Indicator', link: '/dashboard/observations/indicators', label: t_i18n('Indicators'), icon: <ShieldSearch fontSize="small" /> },
            { type: 'Infrastructure', link: '/dashboard/observations/infrastructures', label: t_i18n('Infrastructures'), icon: <ServerNetwork fontSize="small" /> },
          ],
        },
      ] : [],
    },
    {
      id: 'threat-landscape',
      items: canSeeKnowledge ? [
        !hideThreats && {
          id: 'threats',
          label: t_i18n('Threats'),
          icon: <FlaskOutline />,
          link: '/dashboard/threats',
          subItems: [
            { type: 'Threat-Actor-Group', link: '/dashboard/threats/threat_actors_group', label: t_i18n('Threat actors (group)'), icon: <AccountMultipleOutline fontSize="small" /> },
            { type: 'Threat-Actor-Individual', link: '/dashboard/threats/threat_actors_individual', label: t_i18n('Threat actors (individual)'), icon: <LaptopAccount fontSize="small" /> },
            { type: 'Intrusion-Set', link: '/dashboard/threats/intrusion_sets', label: t_i18n('Intrusion sets'), icon: <DiamondOutlined fontSize="small" /> },
            { type: 'Campaign', link: '/dashboard/threats/campaigns', label: t_i18n('Campaigns'), icon: <ChessKnight fontSize="small" /> },
          ],
        },
        !hideArsenal && {
          id: 'arsenal',
          label: t_i18n('Arsenal'),
          icon: <LayersOutlined />,
          link: '/dashboard/arsenal',
          subItems: [
            { type: 'Malware', link: '/dashboard/arsenal/malwares', label: t_i18n('Malwares'), icon: <Biohazard fontSize="small" /> },
            { type: 'Channel', link: '/dashboard/arsenal/channels', label: t_i18n('Channels'), icon: <SurroundSoundOutlined fontSize="small" /> },
            { type: 'Tool', link: '/dashboard/arsenal/tools', label: t_i18n('Tools'), icon: <WebAssetOutlined fontSize="small" /> },
            { type: 'Vulnerability', link: '/dashboard/arsenal/vulnerabilities', label: t_i18n('Vulnerabilities'), icon: <BugReportOutlined fontSize="small" /> },
          ],
        },
        !hideTechniques && {
          id: 'techniques',
          label: t_i18n('Techniques'),
          icon: <ConstructionOutlined />,
          link: '/dashboard/techniques',
          subItems: [
            { type: 'Attack-Pattern', link: '/dashboard/techniques/attack_patterns', label: t_i18n('Attack patterns'), icon: <LockPattern fontSize="small" /> },
            { type: 'Narrative', link: '/dashboard/techniques/narratives', label: t_i18n('Narratives'), icon: <SpeakerNotesOutlined fontSize="small" /> },
            { type: 'Course-Of-Action', link: '/dashboard/techniques/courses_of_action', label: t_i18n('Courses of action'), icon: <ProgressWrench fontSize="small" /> },
            { type: 'Data-Component', link: '/dashboard/techniques/data_components', label: t_i18n('Data components'), icon: <SourceOutlined fontSize="small" /> },
            { type: 'Data-Source', link: '/dashboard/techniques/data_sources', label: t_i18n('Data sources'), icon: <StreamOutlined fontSize="small" /> },
          ],
        },
        !hideEntities && {
          id: 'entities',
          label: t_i18n('Entities'),
          icon: <FolderTableOutline />,
          link: '/dashboard/entities',
          subItems: [
            { type: 'Sector', link: '/dashboard/entities/sectors', label: t_i18n('Sectors'), icon: <DomainOutlined fontSize="small" /> },
            { type: 'Event', link: '/dashboard/entities/events', label: t_i18n('Events'), icon: <EventOutlined fontSize="small" /> },
            { type: 'Organization', link: '/dashboard/entities/organizations', label: t_i18n('Organizations'), icon: <AccountBalanceOutlined fontSize="small" /> },
            { type: 'SecurityPlatform', link: '/dashboard/entities/security_platforms', label: t_i18n('Security platforms'), icon: <SecurityOutlined fontSize="small" /> },
            { type: 'System', link: '/dashboard/entities/systems', label: t_i18n('Systems'), icon: <StorageOutlined fontSize="small" /> },
            { type: 'Individual', link: '/dashboard/entities/individuals', label: t_i18n('Individuals'), icon: <PersonOutlined fontSize="small" /> },
          ],
        },
        !hideLocations && {
          id: 'locations',
          label: t_i18n('Locations'),
          icon: <GlobeModel />,
          link: '/dashboard/locations',
          subItems: [
            { type: 'Region', link: '/dashboard/locations/regions', label: t_i18n('Regions'), icon: <PublicOutlined fontSize="small" /> },
            { type: 'Country', link: '/dashboard/locations/countries', label: t_i18n('Countries'), icon: <FlagOutlined fontSize="small" /> },
            { type: 'Administrative-Area', link: '/dashboard/locations/administrative_areas', label: t_i18n('Administrative areas'), icon: <MapOutlined fontSize="small" /> },
            { type: 'City', link: '/dashboard/locations/cities', label: t_i18n('Cities'), icon: <CityVariantOutline fontSize="small" /> },
            { type: 'Position', link: '/dashboard/locations/positions', label: t_i18n('Positions'), icon: <PlaceOutlined fontSize="small" /> },
          ],
        },
      ] : [],
    },
    {
      id: 'data',
      items: canSeeData ? [
        !inDraft && canSeeIntegrations && {
          id: 'integrations', label: t_i18n('Integrations'), icon: <ExtensionOutlined />, link: '/dashboard/integrations',
        },
        {
          id: 'data',
          label: t_i18n('Data'),
          icon: <Database />,
          link: '/dashboard/data',
          subItems: [
            { granted: isGrantedToKnowledge, link: '/dashboard/data/entities', label: t_i18n('Entities') },
            { granted: isGrantedToKnowledge, link: '/dashboard/data/relationships', label: t_i18n('Relationships') },
            { granted: isGrantedToImport && !inDraft, link: '/dashboard/data/import', label: t_i18n('Import') },
            { granted: isGrantedToProcessing && !inDraft, link: '/dashboard/data/processing', label: t_i18n('Processing') },
            { granted: isGrantedToSharing && !inDraft, link: '/dashboard/data/sharing', label: t_i18n('Data sharing') },
            { granted: isGrantedToManage && !inDraft, link: '/dashboard/data/restriction', label: t_i18n('Restriction') },
            { granted: isDataHealthEnabled && isGrantedToManage && !inDraft, link: '/dashboard/data/health', label: t_i18n('Health') },
            { granted: isTrashEnable() && isGrantedToDelete && !inDraft, link: '/dashboard/trash', label: t_i18n('Trash') },
          ],
        },
      ] : [],
    },
    {
      id: 'settings',
      items: (canSeeSettings && !inDraft) ? [
        {
          id: 'settings',
          label: t_i18n('Settings'),
          icon: <CogOutline />,
          link: '/dashboard/settings',
          subItems: [
            { granted: isGrantedToParameters, link: '/dashboard/settings', label: t_i18n('Parameters'), exact: true },
            { granted: isGrantedToSecurity || isOrganizationAdmin, link: '/dashboard/settings/accesses', label: t_i18n('Security') },
            { granted: isGrantedToCustomization, link: '/dashboard/settings/customization', label: t_i18n('Customization') },
            { granted: isGrantedToTaxonomies, link: '/dashboard/settings/vocabularies', label: t_i18n('Taxonomies') },
            { granted: isGrantedToAudit, link: '/dashboard/settings/activity', label: t_i18n('Activity') },
            { granted: isGrantedToFileIndexing, link: '/dashboard/settings/file_indexing', label: t_i18n('File indexing') },
            { granted: isGrantedToExperience, link: '/dashboard/settings/experience', label: t_i18n('Filigran Experience') },
          ],
        },
      ] : [],
    },
  ];

  return filterNavGroups(groups, hiddenEntities.filter((e): e is string => !!e));
};

/**
 * Drops every falsy entry produced by the conditional expressions above, then
 * applies the row-level `granted` flag and the hidden-entity filter, and
 * finally removes groups that ended up empty so no separator is rendered
 * against nothing. A parent whose submenu is emptied by those filters is kept
 * and degrades to a plain link, matching the component this replaced.
 * Exported for unit testing without a React tree.
 */
export const filterNavGroups = (
  groups: (RawNavGroup | false)[],
  hiddenEntities: string[],
): NavGroup[] => groups
  .filter((group): group is RawNavGroup => !!group)
  .map((group) => ({
    ...group,
    items: group.items
      .filter((item): item is NavItem => !!item)
      .map((item) => {
        if (!item.subItems) return item;
        const subItems = item.subItems.filter(
          (sub) => sub.granted !== false && (!sub.type || !hiddenEntities.includes(sub.type)),
        );
        // A parent whose submenu rows were ALL filtered out keeps its own row
        // and degrades to a plain link: the legacy `LeftBarItem` did exactly
        // that in its "No Subitems" branch (`hasSubItems === false` rendered a
        // navigable `MenuItem`, it did not remove the entry). Removing it here
        // would delete a navigable entry for real permission sets — a user
        // granted only `INGESTION` satisfies `canSeeData` but none of the eight
        // `Data` sub-item grants, and an administrator hiding the `Dashboard`
        // entity type empties the `Dashboards` submenu. `NavBar.renderItem`
        // already renders an empty `subItems` as a leaf, so no chevron ever
        // opens on nothing.
        return { ...item, subItems };
      }),
  }))
  .filter((group) => group.items.length > 0);

export default useNavMenu;
