import React from 'react';
import {
  AccountBalanceOutlined,
  BiotechOutlined,
  BugReportOutlined,
  DescriptionOutlined,
  DomainOutlined,
  EventOutlined,
  FlagOutlined,
  LocalOfferOutlined,
  MapOutlined,
  PersonOutlined,
  PlaceOutlined,
  PublicOutlined,
  SourceOutlined,
  SpeakerNotesOutlined,
  StorageOutlined,
  StreamOutlined,
  SubjectOutlined,
  SurroundSoundOutlined,
  TaskAltOutlined,
  VisibilityOutlined,
  WebAssetOutlined,
  WifiTetheringOutlined,
  WorkspacesOutlined,
} from '@mui/icons-material';
import { Button, ListItemText, MenuItem, MenuList, SvgIconTypeMap } from '@mui/material';
import { OverridableComponent } from '@mui/material/OverridableComponent';
import { makeStyles } from '@mui/styles';
import {
  AccountMultipleOutline,
  ArchiveOutline,
  Biohazard,
  BriefcaseEditOutline,
  BriefcaseEyeOutline,
  BriefcaseRemoveOutline,
  BriefcaseSearchOutline,
  ChessKnight,
  CityVariantOutline,
  DiamondOutline,
  Fire,
  HexagonOutline,
  LaptopAccount,
  LockPattern,
  ProgressWrench,
  ServerNetwork,
  ShieldSearch,
} from 'mdi-material-ui';
import { Link, useLocation } from 'react-router-dom';
import type { Theme } from 'src/components/Theme';
import { useFormatter } from 'src/components/i18n';
import { useIsHiddenEntity } from 'src/utils/hooks/useEntitySettings';
import useGranted, {
  KNOWLEDGE,
  KNOWLEDGE_KNUPDATE,
  MODULES,
  SETTINGS,
  SETTINGS_SETACCESSES,
  SETTINGS_SETLABELS,
  SETTINGS_SETMARKINGS,
  TAXIIAPI_SETCOLLECTIONS,
  TAXIIAPI_SETCSVMAPPERS,
  VIRTUAL_ORGANIZATION_ADMIN,
} from 'src/utils/hooks/useGranted';

export interface RulesType {
  name: string,
  pathname: string,
  iconComponent?: OverridableComponent<SvgIconTypeMap>,
  useIsHiddenEntity?: boolean,
  needs?: string[],
}

export const allTypes: Record<string, Record<string, RulesType>> = {
  Analyses: {
    Report: {
      name: 'Reports',
      pathname: 'reports',
      iconComponent: DescriptionOutlined,
    },
    Grouping: {
      name: 'Groupings',
      pathname: 'groupings',
      iconComponent: WorkspacesOutlined,
    },
    'Malware-Analysis': {
      name: 'Malware analyses',
      pathname: 'malware_analyses',
      iconComponent: BiotechOutlined,
    },
    Note: {
      name: 'Notes',
      pathname: 'notes',
      iconComponent: SubjectOutlined,
    },
    'External-References': {
      name: 'External references',
      pathname: 'external_references',
      iconComponent: LocalOfferOutlined,
      useIsHiddenEntity: false,
    },
  },
  Cases: {
    'Case-Incident': {
      name: 'Incident responses',
      pathname: 'incidents',
      iconComponent: BriefcaseEyeOutline,
    },
    'Case-Rfi': {
      name: 'Requests for information',
      pathname: 'rfis',
      iconComponent: BriefcaseSearchOutline,
    },
    'Case-Rft': {
      name: 'Requests for takedown',
      pathname: 'rfts',
      iconComponent: BriefcaseRemoveOutline,
    },
    Task: {
      name: 'Tasks',
      pathname: 'tasks',
      iconComponent: TaskAltOutlined,
    },
    Feedback: {
      name: 'Feedbacks',
      pathname: 'feedbacks',
      iconComponent: BriefcaseEditOutline,
    },
  },
  Events: {
    Incident: {
      name: 'Incidents',
      pathname: 'incidents',
      iconComponent: Fire,
    },
    'stix-sighting-relationship': {
      name: 'Sightings',
      pathname: 'sightings',
      iconComponent: VisibilityOutlined,
    },
    'Observed-Data': {
      name: 'Observed datas',
      pathname: 'observed_data',
      iconComponent: WifiTetheringOutlined,
    },
  },
  Observations: {
    'Stix-Cyber-Observable': {
      name: 'Observables',
      pathname: 'observables',
      iconComponent: HexagonOutline,
    },
    Artifact: {
      name: 'Artifacts',
      pathname: 'artifacts',
      iconComponent: ArchiveOutline,
    },
    Indicator: {
      name: 'Indicators',
      pathname: 'indicators',
      iconComponent: ShieldSearch,
    },
    Infrastructure: {
      name: 'Infrastructures',
      pathname: 'infrastructures',
      iconComponent: ServerNetwork,
    },
  },
  Threats: {
    'Threat-Actor-Group': {
      name: 'Threat actors (group)',
      pathname: 'threat_actors_group',
      iconComponent: AccountMultipleOutline,
    },
    'Threat-Actor-Individual': {
      name: 'Threat actors (individual)',
      pathname: 'threat_actors_individual',
      iconComponent: LaptopAccount,
    },
    'Intrusion-Set': {
      name: 'Intrusion sets',
      pathname: 'intrusion_sets',
      iconComponent: DiamondOutline,
    },
    Campaign: {
      name: 'Campaigns',
      pathname: 'campaigns',
      iconComponent: ChessKnight,
    },
  },
  Arsenal: {
    Malware: {
      name: 'Malwares',
      pathname: 'malwares',
      iconComponent: Biohazard,
    },
    Channel: {
      name: 'Channels',
      pathname: 'channels',
      iconComponent: SurroundSoundOutlined,
    },
    Tool: {
      name: 'Tools',
      pathname: 'tools',
      iconComponent: WebAssetOutlined,
    },
    Vulnerability: {
      name: 'Vulnerabilities',
      pathname: 'vulnerabilities',
      iconComponent: BugReportOutlined,
    },
  },
  Techniques: {
    'Attack-Pattern': {
      name: 'Attack patterns',
      pathname: 'attack_patterns',
      iconComponent: LockPattern,
    },
    Narrative: {
      name: 'Narratives',
      pathname: 'narratives',
      iconComponent: SpeakerNotesOutlined,
    },
    'Course-Of-Action': {
      name: 'Courses of action',
      pathname: 'courses_of_action',
      iconComponent: ProgressWrench,
    },
    'Data-Component': {
      name: 'Data components',
      pathname: 'data_components',
      iconComponent: SourceOutlined,
    },
    'Data-Source': {
      name: 'Data sources',
      pathname: 'data_sources',
      iconComponent: StreamOutlined,
    },
  },
  Entities: {
    Sector: {
      name: 'Sectors',
      pathname: 'sectors',
      iconComponent: DomainOutlined,
    },
    Event: {
      name: 'Events',
      pathname: 'events',
      iconComponent: EventOutlined,
    },
    Organization: {
      name: 'Organizations',
      pathname: 'organizations',
      iconComponent: AccountBalanceOutlined,
    },
    System: {
      name: 'Systems',
      pathname: 'systems',
      iconComponent: StorageOutlined,
    },
    Individual: {
      name: 'Individuals',
      pathname: 'individuals',
      iconComponent: PersonOutlined,
    },
  },
  Locations: {
    Region: {
      name: 'Regions',
      pathname: 'regions',
      iconComponent: PublicOutlined,
    },
    Country: {
      name: 'Countries',
      pathname: 'countries',
      iconComponent: FlagOutlined,
    },
    'Administrative-Area': {
      name: 'Areas',
      pathname: 'administrative_areas',
      iconComponent: MapOutlined,
    },
    City: {
      name: 'Cities',
      pathname: 'cities',
      iconComponent: CityVariantOutline,
    },
    Position: {
      name: 'Positions',
      pathname: 'positions',
      iconComponent: PlaceOutlined,
    },
  },
  Data: {
    Entity: {
      name: 'Entities',
      pathname: 'entities',
      useIsHiddenEntity: false,
      needs: [KNOWLEDGE],
    },
    Relationship: {
      name: 'Relationships',
      pathname: 'relationships',
      useIsHiddenEntity: false,
      needs: [KNOWLEDGE],
    },
    Ingestion: {
      name: 'Ingestion',
      pathname: 'ingestion',
      useIsHiddenEntity: false,
      needs: [SETTINGS],
    },
    Processing: {
      name: 'Processing',
      pathname: 'processing',
      useIsHiddenEntity: false,
      needs: [KNOWLEDGE_KNUPDATE, SETTINGS_SETACCESSES, TAXIIAPI_SETCSVMAPPERS],
    },
    'Data-Sharing': {
      name: 'Data sharing',
      pathname: 'sharing',
      useIsHiddenEntity: false,
      needs: [TAXIIAPI_SETCOLLECTIONS],
    },
    Connector: {
      name: 'Connectors',
      pathname: 'connectors',
      useIsHiddenEntity: false,
      needs: [MODULES],
    },
  },
  Settings: {
    Parameter: {
      name: 'Parameters',
      pathname: '',
      useIsHiddenEntity: false,
      needs: [SETTINGS],
    },
    Access: {
      name: 'Security',
      pathname: 'accesses',
      useIsHiddenEntity: false,
      needs: [
        SETTINGS_SETMARKINGS,
        SETTINGS_SETACCESSES,
        VIRTUAL_ORGANIZATION_ADMIN,
      ],
    },
    Customization: {
      name: 'Customization',
      pathname: 'customization',
      useIsHiddenEntity: false,
      needs: [SETTINGS],
    },
    Taxonomy: {
      name: 'Taxonomies',
      pathname: 'vocabularies',
      useIsHiddenEntity: false,
      needs: [SETTINGS_SETLABELS],
    },
    Activity: {
      name: 'Activity',
      pathname: 'activity',
      useIsHiddenEntity: false,
      needs: [SETTINGS],
    },
    'File-Indexing': {
      name: 'File indexing',
      pathname: 'file_indexing',
      useIsHiddenEntity: false,
      needs: [SETTINGS],
    },
  },
};

const useStyles = makeStyles<Theme>((theme) => ({
  topButton: {
    marginRight: theme.spacing(2),
    padding: '0 5px',
    minHeight: 20,
    minWidth: 20,
    textTransform: 'none',
  },
  leftButton: {
    padding: '3px 4px 3px 45px',
    minHeight: 20,
    minWidth: 20,
    textWrap: 'balance',
    lineHeight: '15px',
    textTransform: 'none',
  },
  icon: {
    marginRight: theme.spacing(1),
  },
}));

export const hiddenEntityWrapper = (entity_type: string, child: JSX.Element) => (
  !useIsHiddenEntity(entity_type)
    ? child
    : <></>
);

export const createButtonComponent = (
  parent: string,
  rules: RulesType,
  isTopNav = true,
) => {
  const classes = useStyles();
  const location = useLocation();
  const { t_i18n } = useFormatter();
  return (isTopNav
    ? <Button
        component={Link}
        to={`/dashboard/${parent}/${rules.pathname}`}
        variant={
          location.pathname.includes(`/dashboard/${parent}/${rules.pathname}`)
            ? 'contained'
            : 'text'
        }
        size="small"
        classes={{ root: classes.topButton }}
      >
      {rules.iconComponent && <rules.iconComponent className={classes.icon} fontSize="small" />}
      {t_i18n(rules.name)}
    </Button>
    : <MenuItem
        component={Link}
        to={`/dashboard/${parent}/${rules.pathname}`}
        selected={
          location.pathname.includes(`/dashboard/${parent}/${rules.pathname}`)
        }
        dense={true}
        classes={{ root: classes.leftButton }}
      >
      {/* <rules.iconComponent className={classes.icon} fontSize="small" /> */}
      <ListItemText>
        <div style={{
          fontWeight: location.pathname.includes(`/dashboard/${parent}/${rules.pathname}`)
            ? 'bold'
            : 'normal',
        }}
        >
          {t_i18n(rules.name)}
        </div>
      </ListItemText>
    </MenuItem>
  );
};

interface MenuProps { entity: string, parent?: string }

const LeftMenuGeneric = ({ entity, parent }: MenuProps) => (
  <MenuList>
    {Object.entries(allTypes[entity]).filter(([_, entity_rules]) => (entity_rules.needs
      ? useGranted(entity_rules.needs)
      : true)).map(([entity_type, entity_rules]) => {
      const useWrapper = entity_rules.useIsHiddenEntity ?? true;
      const button = createButtonComponent(parent ?? entity.toLowerCase(), entity_rules, false);
      return useWrapper
        ? hiddenEntityWrapper(entity_type, button)
        : button;
    })}
  </MenuList>
);

export default LeftMenuGeneric;
