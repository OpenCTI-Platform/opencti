import { CSSProperties } from 'react';
import {
  AccountBalanceOutlined,
  AlternateEmailOutlined,
  ArchitectureOutlined,
  AssignmentOutlined,
  AutoAwesomeMotion,
  AutoAwesomeOutlined,
  BackupTableOutlined,
  BiotechOutlined,
  BugReportOutlined,
  CampaignOutlined,
  CastConnectedOutlined,
  CenterFocusStrongOutlined,
  CircleOutlined,
  DashboardCustomizeOutlined,
  DescriptionOutlined,
  DiamondOutlined,
  DomainOutlined,
  DrawOutlined,
  DriveFolderUploadOutlined,
  EditOutlined,
  EmailOutlined,
  EventOutlined,
  ExtensionOutlined,
  FactCheckOutlined,
  FilterAltOutlined,
  FlagOutlined,
  HelpOutlined,
  Insights,
  LayersClearOutlined,
  LinkOutlined,
  LocalOfferOutlined,
  LocalPoliceOutlined,
  LoginOutlined,
  LogoutOutlined,
  ManageAccountsOutlined,
  MapOutlined,
  MemoryOutlined,
  NotificationsOutlined,
  PersonOutlined,
  PlaceOutlined,
  PlayCircleOutlined,
  PlaylistRemoveOutlined,
  PrecisionManufacturingOutlined,
  PublicOutlined,
  ReceiptOutlined,
  ReportProblemOutlined,
  ReviewsOutlined,
  RouteOutlined,
  RouterOutlined,
  SafetyCheckOutlined,
  SecurityOutlined,
  SettingsApplicationsOutlined,
  SettingsOutlined,
  ShortTextOutlined,
  SourceOutlined,
  SpeakerNotesOutlined,
  StorageOutlined,
  StreamOutlined,
  SubjectOutlined,
  SurroundSoundOutlined,
  TaskAlt,
  TaskAltOutlined,
  TerminalOutlined,
  TrackChanges,
  TranslateOutlined,
  TravelExploreOutlined,
  TroubleshootOutlined,
  UpcomingOutlined,
  ViewStreamTwoTone,
  VisibilityOutlined,
  WebAssetOutlined,
  WifiTetheringOutlined,
  WorkOutline,
  WorkspacesOutlined,
} from '@mui/icons-material';
import {
  AccountGroupOutline,
  AccountMultipleOutline,
  ArchiveOutline,
  AutoFix,
  BankMinus,
  BankPlus,
  Biohazard,
  BriefcaseCheckOutline,
  BriefcaseEditOutline,
  BriefcaseEyeOutline,
  BriefcaseRemoveOutline,
  BriefcaseSearchOutline,
  ChessKnight,
  CityVariantOutline,
  ClipboardTextClockOutline,
  DatabaseExportOutline,
  FileDelimitedOutline,
  FileOutline,
  FilterOutline,
  FilterVariant,
  Fire,
  FlaskOutline,
  Gauge,
  Group,
  HexagonOutline,
  LabelOutline,
  LaptopAccount,
  LockMinusOutline,
  LockOutline,
  LockPattern,
  ProgressWrench,
  ShieldCheckOutline,
  ShieldSearch,
  SourceFork,
  SourcePull,
  Target,
  VectorRadius,
} from 'mdi-material-ui';
import TableViewIcon from '@mui/icons-material/TableView';
import { itemColor } from '../utils/Colors';

const iconSelector = (
  type: string | null | undefined,
  variant: string | undefined,
  fontSize: 'inherit' | 'large' | 'medium' | 'small',
  color?: string | null,
  isReversed?: boolean,
  overrideStyle: CSSProperties = {},
) => {
  let style: CSSProperties;
  switch (variant) {
    case 'inline':
      style = {
        color: color ?? itemColor(type),
        width: 15,
        height: 15,
        margin: '0 7px 0 0',
        float: 'left',
        paddingTop: 2,
        transform: isReversed ? 'rotate(-90deg)' : 'none',
        ...overrideStyle,
      };
      break;
    default:
      style = {
        color: color ?? itemColor(type),
        transform: isReversed ? 'rotate(-90deg)' : 'none',
        ...overrideStyle,
      };
  }

  switch (type?.toLowerCase()) {
    case 'restricted':
      return <HelpOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'unauthorized':
      return <ReportProblemOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'global':
      return <PublicOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'trigger':
      return <CampaignOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'admin':
      return <ManageAccountsOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'search':
      return <BiotechOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'login':
      return <LoginOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'logout':
      return <LogoutOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'vocabulary':
      return <ShortTextOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'retentionrule':
      return (
        <LayersClearOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />
      );
    case 'streamcollection':
      return <StreamOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'settings':
      return <SettingsOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'draft':
      return <ArchitectureOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'taxiicollection':
      return (
        <DatabaseExportOutline style={style} fontSize={fontSize} role="img" aria-label={type} />
      );
    case 'feed':
      return (
        <FileDelimitedOutline style={style} fontSize={fontSize} role="img" aria-label={type} />
      );
    case 'backgroundtask':
      return (
        <AssignmentOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />
      );
    case 'work':
    case 'csvmapper':
      return <TableViewIcon style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'connector':
      return <ExtensionOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'marking-definition':
      return (
        <CenterFocusStrongOutlined
          style={style}
          fontSize={fontSize}
          role="img"
          aria-label={type}
        />
      );
    case 'external-reference':
      return (
        <LocalOfferOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />
      );
    case 'label':
      return <LabelOutline style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'file':
      return <FileOutline style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'attack-pattern':
      return <LockPattern style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'campaign':
      return <ChessKnight style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'note':
      return <SubjectOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'observed-data':
      return (
        <WifiTetheringOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />
      );
    case 'opinion':
      return <ReviewsOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'report':
      return (
        <DescriptionOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />
      );
    case 'grouping':
      return (
        <WorkspacesOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />
      );
    case 'course-of-action':
      return <ProgressWrench style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'role':
      return <SecurityOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'capability':
      return (
        <LocalPoliceOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />
      );
    case 'individual':
    case 'user':
      return <PersonOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'group':
    case 'all-users':
    case 'dynamic options':
    case 'dynamic from context':
    case 'dynamic from draft':
      return (
        <AccountGroupOutline style={style} fontSize={fontSize} role="img" aria-label={type} />
      );
    case 'organization':
    case 'identity':
      return (
        <AccountBalanceOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />
      );
    case 'organization-add':
      return (
        <BankPlus style={style} fontSize={fontSize} role="img" aria-label={type} />
      );
    case 'organization-remove':
      return (
        <BankMinus style={style} fontSize={fontSize} role="img" aria-label={type} />
      );
    case 'sector':
      return <DomainOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'system':
      return <StorageOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'indicator':
      return <ShieldSearch style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'infrastructure':
      return <RouterOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'intrusion-set':
      return <DiamondOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'city':
      return (
        <CityVariantOutline style={style} fontSize={fontSize} role="img" aria-label={type} />
      );
    case 'position':
    case 'location':
      return <PlaceOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'administrative-area':
      return <MapOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'country':
      return <FlagOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'region':
      return <PublicOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'malware':
      return <Biohazard style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'pir':
      return <TrackChanges style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'in-pir':
      return <TrackChanges style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'malware-analysis':
      return <BiotechOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'threat-actor':
    case 'threat-actor-group':
      return (
        <AccountMultipleOutline style={style} fontSize={fontSize} role="img" aria-label={type} />
      );
    case 'threat-actor-individual':
      return <LaptopAccount style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'tool':
      return <WebAssetOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'vulnerability':
      return <BugReportOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'incident':
      return <Fire style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'channel':
      return (
        <SurroundSoundOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />
      );
    case 'draftworkspace':
      return <ArchitectureOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'event':
      return <EventOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'narrative':
      return (
        <SpeakerNotesOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />
      );
    case 'language':
      return <TranslateOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'data-source':
      return <StreamOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'data-component':
      return <SourceOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'kill-chain-phase':
      return <RouteOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'artifact':
      return <ArchiveOutline style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'statustemplate':
      return <FactCheckOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'case':
      return <WorkOutline style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'case-incident':
      return (
        <BriefcaseEyeOutline style={style} fontSize={fontSize} role="img" aria-label={type} />
      );
    case 'case-template':
      return (
        <BriefcaseCheckOutline style={style} fontSize={fontSize} role="img" aria-label={type} />
      );
    case 'feedback':
      return (
        <BriefcaseEditOutline style={style} fontSize={fontSize} role="img" aria-label={type} />
      );
    case 'case-rfi':
      return (
        <BriefcaseSearchOutline style={style} fontSize={fontSize} role="img" aria-label={type} />
      );
    case 'case-rft':
      return (
        <BriefcaseRemoveOutline style={style} fontSize={fontSize} role="img" aria-label={type} />
      );
    case 'task':
      return <TaskAltOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'task-template':
      return (
        <TaskAlt style={style} fontSize={fontSize} role="img" aria-label={type} />
      );
    case 'security-coverage':
      return (
        <ShieldCheckOutline style={style} fontSize={fontSize} role="img" aria-label={type} />
      );
    case 'history':
      return (
        <ClipboardTextClockOutline
          style={style}
          fontSize={fontSize}
          role="img"
          aria-label={type}
        />
      );
    case 'activity':
      return (
        <SafetyCheckOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />
      );
    case 'dashboard':
    case 'workspace':
      return (
        <DashboardCustomizeOutlined
          style={style}
          fontSize={fontSize}
          role="img"
          aria-label={type}
        />
      );
    case 'investigation':
      return <TravelExploreOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'session':
      return <ReceiptOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'playbook':
      return (
        <PrecisionManufacturingOutlined
          style={style}
          fontSize={fontSize}
          role="img"
          aria-label={type}
        />
      );
    case 'decayrule':
      return <TroubleshootOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'edit':
      return <EditOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'container':
      return <Group style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'memory':
      return <MemoryOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'notification':
      return (
        <NotificationsOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />
      );
    case 'manual':
      return (
        <PlayCircleOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />
      );
    case 'managerconfiguration':
      return (
        <SettingsApplicationsOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />
      );
    case 'observable':
    case 'stix-cyber-observable':
    case 'autonomous-system':
    case 'directory':
    case 'domain-name':
    case 'email-addr':
    case 'email-message':
    case 'email-mime-part-type':
    case 'stixfile':
    case 'x509-certificate':
    case 'ipv4-addr':
    case 'ipv6-addr':
    case 'mac-addr':
    case 'mutex':
    case 'network-traffic':
    case 'process':
    case 'software':
    case 'url':
    case 'user-account':
    case 'windows-registry-key':
    case 'windows-registry-value-type':
    case 'cryptographic-key':
    case 'cryptocurrency-wallet':
    case 'hostname':
    case 'text':
    case 'user-agent':
    case 'bank-account':
    case 'phone-number':
    case 'payment-card':
    case 'credential':
    case 'tracking-number':
    case 'media-content':
    case 'persona':
    case 'ssh-key':
    case 'ai-prompt':
    case 'imei':
    case 'iccid':
    case 'imsi':
      return <HexagonOutline style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'stix-sighting-relationship':
    case 'sighting':
      return (
        <VisibilityOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />
      );
    case 'reduce':
      return <FilterAltOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'filter':
      return <FilterVariant style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'stream':
      return (
        <CastConnectedOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />
      );
    case 'console':
      return <TerminalOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'ai-agent':
      return <AutoAwesomeOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'storage':
      return (
        <DriveFolderUploadOutlined
          style={style}
          fontSize={fontSize}
          role="img"
          aria-label={type}
        />
      );
    case 'related':
      return <LinkOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'threats':
      return <FlaskOutline style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'overview':
      return <Gauge style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'variant':
      return <SourceFork style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'attribution':
      return <SourcePull style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'victimology':
      return <Target style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'cron':
      return <BackupTableOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'relationship':
    case 'stix-core-relationship':
    case 'targets':
    case 'uses':
    case 'located-at':
    case 'related-to':
    case 'mitigates':
    case 'reports-to':
    case 'supports':
    case 'known-as':
    case 'impersonates':
    case 'indicates':
    case 'comes-after':
    case 'attributed-to':
    case 'variant-of':
    case 'part-of':
    case 'employed-by':
    case 'resides-in':
    case 'citizen-of':
    case 'national-of':
    case 'drops':
    case 'delivers':
    case 'compromises':
    case 'belongs-to':
    case 'based-on':
    case 'communicates-with':
    case 'amplifies':
    case 'analysis-of':
    case 'authored-by':
    case 'beacons-to':
    case 'characterizes':
    case 'consists-of':
    case 'interpreted-by':
    case 'technology-from':
    case 'technology-to':
    case 'technology':
    case 'transferred-to':
    case 'demonstrates':
    case 'controls':
    case 'cooperates-with':
    case 'derived-from':
    case 'downloads':
    case 'has':
    case 'bcc':
    case 'cc':
    case 'obs_belongs-to':
    case 'owns':
    case 'dst':
    case 'from':
    case 'hosts':
    case 'image':
    case 'publishes':
    case 'duplicate-of':
    case 'obs_content':
    case 'service-dll':
    case 'dynamic-analysis-of':
    case 'contains':
    case 'created-by':
    case 'object-marking':
    case 'object-label':
    case 'object':
    case 'exfiltrates-to':
    case 'exploits':
    case 'investigates':
    case 'originates-from':
    case 'participates-in':
    case 'body-multipart':
    case 'body-raw':
    case 'child':
    case 'creator-user':
    case 'detects':
    case 'dst-payload':
    case 'encapsulated-by':
    case 'encapsulates':
    case 'opened-connection':
    case 'operating-system':
    case 'parent':
    case 'parent-directory':
    case 'raw-email':
    case 'src-payload':
    case 'remediates':
    case 'resolves-to':
    case 'participates-to':
    case 'obs_resolves-to':
    case 'revoked-by':
    case 'sample':
    case 'sender':
    case 'src':
    case 'to':
    case 'values':
    case 'static-analysis-of':
    case 'subnarrative-of':
    case 'subtechnique-of':
    case 'should-cover':
    case 'has-covered':
      return <VectorRadius style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'notifier':
      return <UpcomingOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'synchronizer':
      return <ViewStreamTwoTone style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'draft_context':
      return <ArchitectureOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'exclusionlist':
      return <PlaylistRemoveOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'disseminationlist':
      return <AlternateEmailOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'emailtemplate':
      return <EmailOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'finteldesign':
      return <DrawOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'securityplatform':
      return <SecurityOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'autofix':
      return <AutoFix style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'lock':
      return <LockOutline style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'lock-remove':
      return <LockMinusOutline style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'customview':
      return <Insights style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'savedfilter':
      return <FilterOutline style={style} fontSize={fontSize} role="img" aria-label={type} />;
    case 'default':
      return <CircleOutlined style={style} fontSize={fontSize} role="img" aria-label={type} />;
    default:
      return <AutoAwesomeMotion style={style} fontSize={fontSize} role="img" aria-label="item" />;
  }
};

interface ItemIconProps {
  type?: string | null;
  size?: 'inherit' | 'large' | 'medium' | 'small';
  variant?: string;
  color?: string | null;
  isReversed?: boolean;
  style?: CSSProperties;
}

const ItemIcon = ({
  type,
  size = 'medium',
  variant,
  color = null,
  isReversed = false,
  style,
}: ItemIconProps) => {
  return iconSelector(type, variant, size, color, isReversed, style);
};

export default ItemIcon;
