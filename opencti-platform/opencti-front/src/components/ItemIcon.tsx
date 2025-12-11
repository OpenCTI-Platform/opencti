import React from 'react';
import {
  AccountBalanceOutlined,
  AlternateEmailOutlined,
  ArchitectureOutlined,
  AssignmentOutlined,
  AutoAwesomeMotion,
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
) => {
  let style: React.CSSProperties;
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
      };
      break;
    default:
      style = {
        color: color ?? itemColor(type),
        transform: isReversed ? 'rotate(-90deg)' : 'none',
      };
  }

  switch (type?.toLowerCase()) {
    case 'restricted':
      return <HelpOutlined style={style} fontSize={fontSize} role="img" />;
    case 'unauthorized':
      return <ReportProblemOutlined style={style} fontSize={fontSize} role="img" />;
    case 'global':
      return <PublicOutlined style={style} fontSize={fontSize} role="img" />;
    case 'trigger':
      return <CampaignOutlined style={style} fontSize={fontSize} role="img" />;
    case 'admin':
      return <ManageAccountsOutlined style={style} fontSize={fontSize} role="img" />;
    case 'search':
      return <BiotechOutlined style={style} fontSize={fontSize} role="img" />;
    case 'login':
      return <LoginOutlined style={style} fontSize={fontSize} role="img" />;
    case 'logout':
      return <LogoutOutlined style={style} fontSize={fontSize} role="img" />;
    case 'vocabulary':
      return <ShortTextOutlined style={style} fontSize={fontSize} role="img" />;
    case 'retentionrule':
      return (
        <LayersClearOutlined style={style} fontSize={fontSize} role="img" />
      );
    case 'streamcollection':
      return <StreamOutlined style={style} fontSize={fontSize} role="img" />;
    case 'settings':
      return <SettingsOutlined style={style} fontSize={fontSize} role="img" />;
    case 'draft':
      return <ArchitectureOutlined style={style} fontSize={fontSize} role="img" />;
    case 'taxiicollection':
      return (
        <DatabaseExportOutline style={style} fontSize={fontSize} role="img" />
      );
    case 'feed':
      return (
        <FileDelimitedOutline style={style} fontSize={fontSize} role="img" />
      );
    case 'backgroundtask':
      return (
        <AssignmentOutlined style={style} fontSize={fontSize} role="img" />
      );
    case 'work':
    case 'csvmapper':
      return <TableViewIcon style={style} fontSize={fontSize} role="img" />;
    case 'connector':
      return <ExtensionOutlined style={style} fontSize={fontSize} role="img" />;
    case 'marking-definition':
      return (
        <CenterFocusStrongOutlined
          style={style}
          fontSize={fontSize}
          role="img"
        />
      );
    case 'external-reference':
      return (
        <LocalOfferOutlined style={style} fontSize={fontSize} role="img" />
      );
    case 'label':
      return <LabelOutline style={style} fontSize={fontSize} role="img" />;
    case 'file':
      return <FileOutline style={style} fontSize={fontSize} role="img" />;
    case 'attack-pattern':
      return <LockPattern style={style} fontSize={fontSize} role="img" />;
    case 'campaign':
      return <ChessKnight style={style} fontSize={fontSize} role="img" />;
    case 'note':
      return <SubjectOutlined style={style} fontSize={fontSize} role="img" />;
    case 'observed-data':
      return (
        <WifiTetheringOutlined style={style} fontSize={fontSize} role="img" />
      );
    case 'opinion':
      return <ReviewsOutlined style={style} fontSize={fontSize} role="img" />;
    case 'report':
      return (
        <DescriptionOutlined style={style} fontSize={fontSize} role="img" />
      );
    case 'grouping':
      return (
        <WorkspacesOutlined style={style} fontSize={fontSize} role="img" />
      );
    case 'course-of-action':
      return <ProgressWrench style={style} fontSize={fontSize} role="img" />;
    case 'role':
      return <SecurityOutlined style={style} fontSize={fontSize} role="img" />;
    case 'capability':
      return (
        <LocalPoliceOutlined style={style} fontSize={fontSize} role="img" />
      );
    case 'individual':
    case 'user':
      return <PersonOutlined style={style} fontSize={fontSize} role="img" />;
    case 'group':
      return (
        <AccountGroupOutline style={style} fontSize={fontSize} role="img" />
      );
    case 'all-users':
    case 'dynamic options':
      return (
        <AccountGroupOutline style={style} fontSize={fontSize} role="img" />
      );
    case 'organization':
    case 'identity':
      return (
        <AccountBalanceOutlined style={style} fontSize={fontSize} role="img" />
      );
    case 'organization-add':
      return (
        <BankPlus style={style} fontSize={fontSize} role="img" />
      );
    case 'organization-remove':
      return (
        <BankMinus style={style} fontSize={fontSize} role="img" />
      );
    case 'sector':
      return <DomainOutlined style={style} fontSize={fontSize} role="img" />;
    case 'system':
      return <StorageOutlined style={style} fontSize={fontSize} role="img" />;
    case 'indicator':
      return <ShieldSearch style={style} fontSize={fontSize} role="img" />;
    case 'infrastructure':
      return <RouterOutlined style={style} fontSize={fontSize} role="img" />;
    case 'intrusion-set':
      return <DiamondOutlined style={style} fontSize={fontSize} role="img" />;
    case 'city':
      return (
        <CityVariantOutline style={style} fontSize={fontSize} role="img" />
      );
    case 'position':
    case 'location':
      return <PlaceOutlined style={style} fontSize={fontSize} role="img" />;
    case 'administrative-area':
      return <MapOutlined style={style} fontSize={fontSize} role="img" />;
    case 'country':
      return <FlagOutlined style={style} fontSize={fontSize} role="img" />;
    case 'region':
      return <PublicOutlined style={style} fontSize={fontSize} role="img" />;
    case 'malware':
      return <Biohazard style={style} fontSize={fontSize} role="img" />;
    case 'pir':
      return <TrackChanges style={style} fontSize={fontSize} role="img" />;
    case 'in-pir':
      return <TrackChanges style={style} fontSize={fontSize} role="img" />;
    case 'malware-analysis':
      return <BiotechOutlined style={style} fontSize={fontSize} role="img" />;
    case 'threat-actor':
    case 'threat-actor-group':
      return (
        <AccountMultipleOutline style={style} fontSize={fontSize} role="img" />
      );
    case 'threat-actor-individual':
      return <LaptopAccount style={style} fontSize={fontSize} role="img" />;
    case 'tool':
      return <WebAssetOutlined style={style} fontSize={fontSize} role="img" />;
    case 'vulnerability':
      return <BugReportOutlined style={style} fontSize={fontSize} role="img" />;
    case 'incident':
      return <Fire style={style} fontSize={fontSize} role="img" />;
    case 'channel':
      return (
        <SurroundSoundOutlined style={style} fontSize={fontSize} role="img" />
      );
    case 'event':
      return <EventOutlined style={style} fontSize={fontSize} role="img" />;
    case 'narrative':
      return (
        <SpeakerNotesOutlined style={style} fontSize={fontSize} role="img" />
      );
    case 'language':
      return <TranslateOutlined style={style} fontSize={fontSize} role="img" />;
    case 'data-source':
      return <StreamOutlined style={style} fontSize={fontSize} role="img" />;
    case 'data-component':
      return <SourceOutlined style={style} fontSize={fontSize} role="img" />;
    case 'kill-chain-phase':
      return <RouteOutlined style={style} fontSize={fontSize} role="img" />;
    case 'artifact':
      return <ArchiveOutline style={style} fontSize={fontSize} role="img" />;
    case 'statustemplate':
      return <FactCheckOutlined style={style} fontSize={fontSize} role="img" />;
    case 'case':
      return <WorkOutline style={style} fontSize={fontSize} role="img" />;
    case 'case-incident':
      return (
        <BriefcaseEyeOutline style={style} fontSize={fontSize} role="img" />
      );
    case 'case-template':
      return (
        <BriefcaseCheckOutline style={style} fontSize={fontSize} role="img" />
      );
    case 'feedback':
      return (
        <BriefcaseEditOutline style={style} fontSize={fontSize} role="img" />
      );
    case 'case-rfi':
      return (
        <BriefcaseSearchOutline style={style} fontSize={fontSize} role="img" />
      );
    case 'case-rft':
      return (
        <BriefcaseRemoveOutline style={style} fontSize={fontSize} role="img" />
      );
    case 'task':
      return <TaskAltOutlined style={style} fontSize={fontSize} role="img" />;
    case 'task-template':
      return (
        <TaskAlt style={style} fontSize={fontSize} role="img" />
      );
    case 'security-coverage':
      return (
        <ShieldCheckOutline style={style} fontSize={fontSize} role="img" />
      );
    case 'history':
      return (
        <ClipboardTextClockOutline
          style={style}
          fontSize={fontSize}
          role="img"
        />
      );
    case 'activity':
      return (
        <SafetyCheckOutlined style={style} fontSize={fontSize} role="img" />
      );
    case 'dashboard':
    case 'workspace':
      return (
        <DashboardCustomizeOutlined
          style={style}
          fontSize={fontSize}
          role="img"
        />
      );
    case 'investigation':
      return <TravelExploreOutlined style={style} fontSize={fontSize} role="img" />;
    case 'session':
      return <ReceiptOutlined style={style} fontSize={fontSize} role="img" />;
    case 'playbook':
      return (
        <PrecisionManufacturingOutlined
          style={style}
          fontSize={fontSize}
          role="img"
        />
      );
    case 'decayrule':
      return <TroubleshootOutlined style={style} fontSize={fontSize} role="img" />;
    case 'edit':
      return <EditOutlined style={style} fontSize={fontSize} role="img" />;
    case 'container':
      return <Group style={style} fontSize={fontSize} role="img" />;
    case 'memory':
      return <MemoryOutlined style={style} fontSize={fontSize} role="img" />;
    case 'notification':
      return (
        <NotificationsOutlined style={style} fontSize={fontSize} role="img" />
      );
    case 'manual':
      return (
        <PlayCircleOutlined style={style} fontSize={fontSize} role="img" />
      );
    case 'managerconfiguration':
      return (
        <SettingsApplicationsOutlined style={style} fontSize={fontSize} role="img" />
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
    case 'imei':
    case 'iccid':
    case 'imsi':   
      return <HexagonOutline style={style} fontSize={fontSize} role="img" />;
    case 'stix-sighting-relationship':
    case 'sighting':
      return (
        <VisibilityOutlined style={style} fontSize={fontSize} role="img" />
      );
    case 'reduce':
      return <FilterAltOutlined style={style} fontSize={fontSize} role="img" />;
    case 'filter':
      return <FilterVariant style={style} fontSize={fontSize} role="img" />;
    case 'stream':
      return (
        <CastConnectedOutlined style={style} fontSize={fontSize} role="img" />
      );
    case 'console':
      return <TerminalOutlined style={style} fontSize={fontSize} role="img" />;
    case 'storage':
      return (
        <DriveFolderUploadOutlined
          style={style}
          fontSize={fontSize}
          role="img"
        />
      );
    case 'related':
      return <LinkOutlined style={style} fontSize={fontSize} role="img" />;
    case 'threats':
      return <FlaskOutline style={style} fontSize={fontSize} role="img" />;
    case 'overview':
      return <Gauge style={style} fontSize={fontSize} role="img" />;
    case 'variant':
      return <SourceFork style={style} fontSize={fontSize} role="img" />;
    case 'attribution':
      return <SourcePull style={style} fontSize={fontSize} role="img" />;
    case 'victimology':
      return <Target style={style} fontSize={fontSize} role="img" />;
    case 'cron':
      return <BackupTableOutlined style={style} fontSize={fontSize} role="img" />;
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
      return <VectorRadius style={style} fontSize={fontSize} role="img" />;
    case 'notifier':
      return <UpcomingOutlined style={style} fontSize={fontSize} role="img" />;
    case 'synchronizer':
      return <ViewStreamTwoTone style={style} fontSize={fontSize} role="img" />;
    case 'draft_context':
      return <ArchitectureOutlined style={style} fontSize={fontSize} role="img" />;
    case 'exclusionlist':
      return <PlaylistRemoveOutlined style={style} fontSize={fontSize} role="img" />;
    case 'disseminationlist':
      return <AlternateEmailOutlined style={style} fontSize={fontSize} role="img" />;
    case 'emailtemplate':
      return <EmailOutlined style={style} fontSize={fontSize} role="img" />;
    case 'finteldesign':
      return <DrawOutlined style={style} fontSize={fontSize} role="img" />;
    case 'securityplatform':
      return <SecurityOutlined style={style} fontSize={fontSize} role="img" />;
    case 'autofix':
      return <AutoFix style={style} fontSize={fontSize} role="img" />;
    case 'lock':
      return <LockOutline style={style} fontSize={fontSize} role="img" />;
    case 'lock-remove':
      return <LockMinusOutline style={style} fontSize={fontSize} role="img" />;
    case 'default':
      return <CircleOutlined style={style} fontSize={fontSize} role="img" />;
    default:
      return <AutoAwesomeMotion style={style} fontSize={fontSize} role="img" />;
  }
};

interface ItemIconProps {
  type?: string | null,
  size?: 'inherit' | 'large' | 'medium' | 'small',
  variant?: string,
  color?: string | null,
  isReversed?: boolean,
}

const ItemIcon = ({ type, size = 'medium', variant, color = null, isReversed = false }: ItemIconProps) => {
  return iconSelector(type, variant, size, color, isReversed);
};

export default ItemIcon;
