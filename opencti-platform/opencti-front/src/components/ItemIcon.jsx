import React from 'react';
import * as PropTypes from 'prop-types';
import {
  AccountBalanceOutlined,
  AssignmentOutlined,
  BiotechOutlined,
  BugReportOutlined,
  CampaignOutlined,
  CenterFocusStrongOutlined,
  DescriptionOutlined,
  DomainOutlined,
  EventOutlined,
  ExtensionOutlined,
  FactCheckOutlined,
  FlagOutlined,
  GroupOutlined,
  GroupsOutlined,
  HelpOutlined,
  LayersClearOutlined,
  LocalOfferOutlined,
  LoginOutlined,
  LogoutOutlined,
  ManageAccountsOutlined,
  MapOutlined,
  PersonOutlined,
  PlaceOutlined,
  PublicOutlined,
  ReportProblemOutlined,
  ReviewsOutlined,
  RouterOutlined,
  SettingsOutlined,
  ShortTextOutlined,
  SourceOutlined,
  SpeakerNotesOutlined,
  StorageOutlined,
  StreamOutlined,
  SubjectOutlined,
  SurroundSoundOutlined,
  TaskAltOutlined,
  TranslateOutlined,
  Visibility,
  WebAssetOutlined,
  WifiTetheringOutlined,
  WorkOutline,
  WorkspacesOutlined,
} from '@mui/icons-material';
import {
  ArchiveOutline,
  Biohazard,
  BriefcaseCheckOutline,
  BriefcaseEditOutline,
  BriefcaseEyeOutline,
  BriefcaseRemoveOutline,
  BriefcaseSearchOutline,
  ChessKnight,
  CityVariantOutline,
  DatabaseExportOutline,
  DiamondOutline,
  FileDelimitedOutline,
  Fire,
  HexagonOutline,
  LabelOutline,
  LaptopAccount,
  Launch,
  LockPattern,
  ProgressWrench,
  ShieldSearch,
  VectorRadius,
} from 'mdi-material-ui';
import { itemColor } from '../utils/Colors';

const iconSelector = (type, variant, fontSize, color, isReversed) => {
  let style;
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

  switch (type) {
    case 'unauthorized':
      return (
        <ReportProblemOutlined style={style} fontSize={fontSize} role="img" />
      );
    case 'global':
      return <PublicOutlined style={style} fontSize={fontSize} role="img" />;
    case 'Trigger':
      return <CampaignOutlined style={style} fontSize={fontSize} role="img" />;
    case 'admin':
      return (
        <ManageAccountsOutlined style={style} fontSize={fontSize} role="img" />
      );
    case 'search':
      return <BiotechOutlined style={style} fontSize={fontSize} role="img" />;
    case 'login':
      return <LoginOutlined style={style} fontSize={fontSize} role="img" />;
    case 'logout':
      return <LogoutOutlined style={style} fontSize={fontSize} role="img" />;
    case 'Vocabulary':
      return <ShortTextOutlined style={style} fontSize={fontSize} role="img" />;
    case 'RetentionRule':
      return (
        <LayersClearOutlined style={style} fontSize={fontSize} role="img" />
      );
    case 'StreamCollection':
      return <StreamOutlined style={style} fontSize={fontSize} role="img" />;
    case 'Settings':
      return <SettingsOutlined style={style} fontSize={fontSize} role="img" />;
    case 'TaxiiCollection':
      return (
        <DatabaseExportOutline style={style} fontSize={fontSize} role="img" />
      );
    case 'Feed':
      return (
        <FileDelimitedOutline style={style} fontSize={fontSize} role="img" />
      );
    case 'BackgroundTask':
      return (
        <AssignmentOutlined style={style} fontSize={fontSize} role="img" />
      );
    case 'work':
    case 'Connector':
      return <ExtensionOutlined style={style} fontSize={fontSize} role="img" />;
    case 'Marking-Definition':
      return (
        <CenterFocusStrongOutlined
          style={style}
          fontSize={fontSize}
          role="img"
        />
      );
    case 'External-Reference':
      return (
        <LocalOfferOutlined style={style} fontSize={fontSize} role="img" />
      );
    case 'Label':
      return <LabelOutline style={style} fontSize={fontSize} role="img" />;
    case 'Attack-Pattern':
      return <LockPattern style={style} fontSize={fontSize} role="img" />;
    case 'Campaign':
      return <ChessKnight style={style} fontSize={fontSize} role="img" />;
    case 'Note':
      return <SubjectOutlined style={style} fontSize={fontSize} role="img" />;
    case 'Observed-Data':
      return (
        <WifiTetheringOutlined style={style} fontSize={fontSize} role="img" />
      );
    case 'Opinion':
      return <ReviewsOutlined style={style} fontSize={fontSize} role="img" />;
    case 'Report':
      return (
        <DescriptionOutlined style={style} fontSize={fontSize} role="img" />
      );
    case 'Grouping':
      return (
        <WorkspacesOutlined style={style} fontSize={fontSize} role="img" />
      );
    case 'Course-Of-Action':
      return <ProgressWrench style={style} fontSize={fontSize} role="img" />;
    case 'Role':
    case 'Individual':
    case 'User':
      return <PersonOutlined style={style} fontSize={fontSize} role="img" />;
    case 'Group':
      return <GroupOutlined style={style} fontSize={fontSize} role="img" />;
    case 'all-users':
      return <GroupsOutlined style={style} fontSize={fontSize} role="img" />;
    case 'Organization':
    case 'Identity':
      return (
        <AccountBalanceOutlined style={style} fontSize={fontSize} role="img" />
      );
    case 'Sector':
      return <DomainOutlined style={style} fontSize={fontSize} role="img" />;
    case 'System':
      return <StorageOutlined style={style} fontSize={fontSize} role="img" />;
    case 'Indicator':
      return <ShieldSearch style={style} fontSize={fontSize} role="img" />;
    case 'Infrastructure':
      return <RouterOutlined style={style} fontSize={fontSize} role="img" />;
    case 'Intrusion-Set':
      return <DiamondOutline style={style} fontSize={fontSize} role="img" />;
    case 'City':
      return (
        <CityVariantOutline style={style} fontSize={fontSize} role="img" />
      );
    case 'Position':
    case 'Location':
      return <PlaceOutlined style={style} fontSize={fontSize} role="img" />;
    case 'Administrative-Area':
      return <MapOutlined style={style} fontSize={fontSize} role="img" />;
    case 'Country':
      return <FlagOutlined style={style} fontSize={fontSize} role="img" />;
    case 'Region':
      return <PublicOutlined style={style} fontSize={fontSize} role="img" />;
    case 'Malware':
      return <Biohazard style={style} fontSize={fontSize} role="img" />;
    case 'Malware-Analysis':
      return <BiotechOutlined style={style} fontSize={fontSize} role="img" />;
    case 'Threat-Actor-Group':
      return <LaptopAccount style={style} fontSize={fontSize} role="img" />;
    case 'Threat-Actor-Individual':
      return <LaptopAccount style={style} fontSize={fontSize} role="img" />;
    case 'Tool':
      return <WebAssetOutlined style={style} fontSize={fontSize} role="img" />;
    case 'Vulnerability':
      return <BugReportOutlined style={style} fontSize={fontSize} role="img" />;
    case 'Incident':
      return <Fire style={style} fontSize={fontSize} role="img" />;
    case 'Channel':
      return (
        <SurroundSoundOutlined style={style} fontSize={fontSize} role="img" />
      );
    case 'Event':
      return <EventOutlined style={style} fontSize={fontSize} role="img" />;
    case 'Narrative':
      return (
        <SpeakerNotesOutlined style={style} fontSize={fontSize} role="img" />
      );
    case 'Language':
      return <TranslateOutlined style={style} fontSize={fontSize} role="img" />;
    case 'Data-Source':
      return <StreamOutlined style={style} fontSize={fontSize} role="img" />;
    case 'Data-Component':
      return <SourceOutlined style={style} fontSize={fontSize} role="img" />;
    case 'Kill-Chain-Phase':
      return <Launch style={style} fontSize={fontSize} role="img" />;
    case 'Artifact':
      return <ArchiveOutline style={style} fontSize={fontSize} role="img" />;
    case 'StatusTemplate':
      return <FactCheckOutlined style={style} fontSize={fontSize} role="img" />;
    case 'Case':
      return <WorkOutline style={style} fontSize={fontSize} role="img" />;
    case 'Case-Incident':
      return (
        <BriefcaseEyeOutline style={style} fontSize={fontSize} role="img" />
      );
    case 'Case-Template':
      return (
        <BriefcaseCheckOutline style={style} fontSize={fontSize} role="img" />
      );
    case 'Feedback':
      return (
        <BriefcaseEditOutline style={style} fontSize={fontSize} role="img" />
      );
    case 'Case-Rfi':
      return (
        <BriefcaseSearchOutline style={style} fontSize={fontSize} role="img" />
      );
    case 'Case-Rft':
      return (
        <BriefcaseRemoveOutline style={style} fontSize={fontSize} role="img" />
      );
    case 'Task':
      return <TaskAltOutlined style={style} fontSize={fontSize} role="img" />;
    case 'Stix-Cyber-Observable':
    case 'Autonomous-System':
    case 'Directory':
    case 'Domain-Name':
    case 'Email-Addr':
    case 'Email-Message':
    case 'Email-Mime-Part-Type':
    case 'StixFile':
    case 'X509-Certificate':
    case 'IPv4-Addr':
    case 'IPv6-Addr':
    case 'Mac-Addr':
    case 'Mutex':
    case 'Network-Traffic':
    case 'Process':
    case 'Software':
    case 'Url':
    case 'User-Account':
    case 'Windows-Registry-Key':
    case 'Windows-Registry-Value-Type':
    case 'Cryptographic-Key':
    case 'Cryptocurrency-Wallet':
    case 'Hostname':
    case 'Text':
    case 'User-Agent':
    case 'Bank-Account':
    case 'Phone-Number':
    case 'Payment-Card':
    case 'Media-Content':
      return <HexagonOutline style={style} fontSize={fontSize} role="img" />;
    case 'stix-sighting-relationship':
      return <Visibility style={style} fontSize={fontSize} role="img" />;
    case 'stix-internal-relationship':
      return <VectorRadius style={style} fontSize={fontSize} role="img" />;
    case 'Stix-Core-Relationship':
    case 'Relationship':
    case 'stix-core-relationship':
    case 'targets':
    case 'uses':
    case 'located-at':
    case 'related-to':
    case 'mitigates':
    case 'impersonates':
    case 'indicates':
    case 'comes-after':
    case 'attributed-to':
    case 'variant-of':
    case 'part-of':
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
    case 'exfiltrates-to':
    case 'exploits':
    case 'investigates':
    case 'x_opencti_linked-to':
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
      return <VectorRadius style={style} fontSize={fontSize} role="img" />;
    default:
      return <HelpOutlined style={style} fontSize={fontSize} role="img" />;
  }
};

const ItemIcon = (props) => {
  const { type, size, variant, color = null, isReversed = false } = props;
  const fontSize = size || 'medium';
  return iconSelector(type, variant, fontSize, color, isReversed);
};

ItemIcon.propTypes = {
  type: PropTypes.string,
  size: PropTypes.string,
  variant: PropTypes.string,
  color: PropTypes.string,
  isReversed: PropTypes.bool,
};

export default ItemIcon;
