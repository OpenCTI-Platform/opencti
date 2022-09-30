import React from 'react';
import * as PropTypes from 'prop-types';
import {
  FlagOutlined,
  PersonOutlined,
  AccountBalanceOutlined,
  DomainOutlined,
  PublicOutlined,
  HelpOutlined,
  BugReportOutlined,
  DescriptionOutlined,
  MapOutlined,
  CenterFocusStrongOutlined,
  ShortTextOutlined,
  WorkOutline,
  FeedbackOutlined,
  LanguageOutlined,
  WifiTetheringOutlined,
  Visibility,
  PlaceOutlined,
  StorageOutlined,
  WebAssetOutlined,
  SurroundSoundOutlined,
  EventOutlined,
  SpeakerNotesOutlined,
  TranslateOutlined,
} from '@mui/icons-material';
import {
  Biohazard,
  DiamondOutline,
  ChessKnight,
  LockPattern,
  Fire,
  CityVariantOutline,
  LabelOutline,
  ProgressWrench,
  HexagonOutline,
  VectorRadius,
  ShieldSearch,
  ServerNetwork,
} from 'mdi-material-ui';

const iconSelector = (type, variant, fontSize, color) => {
  let style = {};
  switch (variant) {
    case 'inline':
      style = {
        color,
        width: 20,
        height: 20,
        margin: '0 7px 0 0',
        float: 'left',
      };
      break;
    default:
      style = {
        color,
      };
  }

  switch (type) {
    case 'attribute':
      return <ShortTextOutlined style={style} fontSize={fontSize} role="img" />;
    case 'Marking-Definition':
      return (
        <CenterFocusStrongOutlined
          style={style}
          fontSize={fontSize}
          role="img"
        />
      );
    case 'External-Reference':
      return <LanguageOutlined style={style} fontSize={fontSize} role="img" />;
    case 'Label':
      return <LabelOutline style={style} fontSize={fontSize} role="img" />;
    case 'Attack-Pattern':
      return <LockPattern style={style} fontSize={fontSize} role="img" />;
    case 'Campaign':
      return <ChessKnight style={style} fontSize={fontSize} role="img" />;
    case 'Note':
      return <WorkOutline style={style} fontSize={fontSize} role="img" />;
    case 'Observed-Data':
      return (
        <WifiTetheringOutlined style={style} fontSize={fontSize} role="img" />
      );
    case 'Opinion':
      return <FeedbackOutlined style={style} fontSize={fontSize} role="img" />;
    case 'Report':
      return (
        <DescriptionOutlined style={style} fontSize={fontSize} role="img" />
      );
    case 'Course-Of-Action':
      return <ProgressWrench style={style} fontSize={fontSize} role="img" />;
    case 'Individual':
      return <PersonOutlined style={style} fontSize={fontSize} role="img" />;
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
      return <ServerNetwork style={style} fontSize={fontSize} role="img" />;
    case 'Intrusion-Set':
      return <DiamondOutline style={style} fontSize={fontSize} role="img" />;
    case 'City':
      return (
        <CityVariantOutline style={style} fontSize={fontSize} role="img" />
      );
    case 'Position':
    case 'Location':
      return <PlaceOutlined style={style} fontSize={fontSize} role="img" />;
    case 'Country':
      return <FlagOutlined style={style} fontSize={fontSize} role="img" />;
    case 'Region':
      return <MapOutlined style={style} fontSize={fontSize} role="img" />;
    case 'Malware':
      return <Biohazard style={style} fontSize={fontSize} role="img" />;
    case 'Threat-Actor':
      return <PublicOutlined style={style} fontSize={fontSize} role="img" />;
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
    case 'Stix-Cyber-Observable':
    case 'Autonomous-System':
    case 'Directory':
    case 'Domain-Name':
    case 'Email-Addr':
    case 'Email-Message':
    case 'Email-Mime-Part-Type':
    case 'Artifact':
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
      return <VectorRadius style={style} fontSize={fontSize} role="img" />;
    default:
      return <HelpOutlined style={style} fontSize={fontSize} role="img" />;
  }
};

const ItemIcon = (props) => {
  const { type, size, variant, color } = props;
  const fontSize = size || 'medium';
  return iconSelector(type, variant, fontSize, color);
};

ItemIcon.propTypes = {
  type: PropTypes.string,
  size: PropTypes.string,
  variant: PropTypes.string,
  color: PropTypes.string,
};

export default ItemIcon;
