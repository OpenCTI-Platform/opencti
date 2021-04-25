import React, { Component } from 'react';
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
} from '@material-ui/icons';
import {
  Biohazard,
  DiamondOutline,
  ChessKnight,
  LockPattern,
  Application,
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
      return (
        <AccountBalanceOutlined style={style} fontSize={fontSize} role="img" />
      );
    case 'Sector':
      return <DomainOutlined style={style} fontSize={fontSize} role="img" />;
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
      return <Application style={style} fontSize={fontSize} role="img" />;
    case 'Vulnerability':
      return <BugReportOutlined style={style} fontSize={fontSize} role="img" />;
    case 'Incident':
      return <Fire style={style} fontSize={fontSize} role="img" />;
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
    case 'X509-V3-Extensions-Type':
    case 'X-OpenCTI-Cryptographic-Key':
    case 'X-OpenCTI-Cryptocurrency-Wallet':
    case 'X-OpenCTI-Hostname':
    case 'X-OpenCTI-Text':
    case 'X-OpenCTI-User-Agent':
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
    case 'localization':
    case 'part-of':
    case 'drops':
      return <VectorRadius style={style} fontSize={fontSize} role="img" />;
    default:
      return <HelpOutlined style={style} fontSize={fontSize} role="img" />;
  }
};

class ItemIcon extends Component {
  render() {
    const {
      type, size, variant, color,
    } = this.props;
    const fontSize = size || 'default';
    return iconSelector(type, variant, fontSize, color);
  }
}

ItemIcon.propTypes = {
  type: PropTypes.string,
  size: PropTypes.string,
  variant: PropTypes.string,
  color: PropTypes.string,
};

export default ItemIcon;
