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
  Print,
  MapOutlined,
  CenterFocusStrongOutlined,
  ShortTextOutlined,
  WorkOutline,
  FeedbackOutlined,
  LanguageOutlined,
  WifiTetheringOutlined,
  ApartmentOutlined,
  HomeOutlined,
  Call,
  Visibility,
  DeveloperBoard,
  PlaceOutlined,
  StorageOutlined,
  StayCurrentPortrait,
  PersonalVideo,
  SettingsVoice,
  Kitchen,
  Whatshot,
  Work,
  Phone,
  Apple,
  Devices,
  PhoneLocked,
  ViewColumn,
  Wifi,
  Storage,
} from '@material-ui/icons';
import {
  MicrosoftWindows,
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
import networkIcon from '../resources/images/assets/networkIcon.svg';
import softwareIcon from '../resources/images/assets/softwareIcon.svg';
import deviceIcon from '../resources/images/assets/deviceIcon.svg';
import linuxIcon from '../resources/images/assets/linuxIcon.svg';
import appendeciesIcon from '../resources/images/entities/appendeciesIcon.svg';
import otherImage from '../resources/images/entities/otherImage.svg';
import switchImage from '../resources/images/entities/switchImage.svg';
import IPAddress from '../resources/images/entities/ip_address.svg';
import VoipDeviceImage from '../resources/images/entities/voip_device.svg';
import operatingSystemIcon from '../resources/images/entities/operating_system.svg';
import loadBalancerImage from '../resources/images/entities/load_balancer.svg';
import routerImage from '../resources/images/entities/responsible_parties.svg';
import collectIcon from '../resources/images/entities/collectIcon.svg';
import poamIcon from '../resources/images/entities/poamIcon.svg';
import userPersonIcon from '../resources/images/assets/userPersonIcon.svg';
import partiesIcon from '../resources/images/assets/partiesIcon.svg';
import applicationSoftwareIcon from '../resources/images/entities/application_software.svg';
import locationsIcon from '../resources/images/assets/locationsIcon.svg';
import inventoryItemIcon from '../resources/images/assets/inventoryItem.svg';
import resourceIcon from '../resources/images/assets/resource.svg';
import assetDashboard from '../resources/images/entities/asset_dashboard.svg';
import riskDashboard from '../resources/images/entities/risk_dashboard.svg';

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
    case 'apple':
      return <Apple style={style} fontSize={fontSize} role="img" />;
    case 'microsoft':
      return <MicrosoftWindows style={style} fontSize={fontSize} role="img" />;
    case 'linux':
      return <img src={linuxIcon} style={style} alt="linux-icon" />;
    case 'component':
      return <img src={softwareIcon} style={style} alt="software-icon" />;
    case 'inventory_item':
      return <img src={inventoryItemIcon} style={style} alt="inventoryItem-icon" />;
    case 'resource':
      return <img src={resourceIcon} style={style} alt="resource-icon" />;
    case 'location':
      return <img src={locationsIcon} style={style} alt="locations-icon" />;
    case 'party':
      return <img src={partiesIcon} style={style} alt="party-icon" />;
    case 'user':
      return <img src={userPersonIcon} style={style} alt="user-icon" />;
    case 'laptop':
      return <img src={deviceIcon} style={style} alt="laptop-icon" />;
    case 'load_balancer':
      return <img src={loadBalancerImage} style={style} alt="load-balancer-icon" />;
    case 'switch':
      return <img src={switchImage} style={style} alt="switch-icon" />;
    case 'other':
      return <img src={otherImage} style={style} alt="other-icon" />;
    case 'application_software':
      return <img src={applicationSoftwareIcon} style={style} alt="applicationSoftware-icon" />;
    case 'operating_system':
      return <img src={operatingSystemIcon} style={style} alt="operatingSystem-icon" />;
    case 'physical_device':
      return <Devices style={style} fontSize={fontSize} role="img" />;
    case 'router':
      return <img src={routerImage} style={style} alt="router-icon" />;
    case 'ip_address':
      return <IPAddress style={style} fontSize={fontSize} role="img" />;
    case 'firewall':
      return <Whatshot style={style} fontSize={fontSize} role="img" />;
    case 'embedded':
      return <DeveloperBoard style={style} fontSize={fontSize} role="img" />;
    case 'network':
      return <img src={networkIcon} style={style} alt="network-icon" />;
    case 'software':
      return <img src={softwareIcon} style={style} alt="software-icon" />;
    case 'appendecies':
      return <img src={appendeciesIcon} style={style} alt="appendecies-icon" />;
    case 'collected':
      return <img src={collectIcon} style={style} alt="collected-icon" />;
    case 'poam':
      return <img src={poamIcon} style={style} alt="poam-icon" />;
    case 'asset':
    case 'global-assets':
      return <img src={assetDashboard} style={style} alt="asset-icon" />;
    case 'global-risks':
    case 'risk':
      return <img src={riskDashboard} style={style} alt="risk-icon" />;
    case 'storage_array':
      return <Storage style={style} fontSize={fontSize} role="img" />;
    case 'appliance':
      return <Kitchen style={style} fontSize={fontSize} role="img" />;
    case 'network_device':
      return <Wifi style={style} fontSize={fontSize} role="img" />;
    case 'server':
      return <ViewColumn style={style} fontSize={fontSize} role="img" />;
    case 'voip_device':
      return <img src={VoipDeviceImage} style={style} alt="voip-device-icon" />;
    case 'workstation':
      return <Work style={style} fontSize={fontSize} role="img" />;
    case 'voip_handset':
      return <Phone style={style} fontSize={fontSize} role="img" />;
    case 'mobile_device':
      return <StayCurrentPortrait style={style} fontSize={fontSize} role="img" />;
    case 'office':
      return <ApartmentOutlined style={style} fontSize={fontSize} role="img" />;
    case 'mobile':
      return <HomeOutlined style={style} fontSize={fontSize} role="img" />;
    case 'home':
      return <Call style={style} fontSize={fontSize} role="img" />;
    case 'pbx':
      return <PhoneLocked style={style} fontSize={fontSize} role="img" />;
    case 'computing_device':
      return <PersonalVideo style={style} fontSize={fontSize} role="img" />;
    case 'voip_router':
      return <SettingsVoice style={style} fontSize={fontSize} role="img" />;
    case 'External-Reference':
      return <LanguageOutlined style={style} fontSize={fontSize} role="img" />;
    case 'printer':
      return <Print style={style} fontSize={fontSize} role="img" />;
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
