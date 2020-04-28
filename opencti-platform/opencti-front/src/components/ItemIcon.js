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
} from '@material-ui/icons';
import {
  Biohazard,
  DiamondOutline,
  ChessKnight,
  LockPattern,
  Application,
  Fire,
  CityVariantOutline,
  TagOutline,
  ProgressWrench,
  HexagonOutline,
  VectorRadius,
  ShieldSearch,
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
    case 'region':
      return <MapOutlined style={style} fontSize={fontSize} role="img" />;
    case 'country':
      return <FlagOutlined style={style} fontSize={fontSize} role="img" />;
    case 'sector':
      return <DomainOutlined style={style} fontSize={fontSize} role="img" />;
    case 'city':
      return (
        <CityVariantOutline style={style} fontSize={fontSize} role="img" />
      );
    case 'threat-actor':
      return <PublicOutlined style={style} fontSize={fontSize} role="img" />;
    case 'intrusion-set':
      return <DiamondOutline style={style} fontSize={fontSize} role="img" />;
    case 'campaign':
      return <ChessKnight style={style} fontSize={fontSize} role="img" />;
    case 'incident':
      return <Fire style={style} fontSize={fontSize} role="img" />;
    case 'user':
      return <PersonOutlined style={style} fontSize={fontSize} role="img" />;
    case 'organization':
      return (
        <AccountBalanceOutlined style={style} fontSize={fontSize} role="img" />
      );
    case 'attack-pattern':
      return <LockPattern style={style} fontSize={fontSize} role="img" />;
    case 'course-of-action':
      return <ProgressWrench style={style} fontSize={fontSize} role="img" />;
    case 'malware':
      return <Biohazard style={style} fontSize={fontSize} role="img" />;
    case 'tool':
      return <Application style={style} fontSize={fontSize} role="img" />;
    case 'vulnerability':
      return <BugReportOutlined style={style} fontSize={fontSize} role="img" />;
    case 'report':
      return (
        <DescriptionOutlined style={style} fontSize={fontSize} role="img" />
      );
    case 'indicator':
      return <ShieldSearch style={style} fontSize={fontSize} role="img" />;
    case 'tag':
      return <TagOutline style={style} fontSize={fontSize} role="img" />;
    case 'note':
      return <WorkOutline style={style} fontSize={fontSize} role="img" />;
    case 'attribute':
      return <ShortTextOutlined style={style} fontSize={fontSize} role="img" />;
    case 'marking-definition':
      return (
        <CenterFocusStrongOutlined
          style={style}
          fontSize={fontSize}
          role="img"
        />
      );
    case 'autonomous-system':
    case 'domain':
    case 'ipv4-addr':
    case 'ipv6-addr':
    case 'url':
    case 'email-address':
    case 'email-subject':
    case 'mutex':
    case 'file':
    case 'file-name':
    case 'file-path':
    case 'file-md5':
    case 'file-sha1':
    case 'file-sha256':
    case 'pdb-path':
    case 'registry-key':
    case 'registry-key-value':
    case 'windows-service-name':
    case 'windows-service-display-name':
    case 'windows-scheduled-task':
    case 'x509-certificate-issuer':
    case 'x509-certificate-serial-number':
      return <HexagonOutline style={style} fontSize={fontSize} role="img" />;
    case 'stix_relation':
    case 'stix-relation':
    case 'targets':
    case 'uses':
    case 'related-to':
    case 'mitigates':
    case 'impersonates':
    case 'indicates':
    case 'comes-after':
    case 'attributed-to':
    case 'variant-of':
    case 'localization':
    case 'gathering':
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
