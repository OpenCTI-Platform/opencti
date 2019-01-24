import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  Person,
  AccountBalance,
  Domain,
  Public,
  Help,
  BugReport,
  Description,
} from '@material-ui/icons';
import {
  Biohazard,
  Diamond,
  ChessKnight,
  LockPattern,
  Application,
  Fire,
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
    case 'sector':
      return <Domain style={style} fontSize={fontSize}/>;
    case 'threat-actor':
      return <Public style={style} fontSize={fontSize}/>;
    case 'intrusion-set':
      return <Diamond style={style} fontSize={fontSize}/>;
    case 'campaign':
      return <ChessKnight style={style} fontSize={fontSize}/>;
    case 'incident':
      return <Fire style={style} fontSize={fontSize}/>;
    case 'user':
      return <Person style={style} fontSize={fontSize}/>;
    case 'organization':
      return <AccountBalance style={style} fontSize={fontSize}/>;
    case 'attack-pattern':
      return <LockPattern style={style} fontSize={fontSize}/>;
    case 'malware':
      return <Biohazard style={style} fontSize={fontSize}/>;
    case 'tool':
      return <Application style={style} fontSize={fontSize}/>;
    case 'vulnerability':
      return <BugReport style={style} fontSize={fontSize}/>;
    case 'report':
      return <Description style={style} fontSize={fontSize}/>;
    default:
      return <Help style={style} fontSize={fontSize}/>;
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
