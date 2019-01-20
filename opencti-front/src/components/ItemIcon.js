import React, { Component } from 'react';
import PropTypes from 'prop-types';
import {
  Person,
  AccountBalance,
  Domain,
  Public,
  Help,
  BugReport,
} from '@material-ui/icons';
import {
  Biohazard,
  Diamond,
  ChessKnight,
  LockPattern,
  Application,
  Fire,
} from 'mdi-material-ui';

const iconSelector = (type, variant, color) => {
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
      return <Domain style={style}/>;
    case 'threat-actor':
      return <Public style={style}/>;
    case 'intrusion-set':
      return <Diamond style={style}/>;
    case 'campaign':
      return <ChessKnight style={style}/>;
    case 'incident':
      return <Fire style={style}/>;
    case 'user':
      return <Person style={style}/>;
    case 'organization':
      return <AccountBalance style={style}/>;
    case 'attack-pattern':
      return <LockPattern style={style}/>;
    case 'malware':
      return <Biohazard style={style}/>;
    case 'tool':
      return <Application style={style}/>;
    case 'vulnerability':
      return <BugReport style={style}/>;
    default:
      return <Help style={style}/>;
  }
};

class ItemIcon extends Component {
  render() {
    const { type, variant, color } = this.props;
    return iconSelector(type, variant, color);
  }
}

ItemIcon.propTypes = {
  type: PropTypes.string,
  variant: PropTypes.string,
  color: PropTypes.string,
};

export default ItemIcon;
