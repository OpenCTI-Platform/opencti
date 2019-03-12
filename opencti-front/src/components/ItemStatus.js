import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withStyles } from '@material-ui/core/styles';

const styles = () => ({
  item: {
    fontSize: 12,
    padding: '5px 8px 5px 8px',
    borderRadius: 5,
  },
});

const inlineStyles = {
  white: {
    backgroundColor: '#ffffff',
    color: '#2b2b2b',
  },
  green: {
    backgroundColor: '#2e7d32',
  },
  blue: {
    backgroundColor: '#283593',
  },
  grey: {
    backgroundColor: '#424242',
  },
  orange: {
    backgroundColor: '#d84315',
  },
};

class ItemMarking extends Component {
  render() {
    const { classes, label, status } = this.props;

    switch (status) {
      case 0:
        return <span className={classes.item} style={inlineStyles.orange}>{label}</span>;
      case 1:
        return <span className={classes.item} style={inlineStyles.blue}>{label}</span>;
      case 2:
        return <span className={classes.item} style={inlineStyles.green}>{label}</span>;
      case 3:
        return <span className={classes.item} style={inlineStyles.grey}>{label}</span>;
      default:
        return <span className={classes.item} style={inlineStyles.blue}>{label}</span>;
    }
  }
}

ItemMarking.propTypes = {
  classes: PropTypes.object.isRequired,
  status: PropTypes.number,
  label: PropTypes.string,
};

export default withStyles(styles)(ItemMarking);
