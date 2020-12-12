import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Button from '@material-ui/core/Button';
import Drawer from '@material-ui/core/Drawer';
import { Clear } from '@material-ui/icons';
import inject18n from '../../../components/i18n';

const styles = (theme) => ({
  bottomNav: {
    zIndex: 1000,
    padding: '10px 274px 10px 84px',
    backgroundColor: theme.palette.navBottom.background,
    display: 'flex',
  },
  icon: {
    marginRight: theme.spacing(1),
    fontSize: 20,
  },
});

class ExploreBottomBar extends Component {
  render() {
    const {
      t, classes, handleClear, entityId,
    } = this.props;
    return (
      <Drawer
        anchor="bottom"
        variant="permanent"
        classes={{ paper: classes.bottomNav }}
      >
        <div
          style={{
            position: 'absolute',
            top: 25,
            right: 285,
            color: '#ffffff',
          }}
        >
          <Button
            variant="contained"
            size="small"
            className={classes.button}
            onClick={handleClear.bind(this)}
            disabled={!entityId}
          >
            <Clear className={classes.icon} />
            {t('Close')}
          </Button>
        </div>
      </Drawer>
    );
  }
}

ExploreBottomBar.propTypes = {
  entityId: PropTypes.string,
  handleClear: PropTypes.func,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(ExploreBottomBar);
