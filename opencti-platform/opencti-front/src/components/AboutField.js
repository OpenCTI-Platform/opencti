import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose,
} from 'ramda';
import {
  Info,
} from '@material-ui/icons';
import Dialog from '@material-ui/core/Dialog';
import DialogContent from '@material-ui/core/DialogContent';
import DialogTitle from '@material-ui/core/DialogTitle';
import DialogActions from '@material-ui/core/DialogActions';
import Button from '@material-ui/core/Button';
import { withStyles } from '@material-ui/core/styles';
import Tooltip from '@material-ui/core/Tooltip';
import IconButton from '@material-ui/core/IconButton';
import inject18n from './i18n';

const styles = (theme) => ({
  dialogRoot: {
    overflowY: 'scroll',
    overflowX: 'hidden',
  },
  dialogContent: {
    overflowY: 'hidden',
  },
  popoverDialog: {
    fontSize: '18px',
    lineHeight: '24px',
    color: theme.palette.header.text,
  },
  dialogActions: {
    justifyContent: 'flex-start',
    padding: '0px 0 20px 22px',
  },
});

class AboutField extends Component {
  constructor(props) {
    super(props);
    this.state = {
      htmlFormatData: '',
      open: false,
    };
  }

  handleCloseAbout() {
    this.setState({ open: false });
  }

  handleAboutButton() {
    const { location } = this.props;
    if (location.pathname === '/dashboard') {
      fetch('/static/docs/pages/dashboard/index.md.html')
        .then((response) => response.text())
        .then((data) => {
          this.setState({ htmlFormatData: data, open: true });
          const script = document.createElement('script');
          script.src = '/static/docs/_markdeep/markdeep.min.js';
          script.async = true;
          document.querySelector('.staticData').appendChild(script);
        });
    }
  }

  render() {
    const {
      t, classes, location, history, keyword, theme,
    } = this.props;
    return (
      <>
        <Tooltip title={t('About')}>
          <IconButton
            classes={{ root: classes.button }}
            onClick={this.handleAboutButton.bind(this)}
            aria-haspopup='true'
          >
            <Info fontSize="default" />
          </IconButton>
        </Tooltip>
        <Dialog
          maxWidth='sm'
          fullWidth={true}
          open={this.state.open}
          classes={{ paper: classes.dialogRoot }}
        >
          <DialogContent classes={{ root: classes.dialogContent }}>
            <div
              className='staticData'
              dangerouslySetInnerHTML={{ __html: this.state.htmlFormatData }}
            />
          </DialogContent>
          <DialogActions className={classes.dialogActions}>
            <Button
              onClick={this.handleCloseAbout.bind(this)}
              disabled={this.state.deleting}
              classes={{ root: classes.buttonPopover }}
              variant="outlined"
              size="small"
            >
              {t('Cancel')}
            </Button>
          </DialogActions>
        </Dialog>
      </>
    );
  }
}

AboutField.propTypes = {
  keyword: PropTypes.string,
  theme: PropTypes.object,
  classes: PropTypes.object,
  location: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(AboutField);
