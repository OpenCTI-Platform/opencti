import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withStyles } from '@material-ui/core/styles';
import Snackbar from '@material-ui/core/Snackbar';
import SnackbarContent from '@material-ui/core/SnackbarContent';
import IconButton from '@material-ui/core/IconButton';
import CheckCircle from '@material-ui/icons/CheckCircle';
import ErrorOutline from '@material-ui/icons/ErrorOutline';
import Close from '@material-ui/icons/Close';
import { compose, head } from 'ramda';
import { MESSAGING$ } from '../relay/environment';
import inject18n from './i18n';

const styles = theme => ({
  message: {
    display: 'flex',
    alignItems: 'center',
  },
  messageIcon: {
    marginRight: theme.spacing.unit,
  },
  error: {
    backgroundColor: '#f44336',
    color: '#ffffff',
  },
  normal: {
    backgroundColor: '#e0e0e0',
  },
});

class Message extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false, error: false, text: '' };
  }

  componentDidMount() {
    this.subscription = MESSAGING$.messages.subscribe({
      next: (messages) => {
        const firstMessage = head(messages);
        const text = this.props.t(firstMessage.text);
        const error = firstMessage.type === 'error';
        this.setState({ open: true, error, text });
      },
    });
  }

  // eslint-disable-next-line
  componentWillUnmount() {
    this.subscription.unsubscribe();
  }

  handleCloseMessage(event, reason) {
    if (reason === 'clickaway') return;
    this.setState({ open: false });
  }

  render() {
    const { classes } = this.props;
    return (
      <Snackbar
        anchorOrigin={{ vertical: 'top', horizontal: 'right' }}
        open={this.state.open}
        onClose={this.handleCloseMessage.bind(this)}
        autoHideDuration={3000}
      >
        <SnackbarContent
          className={this.state.error ? classes.error : classes.normal}
          message={
            <span className={classes.message}>
              {this.state.error ? (
                <ErrorOutline className={classes.messageIcon} />
              ) : (
                <CheckCircle className={classes.messageIcon} />
              )}
              {this.state.text}
            </span>
          }
          action={[
            <IconButton
              key="close"
              aria-label="Close"
              color="inherit"
              onClick={this.handleCloseMessage.bind(this)}
            >
              <Close />
            </IconButton>,
          ]}
        />
      </Snackbar>
    );
  }
}

Message.propTypes = {
  classes: PropTypes.object.isRequired,
  open: PropTypes.bool,
  t: PropTypes.func,
  handleClose: PropTypes.func,
  message: PropTypes.string,
};

export default compose(
  inject18n,
  withStyles(styles),
)(Message);
