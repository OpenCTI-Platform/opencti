import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { withStyles } from '@material-ui/core/styles';
import Snackbar from '@material-ui/core/Snackbar';
import SnackbarContent from '@material-ui/core/SnackbarContent';
import IconButton from '@material-ui/core/IconButton';
import CheckCircle from '@material-ui/icons/CheckCircle';
import Close from '@material-ui/icons/Close';

const styles = theme => ({
  message: {
    display: 'flex',
    alignItems: 'center',
  },
  messageIcon: {
    marginRight: theme.spacing.unit,
  },
});

class Message extends Component {
  render() {
    const { classes, message } = this.props;
    return (
      <Snackbar
        anchorOrigin={{ vertical: 'top', horizontal: 'right' }}
        open={this.props.open}
        onClose={this.props.handleClose.bind(this)}
        autoHideDuration={1500}
      >
        <SnackbarContent
          message={
            <span className={classes.message}>
              <CheckCircle className={classes.messageIcon}/>
              {message}
            </span>
          }
          action={[
            <IconButton
              key='close'
              aria-label='Close'
              color='inherit'
              onClick={this.props.handleClose.bind(this)}
            >
              <Close/>
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
  handleClose: PropTypes.func,
  message: PropTypes.string,
};

export default withStyles(styles)(Message);
