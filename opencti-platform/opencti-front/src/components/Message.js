import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import Snackbar from '@material-ui/core/Snackbar';
import IconButton from '@material-ui/core/IconButton';
import Alert from '@material-ui/lab/Alert';
import Close from '@material-ui/icons/Close';
import { head } from 'ramda';
import { MESSAGING$ } from '../relay/environment';
import inject18n from './i18n';

class Message extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false, error: false, text: '' };
  }

  componentDidMount() {
    this.subscription = MESSAGING$.messages.subscribe({
      next: (messages) => {
        const firstMessage = head(messages);
        if (firstMessage) {
          const text = this.props.t(firstMessage.text);
          const error = firstMessage.type === 'error';
          this.setState({ open: true, error, text });
        }
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
    return (
      <Snackbar
        anchorOrigin={{ vertical: 'top', horizontal: 'right' }}
        open={this.state.open}
        onClose={this.handleCloseMessage.bind(this)}
        autoHideDuration={3000}
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
      >
        {this.state.error ? (
          <Alert severity="error" color="error">
            {this.state.text}
          </Alert>
        ) : (
          <Alert severity="success" color="success">
            {this.state.text}
          </Alert>
        )}
      </Snackbar>
    );
  }
}

Message.propTypes = {
  open: PropTypes.bool,
  t: PropTypes.func,
  handleClose: PropTypes.func,
  message: PropTypes.string,
};

export default inject18n(Message);
