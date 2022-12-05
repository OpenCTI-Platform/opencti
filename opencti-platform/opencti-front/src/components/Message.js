import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import Snackbar from '@material-ui/core/Snackbar';
import Alert from '@material-ui/lab/Alert';
import { head } from 'ramda';
import { MESSAGING$ } from '../relay/environment';
import inject18n from './i18n';
import ErrorBox from '../private/components/common/form/ErrorBox';

class Message extends Component {
  constructor(props) {
    super(props);
    this.state = {
      open: false,
      error: {},
      pathname: '',
      openMessage: false,
      message: '',
    };
  }

  componentDidMount() {
    this.subscription = MESSAGING$.messages.subscribe({
      next: (messages) => {
        const headMessage = head(messages);
        if (headMessage.type === 'message') {
          this.setState({ openMessage: true, message: headMessage.text });
        } else {
          this.setState({ open: true, error: messages, pathname: headMessage.pathanme });
        }
      },
    });
  }

  // eslint-disable-next-line
  componentWillUnmount() {
    this.subscription.unsubscribe();
  }

  handleClearError() {
    this.setState({ error: {} });
  }

  handleCloseMessage(event, reason) {
    if (reason === 'clickaway') return;
    this.setState({ openMessage: false });
  }

  render() {
    return (
      <>
        {
          this.state.open && (
            <ErrorBox
              error={this.state.error}
              pathname={this.state.pathname}
              handleClearError={this.handleClearError.bind(this)}
            />
          )
        }
        {
          this.state.openMessage && (
            <Snackbar
              anchorOrigin={{ vertical: 'top', horizontal: 'center' }}
              open={this.state.openMessage}
              onClose={this.handleCloseMessage.bind(this)}
            >
              <Alert
                severity="success"
                onClose={this.handleCloseMessage.bind(this)}
              >
                {this.state.message}
              </Alert>
            </Snackbar>
          )
        }
      </>
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
