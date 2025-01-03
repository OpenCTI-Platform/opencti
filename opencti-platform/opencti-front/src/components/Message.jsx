import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import Snackbar from '@mui/material/Snackbar';
import Alert from '@mui/material/Alert';
import { head } from 'ramda';
import Button from '@mui/material/Button';
import { Form, Formik } from 'formik';
import { MESSAGING$ } from '../relay/environment';
import inject18n from './i18n';
import RequestAccessDialog from './RequestAccessDialog';

class Message extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false, error: false, text: '', type: '', fullError: null, dialogOpen: false };
  }

  componentDidMount() {
    this.subscription = MESSAGING$.messages.subscribe({
      next: (messages) => {
        const firstMessage = head(messages);
        if (firstMessage) {
          const text = firstMessage.text instanceof String
            ? this.props.t(firstMessage.text)
            : firstMessage.text;
          const error = firstMessage.type === 'error';
          this.setState({ open: true, error, text, fullError: firstMessage.fullError || null });
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

  handleDialogClose = () => {
    this.setState({ dialogOpen: false });
  };

  handleDialogOpen = () => {
    this.setState({ dialogOpen: true, open: false });
  };

  render() {
    const entityIds = this.state.fullError?.extensions?.data?.entityIds || [];
    return (
      <>
        <Snackbar
          anchorOrigin={{ vertical: 'top', horizontal: 'center' }}
          open={this.state.open}
          onClose={this.handleCloseMessage.bind(this)}
          autoHideDuration={this.state.error ? 8000 : 4000}
          sx={{ display: 'flex', alignItems: 'center' }}
        >
          {/* eslint-disable-next-line no-nested-ternary */}
          {this.state.text === 'Restricted entity already exists, user can request access' ? (
            <Alert
              severity="error"
              style={{ display: 'flex', alignItems: 'center' }}
            >
              <div style={{ display: 'flex', alignItems: 'center' }}>
                {this.state.text}
                {this.state.fullError && (
                <Formik>
                  <Form>
                    <Button
                      variant="outlined"
                      size="small"
                      sx={{ marginLeft: 2 }}
                      onClick={this.handleDialogOpen}
                    >
                      Request Access
                    </Button>

                  </Form>
                </Formik>
                )}
              </div>
            </Alert>
          ) : this.state.error ? (
            <Alert severity="error" onClose={this.handleCloseMessage.bind(this)}>
              {this.state.text}
            </Alert>
          ) : (
            <Alert
              severity="success"
              onClose={this.handleCloseMessage.bind(this)}
            >
              {this.state.text}
            </Alert>
          )}
        </Snackbar>
        <RequestAccessDialog
          open={this.state.dialogOpen}
          onClose={this.handleDialogClose}
          entitiesIds={entityIds}
        />
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
