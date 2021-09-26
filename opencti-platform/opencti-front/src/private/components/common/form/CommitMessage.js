import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Field } from 'formik';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Dialog from '@material-ui/core/Dialog';
import DialogContent from '@material-ui/core/DialogContent';
import DialogTitle from '@material-ui/core/DialogTitle';
import DialogActions from '@material-ui/core/DialogActions';
import Button from '@material-ui/core/Button';
import inject18n from '../../../../components/i18n';
import MarkDownField from '../../../../components/MarkDownField';

const styles = () => ({
  container: {
    padding: '10px 20px 20px 20px',
  },
});

class CommitMessage extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({ open: false });
  }

  handleSubmit() {
    this.setState({ open: false }, () => this.props.submitForm());
  }

  render() {
    const { disabled, t } = this.props;
    return (
      <div>
        <Button
          variant="contained"
          color="primary"
          onClick={this.handleOpen.bind(this)}
          style={{ marginTop: 20, float: 'right' }}
        >
          {t('Update')}
        </Button>
        <Dialog
          open={this.state.open}
          onClose={this.handleClose.bind(this)}
          fullWidth={true}
        >
          <DialogTitle>{t('Reference modification')}</DialogTitle>
          <DialogContent>
            <Field
              component={MarkDownField}
              name="message"
              label={t('Message')}
              fullWidth={true}
              multiline={true}
              rows="2"
            />
          </DialogContent>
          <DialogActions>
            <Button
              color="primary"
              onClick={this.handleSubmit.bind(this)}
              disabled={disabled}
            >
              {t('Validate')}
            </Button>
          </DialogActions>
        </Dialog>
      </div>
    );
  }
}

CommitMessage.propTypes = {
  t: PropTypes.func,
  submitForm: PropTypes.func,
  disabled: PropTypes.bool,
  validateForm: PropTypes.func,
  externalReferences: PropTypes.array,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(CommitMessage);
