import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Field } from 'formik';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import inject18n from '../../../../components/i18n';
import MarkDownField from '../../../../components/MarkDownField';
import ExternalReferencesField from './ExternalReferencesField';

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
    this.props.submitForm();
  }

  render() {
    const {
      disabled,
      t,
      id,
      setFieldValue,
      values,
      handleClose,
      open,
      noStoreUpdate,
    } = this.props;
    return (
      <div>
        {typeof handleClose !== 'function' && (
          <Button
            variant="contained"
            color="primary"
            onClick={this.handleOpen.bind(this)}
            style={{ marginTop: 20, float: 'right' }}
          >
            {t('Update')}
          </Button>
        )}
        <Dialog
          PaperProps={{ elevation: 1 }}
          open={typeof handleClose !== 'function' ? this.state.open : open}
          onClose={handleClose || this.handleClose.bind(this)}
          fullWidth={true}
        >
          <DialogTitle>{t('Reference modification')}</DialogTitle>
          <DialogContent>
            <ExternalReferencesField
              name="references"
              style={{ marginTop: 20, width: '100%' }}
              setFieldValue={setFieldValue}
              values={values.references}
              id={id}
              noStoreUpdate={noStoreUpdate}
            />
            <Field
              component={MarkDownField}
              name="message"
              label={t('Message')}
              fullWidth={true}
              multiline={true}
              rows="2"
              style={{ marginTop: 20 }}
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
  id: PropTypes.string,
  t: PropTypes.func,
  submitForm: PropTypes.func,
  disabled: PropTypes.bool,
  validateForm: PropTypes.func,
  setFieldValue: PropTypes.func,
  externalReferences: PropTypes.array,
  open: PropTypes.bool,
  handleClose: PropTypes.func,
  noStoreUpdate: PropTypes.bool,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(CommitMessage);
