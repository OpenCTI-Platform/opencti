/* eslint-disable no-nested-ternary */
// TODO Remove no-nested-ternary
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles/index';
import Select from '@material-ui/core/Select';
import Button from '@material-ui/core/Button';
import IconButton from '@material-ui/core/IconButton';
import FormControl from '@material-ui/core/FormControl';
import InputLabel from '@material-ui/core/InputLabel';
import MenuItem from '@material-ui/core/MenuItem';
import Dialog from '@material-ui/core/Dialog';
import DialogContent from '@material-ui/core/DialogContent';
import DialogTitle from '@material-ui/core/DialogTitle';
import DialogActions from '@material-ui/core/DialogActions';
import { FileUploadOutline } from 'mdi-material-ui';
import { CloudUpload } from '@material-ui/icons';
import inject18n from '../../../components/i18n';
import { commitMutation, MESSAGING$ } from '../../../relay/environment';

const styles = theme => ({
  button: {
    marginLeft: theme.spacing(2),
  },
  rightIcon: {
    marginLeft: theme.spacing(1),
  },
  dialogActions: {
    padding: '0 17px 20px 0',
  },
});

const stixDomainEntitiesImportDataMutation = graphql`
  mutation StixDomainEntitiesImportDataMutation(
    $type: String!
    $file: Upload!
  ) {
    importData(type: $type, file: $file)
  }
`;

class StixDomainEntitiesImportData extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false, type: 'import.stix2.bundle' };
    this.uploadRef = React.createRef();
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({ open: false });
  }

  handleChangeType(event) {
    this.setState({ type: event.target.value });
  }

  handleOpenUpload() {
    this.uploadRef.click();
  }

  handleUpload(event) {
    if (event.target.files.length === 0) {
      return false;
    }
    const file = event.target.files[0];
    const reader = new FileReader();
    reader.readAsDataURL(file);

    reader.onload = () => {
      const fileInfo = {
        name: file.name,
        type: file.type,
        size: file.size,
        base64: reader.result.replace(/^data:(.*;base64,)?/, ''),
      };
      commitMutation({
        mutation: stixDomainEntitiesImportDataMutation,
        variables: { type: this.state.type, file: fileInfo },
        onCompleted: () => {
          MESSAGING$.notifySuccess(
            'The importation of the file has been started',
          );
          this.handleClose();
        },
      });
    };
    return true;
  }

  onReset() {
    this.handleClose();
  }

  render() {
    const { classes, t } = this.props;

    return (
      <div style={{ display: 'inline-block' }}>
        <IconButton
          onClick={this.handleOpen.bind(this)}
          aria-haspopup="true"
          color="primary"
        >
          <FileUploadOutline />
        </IconButton>
        <Dialog
          open={this.state.open}
          onClose={this.handleClose.bind(this)}
          fullWidth={true}
        >
          <DialogTitle>{t('Import data')}</DialogTitle>
          <DialogContent>
            <FormControl fullWidth={true} margin="none">
              <InputLabel htmlFor="type">{t('Import type')}</InputLabel>
              <Select
                style={{ width: '100%', marginBottom: 20 }}
                name="type"
                label={t('Import type')}
                fullWidth={true}
                inputProps={{
                  name: 'type',
                  id: 'type',
                }}
                onChange={this.handleChangeType.bind(this)}
                value={this.state.type}
              >
                <MenuItem value="import.stix2.bundle">
                  {t('STIX2 bundle')}
                </MenuItem>
              </Select>
            </FormControl>
            <input
              ref={ref => (this.uploadRef = ref)}
              type="file"
              style={{ display: 'none' }}
              onChange={this.handleUpload.bind(this)}
            />
          </DialogContent>
          <DialogActions classes={{ root: classes.dialogActions }}>
            <Button
              variant="contained"
              onClick={this.handleClose.bind(this)}
              classes={{ root: classes.button }}
            >
              {t('Cancel')}
            </Button>
            <Button
              variant="contained"
              color="primary"
              classes={{ root: classes.button }}
              onClick={this.handleOpenUpload.bind(this)}
            >
              Upload
              <CloudUpload className={classes.rightIcon} />
            </Button>
          </DialogActions>
        </Dialog>
      </div>
    );
  }
}

StixDomainEntitiesImportData.propTypes = {
  classes: PropTypes.object,
  reportClass: PropTypes.string,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixDomainEntitiesImportData);
