/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Field } from 'formik';
import * as R from 'ramda';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import AddIcon from '@material-ui/icons/Add';
import Delete from '@material-ui/icons/Delete';
import InputAdornment from '@material-ui/core/InputAdornment';
import Typography from '@material-ui/core/Typography';
import { Information } from 'mdi-material-ui';
import Tooltip from '@material-ui/core/Tooltip';
import graphql from 'babel-plugin-relay/macro';
import TextField from '@material-ui/core/TextField';
import { Edit } from '@material-ui/icons';
import Button from '@material-ui/core/Button';
import IconButton from '@material-ui/core/IconButton';
import { Dialog, DialogContent, DialogActions, Select, MenuItem, Input } from '@material-ui/core';
import NewTextField from '../../../../components/TextField';
import inject18n from '../../../../components/i18n';
import { fetchQuery } from '../../../../relay/environment';
import SelectField from '../../../../components/SelectField';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  scrollBg: {
    background: theme.palette.header.background,
    width: '100%',
    color: 'white',
    padding: '10px 5px 10px 15px',
    borderRadius: '5px',
    lineHeight: '20px',
  },
  scrollDiv: {
    width: '100%',
    background: theme.palette.header.background,
    height: '85px',
    overflow: 'hidden',
    overflowY: 'scroll',
  },
  scrollObj: {
    color: theme.palette.header.text,
    fontFamily: 'sans-serif',
    padding: '0px',
    textAlign: 'left',
  },
  inputTextField: {
    color: 'white',
  },
  textField: {
    background: theme.palette.header.background,
  },
  dialogAction: {
    margin: '15px 20px 15px 0',
  },
});

const installedSoftwareAssetQuery = graphql`
  query InstalledAssetSoftwareQuery(
    $filters: [SoftwareAssetFiltering]
  ){
    softwareAssetList(
      filters: $filters
    ) {
      edges {
        node {
          id
          name
          asset_type
          version
        }
      }
    }
  }
`;

class HyperLinkField extends Component {
  constructor(props) {
    super(props);
    this.state = {
      open: false,
      value: [],
      error: false,
      data: [...this.props.data],
      softwareList: [],
    };
  }

  componentDidMount() {

    {
      this.props.type === 'software'
        && (
          fetchQuery(installedSoftwareAssetQuery, {
            filters: this.props.assetType ? [{ key: 'asset_type', values: [this.props.assetType] }] : [],
          })
            .toPromise()
            .then((data) => {
              const installedSoftwareEntities = R.pipe(
                R.pathOr([], ['softwareAssetList', 'edges']),
                R.map((n) => {
                  const softwareName = R.concat(n.node.name, " ");
                  const softwareNameWithVersion = R.concat(softwareName, n.node.version ? n.node.version : "");
                  return {
                    id: n.node.id,
                    name: n.node.name,
                    type: n.node.vendor_name,
                    version: n.node.version,
                    softwareNameWithVersion
                  }
                }),
              )(data);
              this.setState({
                softwareList: {
                  ...this.state.entities,
                  installedSoftwareEntities
                },
              });
            })
        )
    }
  }

  handleAddAddress() {
    if (this.state.value === '' || this.state.value === null) {
      return;
    }
    if (this.state.data.every((value) => value !== this.state.value)) {
      this.state.data.push(this.state.value);
    }
    this.setState({ value: '' });
  }

  handleSubmit() {
    this.setState({ open: false, value: '' }, () => (
      this.props.setFieldValue(this.props.name, this.state.data)
    ));
  }

  handleDeleteAddress(key) {
    this.setState({ ipAddress: this.state.data.filter((value, i) => i !== key) });
  }

  render() {
    const {
      t, fldt, classes, name, title, helperText, containerstyle, style
    } = this.props;
    const {
      error, data,
    } = this.state;
    const softwareList = R.pathOr(
        [],
        ['installedSoftwareEntities'],
        this.state.softwareList,
      );
  
      const sortedSoftwareList = softwareList.sort(function(a, b) {
        return a.softwareNameWithVersion.localeCompare(b.softwareNameWithVersion, undefined, {
          numeric: true,
          sensitivity: 'base'
        });
      });
    return (
      <>
        <div style={{ display: 'flex', alignItems: 'center' }}>
          <Typography>
            {title && t(title)}
          </Typography>
          <div style={{ float: 'left', margin: '5px 0 0 5px' }}>
            <Tooltip title={t('Baseline Configuration Name')} >
              <Information fontSize="inherit" color="disabled" />
            </Tooltip>
          </div>
          <IconButton size='small' onClick={() => this.setState({ open: true })}>
            <Edit fontSize='small' />
          </IconButton>
        </div>
        <Field
          component={NewTextField}
          name={name}
          fullWidth={true}
          disabled={true}
          multiline={true}
          rows="3"
          value={data}
          className={classes.textField}
          InputProps={{
            className: classes.inputTextField,
          }}
          variant='outlined'
        />
        <Dialog
          open={this.state.open}
          fullWidth={true}
          maxWidth='sm'
        >
          <DialogContent>
            {t(`Edit ${title}(s)`)}
          </DialogContent>
          <DialogContent style={{ overflow: 'hidden' }}>
            <Field
                component={SelectField}
                name={name}
                // label={label}
                multiple={true}
                fullWidth={true}
                containerstyle={containerstyle}
                // variant={variant}
                // disabled={disabled || false}
                // size={size}
                style={style}
                helperText={helperText}
                >
                {sortedSoftwareList.map((device) => (
                    <MenuItem key={device.id} value={device.id}>
                        {device.name && t(device.name)}
                    </MenuItem>
                ))}
            </Field>
            <IconButton
                aria-label="toggle password visibility"
                edge="end"
                onClick={this.handleAddAddress.bind(this)}
                style={{ marginTop: '20px' }}
            >
                <AddIcon />
            </IconButton>
          </DialogContent>
          <DialogContent>
            <div className={classes.scrollBg}>
              <div className={classes.scrollDiv}>
                <div className={classes.scrollObj}>
                  {data.map((item, key) => (
                    <div key={key} style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <Typography>
                        {item}
                      </Typography>
                      <IconButton onClick={this.handleDeleteAddress.bind(this, key)}>
                        <Delete />
                      </IconButton>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </DialogContent>
          <DialogActions className={classes.dialogAction}>
            <Button
              variant='outlined'
              onClick={() => this.setState({ open: false, value: '' })}
            >
              {t('Cancel')}
            </Button>
            <Button
              disabled={!data.length}
              variant='contained'
              onClick={this.handleSubmit.bind(this)}
              color="primary"
            >
              {t('Submit')}
            </Button>
          </DialogActions>
        </Dialog>
      </>
    );
  }
}

HyperLinkField.propTypes = {
  name: PropTypes.string,
  device: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fldt: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(HyperLinkField);
