// /* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Field } from 'formik';
import {
  compose,
  map,
  union,
  pipe,
  pathOr,
} from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import InsertLinkIcon from '@material-ui/icons/InsertLink';
import LinkOffIcon from '@material-ui/icons/LinkOff';
import Typography from '@material-ui/core/Typography';
import { Information } from 'mdi-material-ui';
import Tooltip from '@material-ui/core/Tooltip';
import TextField from '@material-ui/core/TextField';
import Button from '@material-ui/core/Button';
import IconButton from '@material-ui/core/IconButton';
import { Dialog, DialogContent, DialogActions } from '@material-ui/core';
import { fetchQuery } from '../../../../relay/environment';
import NewTextField from '../../../../components/TextField';
import AutocompleteField from '../../../../components/AutocompleteField';
import inject18n from '../../../../components/i18n';

const LocationFieldSearchQuery = graphql`
  query LocationFieldSearchQuery(
    $orderedBy: OscalLocationOrdering
    $orderMode: OrderingMode
  ){
    oscalLocations(
      orderedBy: $orderedBy
      orderMode: $orderMode
    ) {
      edges {
        node {
          id
          created
          name
          location_type
        }
      }
    }
  }
`;

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
  descriptionBox: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
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

class LocationField extends Component {
  constructor(props) {
    super(props);
    this.state = {
      open: false,
      error: false,
      ipAddress: [...this.props.addressValues],
      stateLabels: [],
    };
  }

  searchData = () => {
    fetchQuery(LocationFieldSearchQuery, {
      orderedBy: 'name',
      orderMode: 'asc',
    })
      .toPromise()
      .then((data) => {
        const transformLabels = pipe(
          pathOr([], ['oscalLocations', 'edges']),
          map((n) => ({
            label: n.node.name,
            value: n.node.id,
          })),
        )(data);
        this.setState({ stateLabels: union(this.state.stateLabels, transformLabels) });
      });
  };

  handleSubmit() {
    this.setState({ open: false }, () => (
      this.props.setFieldValue(this.props.name,
        this.state.ipAddress.map((location) => location.value))
    ));
  }

  handleOpenCreate() {
    if (this.props.addressValues.length === 0) {
      return;
    }
    if (this.state.ipAddress.every((value) => value.label !== this.props.addressValues.label)) {
      this.setState({ ipAddress: [...this.state.ipAddress, this.props.addressValues] });
    }
  }

  handleDeleteAddress(key) {
    this.setState({ ipAddress: this.state.ipAddress.filter((i) => i !== key) },
      () => this.props.setFieldValue(this.props.name, this.state.ipAddress));
  }

  render() {
    const {
      t, classes, name, title,
    } = this.props;
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
            <InsertLinkIcon />
          </IconButton>
        </div>
        <div className={classes.scrollBg}>
          <div className={classes.scrollDiv}>
            <div className={classes.scrollObj}>
              {this.state.ipAddress && this.state.ipAddress.map((address, key) => (
                <div key={key} className={classes.descriptionBox}>
                  <Typography>
                    {address && t(address.label)}
                  </Typography>
                  <IconButton size='small' onClick={this.handleDeleteAddress.bind(this, key)}>
                    <LinkOffIcon />
                  </IconButton>
                </div>
              ))}
            </div>
          </div>
        </div>
        <Dialog
          open={this.state.open}
          onClose={() => this.setState({ open: false })}
          fullWidth={true}
          maxWidth='sm'
        >
          <DialogContent>
            {title && t(title)}
          </DialogContent>
          <DialogContent style={{ overflow: 'hidden' }}>
            <Field
              component={AutocompleteField}
              name={name}
              disableClearable={true}
              clearOnEscape={true}
              textfieldprops={{
                label: t('Locations'),
                onFocus: this.searchData.bind(this),
              }}
              noOptionsText={t('No available options')}
              options={this.state.stateLabels}
              insertIcon={true}
              renderInput={(params) => (
                <TextField
                  {...params}
                  label="clearOnEscape"
                  variant="standard"
                />
              )}
              onInputChange={this.searchData.bind(this)}
              openCreate={this.handleOpenCreate.bind(this)}
              classes={{ clearIndicator: classes.autoCompleteIndicator }}
            />
          </DialogContent>
          <DialogContent>
            <div className={classes.scrollBg}>
              <div className={classes.scrollDiv}>
                <div className={classes.scrollObj}>
                  {this.state.ipAddress.map((address, key) => (
                    <div key={key} className={classes.descriptionBox}>
                      <Typography>
                        {address && t(address.label)}
                      </Typography>
                      <IconButton size='small' onClick={this.handleDeleteAddress.bind(this, key)}>
                        <LinkOffIcon />
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
              onClick={() => this.setState({ open: false })}
            >
              {t('Cancel')}
            </Button>
            <Button
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

LocationField.propTypes = {
  name: PropTypes.string,
  device: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fldt: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(LocationField);
