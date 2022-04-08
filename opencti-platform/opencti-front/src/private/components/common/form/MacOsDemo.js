import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Formik, Form, Field } from 'formik';
import { compose, propOr, map } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import AddIcon from '@material-ui/icons/Add';
import Delete from '@material-ui/icons/Delete';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import TextField from '@material-ui/core/TextField';
import Button from '@material-ui/core/Button';
import IconButton from '@material-ui/core/IconButton';
import { Label, Information } from 'mdi-material-ui';
import { Dialog, DialogContent, DialogActions } from '@material-ui/core';
import Autocomplete from '@material-ui/lab/Autocomplete';
import inject18n from '../../../../components/i18n';
import ItemAuthor from '../../../../components/ItemAuthor';
import ItemMarking from '../../../../components/ItemMarking';
import AutocompleteField from '../../../../components/AutocompleteField';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';

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
});

class MacOsComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      open: false,
      value: '',
      ipAddress: [],
    };
  }

  handleAddIP() {
    if (this.state.value === '' || this.state.value === null) {
      return;
    }
    if (this.state.ipAddress.every((value) => value !== this.state.value)) {
      this.state.ipAddress.push(this.state.value);
    }
    this.setState({ value: '' });
  }

  handleDeleteIP(key) {
    this.setState({ ipAddress: this.state.ipAddress.filter((value, i) => i !== key) });
  }

  render() {
    const {
      t, fldt, classes, device,
    } = this.props;
    const top100Films = ['html', 'css', 'javascript', 'node'];
    return (
      <div style={{ height: '100%' }} className="break">
        <Typography variant="h4" gutterBottom={true}>
          {t('Information')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <div style={{ display: 'flex', alignItems: 'center' }}>
            <Typography>
              Mac Address
            </Typography>
            <IconButton onClick={() => this.setState({ open: true })}>
              <AddIcon />
            </IconButton>
          </div>
          <div className={classes.scrollBg}>
            <div className={classes.scrollDiv}>
              <div className={classes.scrollObj}>
                {this.state.ipAddress.join(',')}
              </div>
            </div>
          </div>
          <Dialog
            open={this.state.open}
            onClose={() => this.setState({ open: false })}
            fullWidth={true}
            maxWidth='lg'
          >
            <DialogContent>
              Edit Mac Address(es)
            </DialogContent>
            <DialogContent style={{ display: 'grid', gridTemplateColumns: '96% 1fr' }}>
              <Autocomplete
                disablePortal
                freeSolo={true}
                options={top100Films}
                sx={{ width: 300 }}
                value={this.state.value}
                onChange={(event, newVal) => this.setState({ value: newVal })}
                renderInput={(params) => <TextField {...params} label="Movie" />}
              />
              <IconButton onClick={this.handleAddIP.bind(this)}>
                <AddIcon />
              </IconButton>
            </DialogContent>
            <DialogContent>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Location')}
                </Typography>
                <div className="clearfix" />
                <div className={classes.scrollBg}>
                  <div className={classes.scrollDiv}>
                    <div className={classes.scrollObj}>
                      <>
                        {this.state.ipAddress.map((address, key) => (
                          <div key={key} style={{ display: 'flex', justifyContent: 'space-between' }}>
                            <Typography>
                              {address}
                            </Typography>
                            <IconButton onClick={this.handleDeleteIP.bind(this, key)}>
                              <Delete />
                            </IconButton>
                          </div>
                        ))}
                      </>
                    </div>
                  </div>
                </div>
              </div>
            </DialogContent>
            <DialogActions>
              <Button
                variant='outlined'
                onClick={() => this.setState({ open: false, value: '' })}
              >
                {t('Cancel')}
              </Button>
              <Button
                variant='contained'
                onClick={() => this.setState({ open: false })}
                color="primary"
              >
                {t('Submit')}
              </Button>
            </DialogActions>
          </Dialog>
        </Paper>
      </div>
    );
  }
}

MacOsComponent.propTypes = {
  device: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fldt: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(MacOsComponent);
