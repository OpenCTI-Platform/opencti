import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import {
  compose,
  pipe,
  pluck,
  assoc,
} from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer, QueryRenderer as QR } from 'react-relay';
import { Formik, Form, Field } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import * as Yup from 'yup';
import Typography from '@material-ui/core/Typography';
import Grid from '@material-ui/core/Grid';
import Paper from '@material-ui/core/Paper';
import { Information } from 'mdi-material-ui';
import Markdown from 'react-markdown';
import Tooltip from '@material-ui/core/Tooltip';
import FormControl from '@material-ui/core/FormControl';
import AddIcon from '@material-ui/icons/Add';
import Cancel from '@material-ui/icons/Cancel';
import Button from '@material-ui/core/Button';
import MenuItem from '@material-ui/core/MenuItem';
import Select from '@material-ui/core/Select';
import { IconButton } from '@material-ui/core';
import inject18n from '../../../../../components/i18n';
import TextField from '../../../../../components/TextField';
import { SubscriptionFocus } from '../../../../../components/Subscription';
import { commitMutation } from '../../../../../relay/environment';
import QueryRendererDarkLight from '../../../../../relay/environmentDarkLight';
import CreatedByField from '../../../common/form/CreatedByField';
import ObjectLabelField from '../../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../../common/form/ObjectMarkingField';
import MarkDownField from '../../../../../components/MarkDownField';
import SelectField from '../../../../../components/SelectField';
import ConfidenceField from '../../../common/form/ConfidenceField';
import AssetTaglist from '../../../common/form/AssetTaglist';
import AssetType from '../../../common/form/AssetType';
// import Ports from '../../../common/form/Ports';
import CommitMessage from '../../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../../utils/String';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    overflow: 'hidden',
    backgroundColor: theme.palette.navAlt.background,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: '30px 30px 30px 30px',
  },
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '24px 24px 32px 24px',
    borderRadius: 6,
  },
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
  },
  importButton: {
    position: 'absolute',
    top: 30,
    right: 30,
  },
});

class RemediationCreationOverviewComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      open: false,
      labelCreation: false,
    };
  }

  render() {
    const {
      t,
      classes,
      remediation,
      context,
      values,
      onSubmit,
      setFieldValue,
      enableReferences,
    } = this.props;
    return (
      <div style={{ height: '100%' }} className="break">
        <Typography variant="h4" gutterBottom={true}>
          {t('General')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Grid container={true} spacing={3} style={{ marginBottom: '12px' }}>
            <Grid item={true} xs={12}>
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ float: 'left' }}
              >
                {t('Name')}
              </Typography>
              <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                <Tooltip title={t('Name')}>
                  <Information fontSize="inherit" color="disabled" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              <TextField id="outlined-basic" style={{ width: '100%' }} size="small" variant="outlined" />
            </Grid>
          </Grid>
          <Grid container={true} spacing={3}>
            <Grid xs={6} item={true}>
              <Grid style={{ marginBottom: '20px' }} item={true}>
                <Typography
                  variant="h3"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Title')}
                </Typography>
                <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                  <Tooltip title={t('Title')}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <TextField id="outlined-basic" style={{ width: '100%' }} size="small" variant="outlined" />
              </Grid>
              <Grid style={{ marginBottom: '20px' }} item={true}>
                <Typography
                  variant="h3"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('ID')}
                </Typography>
                <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                  <Tooltip title={t('ID')}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <TextField id="outlined-basic" style={{ width: '100%' }} size="small" variant="outlined" />
              </Grid>
              <Grid style={{ marginBottom: '20px' }} item={true}>
                <Typography
                  variant="h3"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Created')}
                </Typography>
                <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                  <Tooltip title={t('Created')}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <TextField id="outlined-basic" style={{ width: '100%' }} size="small" variant="outlined" />
              </Grid>
              <Grid style={{ marginBottom: '20px' }} item={true}>
                <Typography
                  variant="h3"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Response Type')}
                </Typography>
                <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                  <Tooltip title={t('Response Type')}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <FormControl size="small" style={{ width: '100%', marginBottom: '5px' }} variant="outlined">
                  <Select defaultValue={1}>
                    <MenuItem value="">
                      <em>None</em>
                    </MenuItem>
                    <MenuItem value={1}>Physical Device</MenuItem>
                    <MenuItem value={2}>Twenty</MenuItem>
                    <MenuItem value={3}>Thirty</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
            </Grid>
            <Grid item={true} xs={6}>
              <Grid style={{ marginBottom: '20px', display: 'flex', flexWrap: 'wrap' }} item={true}>
                <Typography variant="h3" gutterBottom={true} style={{ float: 'left' }}>
                  {t('Source')}
                </Typography>
                <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                  <Tooltip title={t('Source')}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <AddIcon fontSize="size" style={{ margin: '-7px 0 0 0' }} />
                <div className="clearfix" />
                <div>
                  <FormControl size="small" style={{ width: '50%' }} variant="outlined">
                    <Select defaultValue={10}>
                      <MenuItem value="">
                        <em>None</em>
                      </MenuItem>
                      <MenuItem value={10}>Asset Owner</MenuItem>
                      <MenuItem value={20}>Twenty</MenuItem>
                      <MenuItem value={30}>Thirty</MenuItem>
                    </Select>
                  </FormControl>
                  <FormControl size="small" style={{ width: '50%' }} variant="outlined">
                    <Select defaultValue={10}>
                      <MenuItem value="">
                        <em>None</em>
                      </MenuItem>
                      <MenuItem value={10}>Lorel Ipsum</MenuItem>
                      <MenuItem value={20}>Twenty</MenuItem>
                      <MenuItem value={30}>Thirty</MenuItem>
                    </Select>
                  </FormControl>
                </div>
              </Grid>
              <Grid style={{ marginBottom: '20px', display: 'flex', flexWrap: 'wrap' }} item={true}>
                <Typography variant="h3" gutterBottom={true} style={{ float: 'left' }}>
                  {t('Decision Maker')}
                </Typography>
                <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                  <Tooltip title={t('Decision Maker')}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <AddIcon fontSize="size" style={{ margin: '-7px 0 0 0' }} />
                <div className="clearfix" />
                <div>
                  <FormControl size="small" style={{ width: '50%' }} variant="outlined">
                    <Select defaultValue={10}>
                      <MenuItem value="">
                        <em>None</em>
                      </MenuItem>
                      <MenuItem value={10}>Asset Owner</MenuItem>
                      <MenuItem value={20}>Twenty</MenuItem>
                      <MenuItem value={30}>Thirty</MenuItem>
                    </Select>
                  </FormControl>
                  <FormControl size="small" style={{ width: '50%' }} variant="outlined">
                    <Select defaultValue={10}>
                      <MenuItem value="">
                        <em>None</em>
                      </MenuItem>
                      <MenuItem value={10}>Lorel Ipsum</MenuItem>
                      <MenuItem value={20}>Twenty</MenuItem>
                      <MenuItem value={30}>Thirty</MenuItem>
                    </Select>
                  </FormControl>
                </div>
              </Grid>
              <Grid style={{ marginBottom: '20px' }} item={true}>
                <Typography
                  variant="h3"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Last Modified')}
                </Typography>
                <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                  <Tooltip title={t('Last Modified')}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <TextField id="outlined-basic" style={{ width: '100%' }} size="small" variant="outlined" />
              </Grid>
              <Grid style={{ marginBottom: '20px' }} item={true}>
                <Typography
                  variant="h3"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Lifecycle')}
                </Typography>
                <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                  <Tooltip title={t('Lifecycle')}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <TextField id="outlined-basic" style={{ width: '100%' }} size="small" variant="outlined" />
              </Grid>
            </Grid>
          </Grid>
          <Grid style={{ marginTop: '10px' }} item={true}>
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ float: 'left' }}
            >
              {t('Label')}
            </Typography>
            <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
              <Tooltip title={t('Label')}>
                <Information fontSize="inherit" color="disabled" />
              </Tooltip>
            </div>
            <div className="clearfix" />
            <textarea className="scrollbar-customize" rows="4" cols="68" />
          </Grid>
        </Paper>
      </div>
    );
  }
}

RemediationCreationOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  remediation: PropTypes.object,
  enableReferences: PropTypes.bool,
  context: PropTypes.array,
  handleClose: PropTypes.func,
};

const RemediationCreationOverview = createFragmentContainer(
  RemediationCreationOverviewComponent,
  {
    remediation: graphql`
      fragment RemediationCreationGeneral_remediation on ThreatActor {
        id
        name
        threat_actor_types
        confidence
        description
        createdBy {
          ... on Identity {
            id
            name
            entity_type
          }
        }
        objectMarking {
          edges {
            node {
              id
              definition
              definition_type
            }
          }
        }
      }
    `,
  },
);

export default R.compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(RemediationCreationOverview);
