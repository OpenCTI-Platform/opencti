/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import * as R from 'ramda';
import { Field } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import Grid from '@material-ui/core/Grid';
import { Information } from 'mdi-material-ui';
import Tooltip from '@material-ui/core/Tooltip';
import inject18n from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import SwitchField from '../../../../components/SwitchField';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { commitMutation } from '../../../../relay/environment';
import TaskType from '../../common/form/TaskType';

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
    padding: '34px 34px 42px 34px',
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

// const softwareMutationFieldPatch = graphql`
//   mutation SoftwareCreationDetailsFieldPatchMutation(
//     $id: ID!
//     $input: [EditInput]!
//     $commitMessage: String
//   ) {
//     threatActorEdit(id: $id) {
//       fieldPatch(input: $input, commitMessage: $commitMessage) {
//         ...SoftwareCreationDetails_software
//         ...Software_software
//       }
//     }
//   }
// `;

const informationSystemCreationDetailsFocus = graphql`
  mutation InformationSystemCreationDetailsFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    threatActorEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

class InformationSystemCreationDetailsComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: informationSystemCreationDetailsFocus,
      variables: {
        id: this.props.informationSystem.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  render() {
    const { t, classes } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Details')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Grid container={true} spacing={3}>
            <Grid container spacing={3}>
              <Grid item={true} xs={6}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Software Identifier')}
                </Typography>
                <div style={{ float: 'left', margin: '-5px 0 0 5px' }}>
                  <Tooltip title={t('Software Identifier')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <Field
                  component={TextField}
                  variant='outlined'
                  name="software_identifier"
                  size='small'
                  fullWidth={true}
                />
              </Grid>
              <Grid item={true} xs={6}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Patch Level')}
                </Typography>
                <div style={{ float: 'left', margin: '-5px 0 0 5px' }}>
                  <Tooltip title={t('Patch Level')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Field
                  component={TextField}
                  style={{ height: '38.09px' }}
                  variant='outlined'
                  name="patch_level"
                  size='small'
                  fullWidth={true}
                  containerstyle={{ width: '100%', padding: '0 0 1px 0' }}
                />
              </Grid>
            </Grid>
            <Grid container spacing={3}>
              <Grid item={true} xs={6}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('CPE Identifier')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip
                    title={t('CPE Identifier')}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <Field
                  component={TextField}
                  variant='outlined'
                  name="cpe_identifier"
                  size='small'
                  fullWidth={true}
                />
              </Grid>
              <Grid item={true} xs={6}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Implementation Point')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip title={t('Implementation Point')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <TaskType
                  name='implementation_point'
                  taskType='ImplementationPoint'
                  fullWidth={true}
                  variant='outlined'
                  style={{ height: '38.09px' }}
                  containerstyle={{ width: '100%' }}
                />
              </Grid>
            </Grid>
            <Grid container spacing={3}>
              <Grid item={true} xs={6}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('License Key')}
                </Typography>
                <div style={{ float: 'left', margin: '15px 0 0 5px' }}>
                  <Tooltip title={t('License Key')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <Field
                  component={TextField}
                  style={{ height: '38.09px' }}
                  variant='outlined'
                  name="license_key"
                  size='small'
                  fullWidth={true}
                  containerstyle={{ width: '100%' }}
                />
              </Grid>
              <Grid item={true} xs={6}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Installation ID')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip title={t('Installation ID')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <Field
                  component={TextField}
                  variant='outlined'
                  name="installation_id"
                  size='small'
                  fullWidth={true}
                />
              </Grid>
            </Grid>
            <Grid container spacing={3}>
              <Grid item={true} xs={6}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Scanned')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip title={t('Scanned')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <div style={{ display: 'flex', alignItems: 'center' }}>
                  <Typography>No</Typography>
                  <Field
                    component={SwitchField}
                    type="checkbox"
                    name="is_scanned"
                    containerstyle={{ marginLeft: 10, marginRight: '-15px' }}
                    inputProps={{ 'aria-label': 'ant design' }}
                  />
                  <Typography>Yes</Typography>
                </div>
              </Grid>
              <Grid item={true} xs={6}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Last Scanned')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip title={t('Last Scanned')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <Field
                  component={DateTimePickerField}
                  variant="outlined"
                  name="last_scanned"
                  size="small"
                  invalidDateMessage={t(
                    'The value must be a date (YYYY-MM-DD HH:MM)',
                  )}
                  fullWidth={true}
                  style={{ height: '38.09px' }}
                  containerstyle={{ width: '100%' }}
                />
              </Grid>
            </Grid>
          </Grid>
        </Paper>
      </div>
    );
  }
}

InformationSystemCreationDetailsComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  informationSystem: PropTypes.object,
  enableReferences: PropTypes.bool,
  context: PropTypes.array,
  handleClose: PropTypes.func,
};

const InformationSystemCreationDetails = createFragmentContainer(
  InformationSystemCreationDetailsComponent,
  {
    informationSystem: graphql`
      fragment InformationSystemCreationDetails_software on ThreatActor {
        id
        first_seen
        last_seen
        sophistication
        resource_level
        primary_motivation
        secondary_motivations
        personal_motivations
        goals
      }
    `,
  },
);

export default R.compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(InformationSystemCreationDetails);
