import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import * as R from 'ramda';
import * as Yup from 'yup';
import { Formik, Form, Field } from 'formik';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import { Grid, Tooltip, IconButton } from '@material-ui/core';
import Button from '@material-ui/core/Button';
import Edit from '@material-ui/icons/Edit';
import Switch from '@material-ui/core/Switch';
import { Information } from 'mdi-material-ui';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import MarkDownField from '../../../../components/MarkDownField';
import RiskStatus from '../../common/form/RiskStatus';
import DatePickerField from '../../../../components/DatePickerField';
import SwitchField from '../../../../components/SwitchField';

const styles = (theme) => ({
  paper: {
    marginTop: '2%',
    padding: '1.5rem',
    borderRadius: 6,
    height: '75%',
  },
  link: {
    fontSize: '16px',
    font: 'DIN Next LT Pro',
  },
  chip: {
    color: theme.palette.header.text,
    height: 25,
    fontSize: 12,
    padding: '14px 12px',
    margin: '0 7px 7px 0',
    backgroundColor: theme.palette.header.background,
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
    height: '78px',
    overflow: 'hidden',
    overflowY: 'scroll',
  },
  scrollObj: {
    color: theme.palette.header.text,
    fontFamily: 'sans-serif',
    padding: '0px',
    textAlign: 'left',
  },
  statusButton: {
    cursor: 'default',
    background: '#075AD333',
    marginBottom: '5px',
    border: '1px solid #075AD3',
  },
  gridContainer: {
    marginBottom: '5%',
  },
  thumb: {
    '&.MuiSwitch-thumb': {
      color: 'white',
    },
  },
  textBase: {
    display: 'flex',
    alignItems: 'center',
    marginBottom: 5,
  },
  switch_track: {
    backgroundColor: '#D3134A !important',
    opacity: '1 !important',
  },
  switch_base: {
    color: 'white',
    '&.Mui-checked + .MuiSwitch-track': {
      backgroundColor: '#49B8FC !important',
      opacity: 1,
    },
  },
});

const riskDetailsEditMutation = graphql`
  mutation RiskDetailsEditMutation($id: ID!, $input: [EditInput]!) {
    editRisk(id: $id, input: $input) {
      id
      statement
      deadline
      risk_status
      accepted
      false_positive
      risk_adjusted
      vendor_dependency
    }
  }
`;

const RiskValidation = () => Yup.object().shape({
  statement: Yup.string().nullable(),
  risk_status: Yup.string().nullable(),
  deadline: Yup.string().nullable(),
  false_positive: Yup.string().nullable(),
  risk_adjusted: Yup.string().nullable(),
  vendor_dependency: Yup.string().nullable(),
  accepted: Yup.string().nullable(),
});

class RiskDetailsComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      open: false,
      modelName: '',
    };
  }

  handleEditOpen(field) {
    this.setState({ open: !this.state.open, modelName: field });
  }

  handleSubmitField(name, value) {
    RiskValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: riskDetailsEditMutation,
          variables: { id: this.props.risk.id, input: { key: name, value } },
          onCompleted: () => {
            this.setState({ modelName: '', open: false });
          },
        });
      })
      .catch(() => false);
  }

  render() {
    const {
      t,
      classes,
      risk,
      fldt,
    } = this.props;
    const {
      open,
      modelName,
    } = this.state;
    const riskDetectionSource = R.pipe(
      R.path(['origins']),
    )(risk);
    const initialValues = R.pipe(
      R.assoc('deadline', risk?.deadline || ''),
      R.assoc('statement', risk?.statement || ''),
      R.assoc('risk_status', risk?.risk_status || ''),
      R.assoc('vendor_dependency', risk?.vendor_dependency || false),
      R.pick([
        'deadline',
        'statement',
        'risk_status',
        'vendor_dependency',
      ]),
    )(risk);
    return (
      <div>
        <Typography variant="h4" gutterBottom={true}>
          {t('Details')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Formik
            enableReinitialize={true}
            initialValues={initialValues}
          >
            <Form>
              <Grid container spacing={3}>
                <Grid item={true} xs={6}>
                  <div className={classes.textBase}>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                      style={{ margin: 0 }}
                    >
                      {t('First Seen')}
                    </Typography>
                    <Tooltip
                      title={t(
                        'Identifies the date/time when the risk was first seen/observered.',
                      )}
                    >
                      <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <div className="clearfix" />
                  {risk.first_seen && fldt(risk.first_seen)}
                </Grid>
                <Grid item={true} xs={6}>
                  <div className={classes.textBase}>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                      style={{ margin: 0 }}
                    >
                      {t('Last Seen')}
                    </Typography>
                    <Tooltip
                      title={t(
                        'Idetifies the date/time when the risk was last seen/observed.',
                      )}
                    >
                      <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <div className="clearfix" />
                  {risk.last_seen && fldt(risk.last_seen)}
                </Grid>
                <Grid item={true} xs={12}>
                  <div className={classes.textBase}>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                      style={{ margin: 0 }}
                    >
                      {t('Statement')}
                    </Typography>
                    <Tooltip
                      title={t(
                        'Identifies a summary of impact for how the risk affects the system.',
                      )}
                    >
                      <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                    </Tooltip>
                    <IconButton
                      size='small'
                      style={{ fontSize: '15px' }}
                      color={(open && modelName === 'statement') ? 'primary' : 'inherit'}
                      onClick={this.handleEditOpen.bind(this, 'statement')}
                    >
                      <Edit fontSize='inherit' />
                    </IconButton>
                  </div>
                  <div className="clearfix" />
                  {open && modelName === 'statement' ? (
                    <Field
                      component={MarkDownField}
                      name='statement'
                      fullWidth={true}
                      multiline={true}
                      variant='outlined'
                      onSubmit={this.handleSubmitField.bind(this)}
                    />
                  ) : (
                    <div className={classes.scrollBg}>
                      <div className={classes.scrollDiv}>
                        <div className={classes.scrollObj}>
                          {risk.statement && t(risk.statement)}
                        </div>
                      </div>
                    </div>
                  )}
                </Grid>
                <Grid item={true} xs={6}>
                  <div className={classes.textBase}>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                      style={{ margin: 0 }}
                    >
                      {t('Risk Status')}
                    </Typography>
                    <Tooltip
                      title={t(
                        'Identifies the status of the associated risk.',
                      )}
                    >
                      <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                    </Tooltip>
                    <IconButton
                      size='small'
                      style={{ fontSize: '15px' }}
                      color={(open && modelName === 'risk_status') ? 'primary' : 'inherit'}
                      onClick={this.handleEditOpen.bind(this, 'risk_status')}
                    >
                      <Edit fontSize='inherit' />
                    </IconButton>
                  </div>
                  <div className="clearfix" />
                  {open && modelName === 'risk_status' ? (
                    <RiskStatus
                      variant='outlined'
                      name='risk_status'
                      size='small'
                      onChange={this.handleSubmitField.bind(this)}
                      fullWidth={true}
                      style={{ height: '38.09px', marginBottom: '3px' }}
                      containerstyle={{ width: '100%', padding: '0 0 1px 0' }}
                    />
                  ) : risk.risk_status && (
                    <Button
                      variant="outlined"
                      size="small"
                      className={classes.statusButton}
                    >
                      {t(risk.risk_status)}
                    </Button>
                  )}

                </Grid>
                <Grid item={true} xs={6}>
                  <div className={classes.textBase}>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                      style={{ margin: 0 }}
                    >
                      {t('Deadline')}
                    </Typography>
                    <Tooltip
                      title={t(
                        'Identifies the date/time by which the risk must be resolved.',
                      )}
                    >
                      <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                    </Tooltip>
                    <IconButton
                      size='small'
                      style={{ fontSize: '15px' }}
                      color={(open && modelName === 'deadline') ? 'primary' : 'inherit'}
                      onClick={this.handleEditOpen.bind(this, 'deadline')}
                    >
                      <Edit fontSize='inherit' />
                    </IconButton>
                  </div>
                  <div className="clearfix" />
                  {open && modelName === 'deadline' ? (
                    <Field
                      component={DatePickerField}
                      name='deadline'
                      fullWidth={true}
                      multiline={true}
                      variant='outlined'
                      onSubmit={this.handleSubmitField.bind(this)}
                      invalidDateMessage={t('The value must be a date (YYYY-MM-DD)')}
                    />
                  ) : risk.deadline && fldt(risk.deadline)
                  }
                </Grid>
                <Grid item={true} xs={6}>
                  <div className={classes.textBase}>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                      style={{ margin: 0 }}
                    >
                      {t('Detection Source')}
                    </Typography>
                    <Tooltip
                      title={t(
                        'Detection Source',
                      )}
                    >
                      <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <div className="clearfix" />
                  {riskDetectionSource
                    && riskDetectionSource.map((value) => value.origin_actors.map((actor, i) => (
                      <Typography key={i}>
                        {actor.actor_ref.name && t(actor.actor_ref.name)}
                      </Typography>
                    )))}
                </Grid>
                <Grid item={true} xs={6}>
                  <div className={classes.textBase}>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                      style={{ margin: 0 }}
                    >
                      {t('Vendor Dependency')}
                    </Typography>
                    <Tooltip
                      title={t(
                        'Identifies that a vendor resolution is pending, but not yet available.',
                      )}
                    >
                      <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                    </Tooltip>
                    <IconButton
                      size='small'
                      style={{ fontSize: '15px' }}
                      color={(open && modelName === 'vendor_dependency') ? 'primary' : 'inherit'}
                      onClick={this.handleEditOpen.bind(this, 'vendor_dependency')}
                    >
                      <Edit fontSize='inherit' />
                    </IconButton>
                  </div>
                  <div className="clearfix" />
                  <div style={{ display: 'flex' }}>
                    <Typography style={{ display: 'flex', alignItems: 'center' }}>No</Typography>
                    {open && modelName === 'vendor_dependency' ? (
                      <Field
                        component={SwitchField}
                        name="vendor_dependency"
                        type='checkbox'
                        containerstyle={{ margin: '0 -15px 0 11px' }}
                        onChange={this.handleSubmitField.bind(this)}
                      />
                    ) : (
                      <Switch
                        disabled
                        defaultChecked={risk.vendor_dependency}
                        classes={{
                          thumb: classes.thumb,
                          track: classes.switch_track,
                          switchBase: classes.switch_base,
                        }}
                      />
                    )}
                    <Typography style={{ display: 'flex', alignItems: 'center' }}>Yes</Typography>
                  </div>
                </Grid>
              </Grid>
            </Form>
          </Formik>
        </Paper>
      </div>
    );
  }
}

RiskDetailsComponent.propTypes = {
  risk: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fldt: PropTypes.func,
};

const RiskDetails = createFragmentContainer(
  RiskDetailsComponent,
  {
    risk: graphql`
      fragment RiskDetails_risk on Risk {
        id
        statement
        risk_status
        deadline
        false_positive
        risk_adjusted
        accepted
        vendor_dependency
        impacted_control_id
        first_seen
        last_seen
        origins {
          origin_actors {
            actor_type
            actor_ref {
              ... on AssessmentPlatform {
                id
                name
              }
              ... on Component {
                id
                component_type
                name
              }
              ... on OscalParty {
                id
                party_type
                name
              }
            }
          }
        }
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(RiskDetails);
