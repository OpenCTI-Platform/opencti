import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import * as Yup from 'yup';
import * as R from 'ramda';
import { Formik, Form, Field } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import Switch from '@material-ui/core/Switch';
import Paper from '@material-ui/core/Paper';
import MenuItem from '@material-ui/core/MenuItem';
import Typography from '@material-ui/core/Typography';
import Grid from '@material-ui/core/Grid';
import { Information } from 'mdi-material-ui';
import AddIcon from '@material-ui/icons/Add';
import Tooltip from '@material-ui/core/Tooltip';
import inject18n from '../../../../../components/i18n';
import TextField from '../../../../../components/TextField';
import SelectField from '../../../../../components/SelectField';
import { SubscriptionFocus } from '../../../../../components/Subscription';
import { commitMutation } from '../../../../../relay/environment';
import OpenVocabField from '../../../common/form/OpenVocabField';
import { dateFormat, parse } from '../../../../../utils/Time';
import DatePickerField from '../../../../../components/DatePickerField';
import CommitMessage from '../../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../../utils/String';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '24px 24px 32px 24px',
    borderRadius: 6,
  },
});

const remediationMutationFieldPatch = graphql`
  mutation RemediationEditionDetailsFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    editRisk(id: $id, input: $input) {
      id
    }
  }
`;

const remediationEditionDetailsFocus = graphql`
  mutation RemediationEditionDetailsFocusMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    editRisk(id: $id, input: $input) {
      id
    }
  }
`;

class RemediationEditionDetailsComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: remediationEditionDetailsFocus,
      variables: {
        id: this.props.risk?.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  render() {
    const {
      t, classes, risk, context, enableReferences,
    } = this.props;
    console.log('RemediationEditionDetails', risk);
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Details')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={6}>
              <Grid style={{ marginBottom: '20px' }} item={true}>
                <Typography variant="h3"
                  color="textSecondary" gutterBottom={true} style={{ float: 'left' }}>
                  {t('Source')}
                </Typography>
                <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                  <Tooltip title={t('Source')}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <AddIcon fontSize="small" style={{ margin: '-4px 0 0 0' }} />
                <div className="clearfix" />
                <div>
                  <Field
                    component={SelectField}
                    variant='outlined'
                    name="source"
                    size='small'
                    fullWidth={true}
                    style={{ height: '38.09px' }}
                    containerstyle={{ width: '50%', padding: '0 0 1px 0' }}
                  />
                  <Field
                    component={SelectField}
                    variant='outlined'
                    name="source"
                    size='small'
                    fullWidth={true}
                    style={{ height: '38.09px' }}
                    containerstyle={{ width: '50%', padding: '0 0 1px 0' }}
                  />
                </div>
              </Grid>
              <Grid style={{ marginBottom: '15px' }} item={true}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Response Type')}
                </Typography>
                <div style={{ float: 'left', margin: '0 0 0 4px' }}>
                  <Tooltip
                    title={t(
                      'Response type',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Field
                  component={SelectField}
                  variant='outlined'
                  name="response_type"
                  size='small'
                  fullWidth={true}
                  style={{ height: '38.09px' }}
                  containerstyle={{ width: '100%', padding: '0 0 1px 0' }}
                />
              </Grid>
            </Grid>
            <Grid item={true} xs={6}>
              <Grid style={{ marginTop: '80px' }} item={true}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Lifecycle')}
                </Typography>
                <div style={{ float: 'left', margin: '0 0 0 4px' }}>
                  <Tooltip
                    title={t(
                      'Lifecycle',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Field
                  component={SelectField}
                  variant='outlined'
                  name="lifecycle"
                  size='small'
                  fullWidth={true}
                  style={{ height: '38.09px' }}
                  containerstyle={{ width: '100%', padding: '0 0 1px 0' }}
                />
              </Grid>
            </Grid>
          </Grid>
        </Paper>
      </div>
    );
  }
}

RemediationEditionDetailsComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  risk: PropTypes.object,
  enableReferences: PropTypes.bool,
  context: PropTypes.array,
  handleClose: PropTypes.func,
};

// const RemediationEditionDetails = createFragmentContainer(
//   RemediationEditionDetailsComponent,
//   {
//     risk: graphql`
//       fragment RiskEditionDetails_risk on ThreatActor {
//         id
//         first_seen
//         last_seen
//         sophistication
//         resource_level
//         primary_motivation
//         secondary_motivations
//         personal_motivations
//         goals
//       }
//     `,
//   },
// );

const RemediationEditionDetails = createFragmentContainer(
  RemediationEditionDetailsComponent,
  {
    risk: graphql`
      fragment RemediationEditionDetails_remediation on RiskResponse {
        id
        name              # Title
        description       # Description
        created           # Created
        modified          # Last Modified
        lifecycle         # Lifecycle
        response_type     # Response Type
        origins {
          id
          origin_actors {
            actor_type
            actor {
              ... on OscalPerson {
                id
                name      # source
              }
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
)(RemediationEditionDetails);
