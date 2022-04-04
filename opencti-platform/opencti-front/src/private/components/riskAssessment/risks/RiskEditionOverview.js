import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Formik, Form, Field } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import * as Yup from 'yup';
import Typography from '@material-ui/core/Typography';
import Grid from '@material-ui/core/Grid';
import Paper from '@material-ui/core/Paper';
import { Information } from 'mdi-material-ui';
import Tooltip from '@material-ui/core/Tooltip';
import Cancel from '@material-ui/icons/Cancel';
import Button from '@material-ui/core/Button';
import MenuItem from '@material-ui/core/MenuItem';
import AddIcon from '@material-ui/icons/Add';
// import AssetTaglist from '../../common/form/AssetTaglist';
import inject18n from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import DatePickerField from '../../../../components/DatePickerField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { commitMutation } from '../../../../relay/environment';
import CreatedByField from '../../common/form/CreatedByField';
import AssetType from '../../common/form/AssetType';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkDownField from '../../../../components/MarkDownField';
import SelectField from '../../../../components/SelectField';
import ConfidenceField from '../../common/form/ConfidenceField';
import CommitMessage from '../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';
import { dateFormat } from '../../../../utils/Time';
import StixCoreObjectLabelsView from '../../common/stix_core_objects/StixCoreObjectLabelsView';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '24px 24px 32px 24px',
    borderRadius: 6,
  },
});

const riskMutationFieldPatch = graphql`
  mutation RiskEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    editRisk(id: $id, input: $input) {
        id
       # ...RiskEditionOverview_risk
       # ...Risk_risk
    }
  }
`;

export const riskEditionOverviewFocus = graphql`
  mutation RiskEditionOverviewFocusMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    editRisk(id: $id, input: $input) {
      id
    }
  }
`;

// const riskValidation = (t) => Yup.object().shape({
//   name: Yup.string().required(t('This field is required')),
//   threat_actor_types: Yup.array(),
//   confidence: Yup.number().required(t('This field is required')),
//   description: Yup.string()
//     .min(3, t('The value is too short'))
//     .max(5000, t('The value is too long'))
//     .required(t('This field is required')),
// });

class RiskEditionOverviewComponent extends Component {
  render() {
    const {
      t,
      classes,
      risk,
      values,
    } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Basic Information')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Grid container={true} spacing={3} style={{ marginBottom: '9px' }}>
            <Grid item={true} xs={6}>
              <Grid item={true}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('ID')}
                </Typography>
                <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                  <Tooltip
                    title={t(
                      'In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Field
                  component={TextField}
                  variant='outlined'
                  size='small'
                  name="id"
                  fullWidth={true}
                  containerstyle={{ width: '100%' }}
                  disabled={true}
                />
              </Grid>
            </Grid>
            <Grid item={true} xs={6}>
              <Grid item={true}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('POAM ID')}
                </Typography>
                <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                  <Tooltip
                    title={t(
                      'In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Field
                  component={TextField}
                  variant='outlined'
                  size='small'
                  name="poam_id"
                  fullWidth={true}
                  containerstyle={{ width: '100%' }}
                />
              </Grid>
            </Grid>
          </Grid>
          <Grid container={true} spacing={3} style={{ marginBottom: '9px' }}>
            <Grid item={true} xs={6}>
              <Grid item={true}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Created')}
                </Typography>
                <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                  <Tooltip
                    title={t(
                      'In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Field
                  component={DatePickerField}
                  variant='outlined'
                  size='small'
                  name="created"
                  fullWidth={true}
                  containerstyle={{ width: '100%' }}
                />
              </Grid>
            </Grid>
            <Grid item={true} xs={6}>
              <Grid item={true}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Last Modified')}
                </Typography>
                <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                  <Tooltip
                    title={t(
                      'In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Field
                  component={DatePickerField}
                  variant='outlined'
                  size='small'
                  name="modified"
                  fullWidth={true}
                  containerstyle={{ width: '100%' }}
                />
              </Grid>
            </Grid>
          </Grid>
          <Grid item={true} xs={12} style={{ marginBottom: '15px' }}>
            <Typography
              variant="h3"
              color="textSecondary"
              gutterBottom={true}
              style={{ float: 'left' }}
            >
              {t('Description')}
            </Typography>
            <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
              <Tooltip
                title={t(
                  'In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.',
                )}
              >
                <Information fontSize="inherit" color="disabled" />
              </Tooltip>
            </div>
            <div className="clearfix" />
            <Field
              component={TextField}
              name="description"
              fullWidth={true}
              multiline={true}
              rows="4"
              variant='outlined'
            />
          </Grid>
          <Grid container={true} spacing={3}>
            <Grid xs={6} item={true}>
              <Grid style={{ marginBottom: '58px' }} item={true}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Weakness')}
                </Typography>
                <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                  <Tooltip
                    title={t(
                      'In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Field
                  component={TextField}
                  variant='outlined'
                  size='small'
                  name="weakness"
                  fullWidth={true}
                  containerstyle={{ width: '100%' }}
                />
              </Grid>
              <Grid style={{ marginBottom: '20px' }} item={true}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Risk Rating')}
                </Typography>
                <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                  <Tooltip
                    title={t(
                      'In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Field
                  component={TextField}
                  variant='outlined'
                  size='small'
                  name="risk_rating"
                  fullWidth={true}
                  containerstyle={{ width: '100%' }}
                  disabled={true}
                />
              </Grid>
              <Grid style={{ marginBottom: '15px' }} item={true}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Impact')}
                </Typography>
                <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                  <Tooltip
                    title={t(
                      'In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Field
                  component={TextField}
                  variant='outlined'
                  size='small'
                  name="impact"
                  fullWidth={true}
                  containerstyle={{ width: '100%' }}
                />
              </Grid>
            </Grid>
            <Grid item={true} xs={6}>
              <Grid style={{ marginBottom: '15px' }} item={true}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Controls')}
                </Typography>
                <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                  <Tooltip
                    title={t(
                      'In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <AddIcon fontSize="small" style={{ margin: '-5px 0 0 0' }} />
                <div className="clearfix" />
                <Field
                  component={SelectField}
                  variant='outlined'
                  name="controls"
                  size='small'
                  fullWidth={true}
                  style={{ height: '38.09px', marginBottom: '3px' }}
                  containerstyle={{ width: '100%', padding: '0 0 1px 0' }}
                />
                <Field
                  component={SelectField}
                  variant='outlined'
                  name="controls"
                  size='small'
                  fullWidth={true}
                  style={{ height: '38.09px' }}
                  containerstyle={{ width: '100%', padding: '0 0 1px 0' }}
                />
              </Grid>
              <Grid style={{ marginBottom: '20px' }} item={true}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Priority')}
                </Typography>
                <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                  <Tooltip
                    title={t(
                      'In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Field
                  component={TextField}
                  variant='outlined'
                  size='small'
                  name="priority"
                  fullWidth={true}
                  containerstyle={{ width: '100%' }}
                />
              </Grid>
              <Grid style={{ marginBottom: '10px' }} item={true}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Likelihood')}
                </Typography>
                <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                  <Tooltip
                    title={t(
                      'In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Field
                  component={TextField}
                  variant='outlined'
                  size='small'
                  name="likelihood"
                  fullWidth={true}
                  containerstyle={{ width: '100%' }}
                />
              </Grid>
            </Grid>
          </Grid>
          <Grid style={{ marginTop: '10px' }} item={true}>
            <Typography
              variant="h3"
              gutterBottom={true}
              color="textSecondary"
              style={{ float: 'left' }}
            >
              {t('Label')}
            </Typography>
            <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
              <Tooltip
                title={t(
                  'In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.',
                )}
              >
                <Information fontSize="inherit" color="disabled" />
              </Tooltip>
            </div>
            <div className="clearfix" />
            {/* <ObjectLabelField
                    variant='outlined'
                    name="labels"
                    style={{ marginTop: 10, width: '100%' }}
                    setFieldValue={setFieldValue}
                  // values={values.objectLabel}
                  /> */}
          </Grid>
        </Paper>
      </div>
    );
  }
}

RiskEditionOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  risk: PropTypes.object,
  enableReferences: PropTypes.bool,
  context: PropTypes.array,
  handleClose: PropTypes.func,
};

const RiskEditionOverview = createFragmentContainer(
  RiskEditionOverviewComponent,
  {
    risk: graphql`
      fragment RiskEditionOverview_risk on POAMItem {
        id
        created
        modified
        poam_id     # Item ID
        name        # Weakness
        description
        labels {
          id
          name
          color
          description
        }
        origins {
          id
          origin_actors {       # only use if UI support Detection Source
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
        links {
          id
          created
          modified
          external_id     # external id
          source_name     # Title
          description     # description
          url             # URL
          media_type      # Media Type
        }
        remarks {
          id
          abstract
          content
          authors
        }
        related_risks {
          edges {
            node{
              id
              created
              modified
              name
              description
              statement
              risk_status       # Risk Status
              deadline
              priority
              impacted_control_id
              accepted
              false_positive    # False-Positive
              risk_adjusted     # Operational Required
              vendor_dependency # Vendor Dependency
              characterizations {
                origins {
                  id
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
                        name          # Detection Source
                      }
                      ... on OscalParty {
                      id
                      party_type
                      name            # Detection Source
                      }
                    }
                  }
                }
                facets {
                  id
                  source_system
                  facet_name
                  facet_value
                  risk_state
                  entity_type
                }
              }
              remediations {
                response_type
                lifecycle
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
)(RiskEditionOverview);
