import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import { graphql, createFragmentContainer } from 'react-relay';
import { Form, Formik, Field } from 'formik';
import withStyles from '@mui/styles/withStyles';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import Button from '@mui/material/Button';
import { Close } from '@mui/icons-material';
import * as Yup from 'yup';
import * as R from 'ramda';
import { buildDate } from '../../../../utils/Time';
import { resolveLink } from '../../../../utils/Entity';
import inject18n from '../../../../components/i18n';
import {
  commitMutation,
  requestSubscription,
} from '../../../../relay/environment';
import { SubscriptionFocus } from '../../../../components/Subscription';
import DateTimePickerField from '../../../../components/DateTimePickerField';

const styles = (theme) => ({
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  importButton: {
    position: 'absolute',
    top: 15,
    right: 20,
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
  appBar: {
    width: '100%',
    zIndex: theme.zIndex.drawer + 1,
    borderBottom: '1px solid #5c5c5c',
  },
  title: {
    float: 'left',
  },
  button: {
    float: 'right',
    backgroundColor: '#f44336',
    borderColor: '#f44336',
    color: '#ffffff',
    '&:hover': {
      backgroundColor: '#c62828',
      borderColor: '#c62828',
    },
  },
  buttonLeft: {
    float: 'left',
  },
});

const subscription = graphql`
  subscription StixCyberObservableRelationshipEditionOverviewSubscription(
    $id: ID!
  ) {
    stixCyberObservableRelationship(id: $id) {
      ...StixCyberObservableRelationshipEditionOverview_stixCyberObservableRelationship
    }
  }
`;

const stixCyberObservableRelationshipMutationFieldPatch = graphql`
  mutation StixCyberObservableRelationshipEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    stixCyberObservableRelationshipEdit(id: $id) {
      fieldPatch(input: $input) {
        ...StixCyberObservableRelationshipEditionOverview_stixCyberObservableRelationship
      }
    }
  }
`;

export const stixCyberObservableRelationshipEditionFocus = graphql`
  mutation StixCyberObservableRelationshipEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    stixCyberObservableRelationshipEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const stixCyberObservableRelationshipValidation = (t) => Yup.object().shape({
  start_time: Yup.date()
    .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
    .required(t('This field is required')),
  stop_time: Yup.date()
    .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
    .required(t('This field is required')),
});

class StixCyberObservableRelationshipEditionOverview extends Component {
  constructor(props) {
    super(props);
    this.sub = requestSubscription({
      subscription,
      variables: { id: props.stixCyberObservableRelationship.id },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  handleChangeFocus(name) {
    commitMutation({
      mutation: stixCyberObservableRelationshipEditionFocus,
      variables: {
        id: this.props.stixCyberObservableRelationship.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  handleSubmitField(name, value) {
    stixCyberObservableRelationshipValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: stixCyberObservableRelationshipMutationFieldPatch,
          variables: {
            id: this.props.stixCyberObservableRelationship.id,
            input: { key: name, value: value || '' },
          },
        });
      })
      .catch(() => false);
  }

  render() {
    const {
      t,
      classes,
      handleClose,
      stixCyberObservableRelationship,
      stixDomainObject,
    } = this.props;
    const { editContext } = stixCyberObservableRelationship;
    const killChainPhases = R.pipe(
      R.pathOr([], ['killChainPhases', 'edges']),
      R.map((n) => ({
        label: `[${n.node.kill_chain_name}] ${n.node.phase_name}`,
        value: n.node.id,
      })),
    )(stixCyberObservableRelationship);
    const objectMarking = R.pipe(
      R.pathOr([], ['objectMarking', 'edges']),
      R.map((n) => ({
        label: n.node.definition,
        value: n.node.id,
      })),
    )(stixCyberObservableRelationship);
    const initialValues = R.pipe(
      R.assoc(
        'start_time',
        buildDate(stixCyberObservableRelationship.start_time),
      ),
      R.assoc(
        'stop_time',
        buildDate(stixCyberObservableRelationship.stop_time),
      ),
      R.assoc('killChainPhases', killChainPhases),
      R.assoc('objectMarking', objectMarking),
      R.pick(['start_time', 'stop_time', 'killChainPhases', 'objectMarking']),
    )(stixCyberObservableRelationship);
    const link = stixDomainObject
      ? resolveLink(stixDomainObject.entity_type)
      : '';
    return (
      <div>
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={handleClose.bind(this)}
            size="large"
            color="primary"
          >
            <Close fontSize="small" color="primary" />
          </IconButton>
          <Typography variant="h6" classes={{ root: classes.title }}>
            {t('Update a relationship')}
          </Typography>
          <div className="clearfix" />
        </div>
        <div className={classes.container}>
          <Formik
            enableReinitialize={true}
            initialValues={initialValues}
            validationSchema={stixCyberObservableRelationshipValidation(t)}
            render={() => (
              <Form style={{ margin: '20px 0 20px 0' }}>
                <Field
                  component={DateTimePickerField}
                  name="start_time"
                  onFocus={this.handleChangeFocus.bind(this)}
                  onSubmit={this.handleSubmitField.bind(this)}
                  TextFieldProps={{
                    label: t('Start time'),
                    variant: 'standard',
                    fullWidth: true,
                    helperText: (
                      <SubscriptionFocus
                        context={editContext}
                        fieldName="start_time"
                      />
                    ),
                  }}
                />
                <Field
                  component={DateTimePickerField}
                  name="stop_time"
                  onFocus={this.handleChangeFocus.bind(this)}
                  onSubmit={this.handleSubmitField.bind(this)}
                  TextFieldProps={{
                    label: t('Stop time'),
                    variant: 'standard',
                    fullWidth: true,
                    style: { marginTop: 20 },
                    helperText: (
                      <SubscriptionFocus
                        context={editContext}
                        fieldName="stop_time"
                      />
                    ),
                  }}
                />
              </Form>
            )}
          />
          {stixDomainObject ? (
            <Button
              variant="contained"
              color="primary"
              component={Link}
              to={`${link}/${stixDomainObject.id}/knowledge/relations/${stixCyberObservableRelationship.id}`}
              classes={{ root: classes.buttonLeft }}
            >
              {t('Details')}
            </Button>
          ) : (
            ''
          )}
        </div>
      </div>
    );
  }
}

StixCyberObservableRelationshipEditionOverview.propTypes = {
  handleClose: PropTypes.func,
  handleDelete: PropTypes.func,
  classes: PropTypes.object,
  stixDomainObject: PropTypes.object,
  stixCyberObservableRelationship: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const StixCyberObservableRelationshipEditionFragment = createFragmentContainer(
  StixCyberObservableRelationshipEditionOverview,
  {
    stixCyberObservableRelationship: graphql`
      fragment StixCyberObservableRelationshipEditionOverview_stixCyberObservableRelationship on StixCyberObservableRelationship {
        id
        start_time
        stop_time
        relationship_type
        editContext {
          name
          focusOn
        }
      }
    `,
  },
);

export default R.compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(StixCyberObservableRelationshipEditionFragment);
