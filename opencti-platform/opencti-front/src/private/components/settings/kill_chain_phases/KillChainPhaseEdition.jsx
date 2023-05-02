import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import { compose, defaultTo, lensProp, over, pickAll } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import { Close } from '@mui/icons-material';
import * as Yup from 'yup';
import inject18n from '../../../../components/i18n';
import {
  commitMutation,
  requestSubscription,
} from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import {
  SubscriptionAvatars,
  SubscriptionFocus,
} from '../../../../components/Subscription';

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
});

const subscription = graphql`
  subscription KillChainPhaseEditionSubscription($id: ID!) {
    killChainPhase(id: $id) {
      ...KillChainPhaseEdition_killChainPhase
    }
  }
`;

const killChainPhaseMutationFieldPatch = graphql`
  mutation KillChainPhaseEditionFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    killChainPhaseEdit(id: $id) {
      fieldPatch(input: $input) {
        ...KillChainPhaseEdition_killChainPhase
      }
    }
  }
`;

const killChainPhaseEditionFocus = graphql`
  mutation KillChainPhaseEditionFocusMutation($id: ID!, $input: EditContext!) {
    killChainPhaseEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const killChainPhaseValidation = (t) => Yup.object().shape({
  kill_chain_name: Yup.string().required(t('This field is required')),
  phase_name: Yup.string().required(t('This field is required')),
  x_opencti_order: Yup.number()
    .typeError(t('The value must be a number'))
    .integer(t('The value must be a number')),
});

class KillChainPhaseEditionContainer extends Component {
  constructor(props) {
    super(props);
    this.sub = requestSubscription({
      subscription,
      variables: { id: props.killChainPhase.id },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  handleChangeFocus(name) {
    commitMutation({
      mutation: killChainPhaseEditionFocus,
      variables: {
        id: this.props.killChainPhase.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  handleSubmitField(name, value) {
    killChainPhaseValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: killChainPhaseMutationFieldPatch,
          variables: {
            id: this.props.killChainPhase.id,
            input: { key: name, value: value || '' },
          },
        });
      })
      .catch(() => false);
  }

  render() {
    const { t, classes, handleClose, killChainPhase } = this.props;
    const { editContext } = killChainPhase;
    const initialValues = over(
      lensProp('x_opencti_order'),
      defaultTo(''),
      pickAll(
        ['kill_chain_name', 'phase_name', 'x_opencti_order'],
        killChainPhase,
      ),
    );
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
            {t('Update a kill chain phase')}
          </Typography>
          <SubscriptionAvatars context={editContext} />
          <div className="clearfix" />
        </div>
        <div className={classes.container}>
          <Formik
            enableReinitialize={true}
            initialValues={initialValues}
            validationSchema={killChainPhaseValidation(t)}
          >
            {() => (
              <Form style={{ margin: '20px 0 20px 0' }}>
                <Field
                  component={TextField}
                  variant="standard"
                  name="kill_chain_name"
                  label={t('Kill chain name')}
                  fullWidth={true}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onSubmit={this.handleSubmitField.bind(this)}
                  helperText={
                    <SubscriptionFocus
                      context={editContext}
                      fieldName="kill_chain_name"
                    />
                  }
                />
                <Field
                  component={TextField}
                  variant="standard"
                  name="phase_name"
                  label={t('Phase name')}
                  fullWidth={true}
                  style={{ marginTop: 20 }}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onSubmit={this.handleSubmitField.bind(this)}
                  helperText={
                    <SubscriptionFocus
                      context={editContext}
                      fieldName="phase_name"
                    />
                  }
                />
                <Field
                  component={TextField}
                  variant="standard"
                  name="x_opencti_order"
                  label={t('Order')}
                  fullWidth={true}
                  type="number"
                  style={{ marginTop: 20 }}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onSubmit={this.handleSubmitField.bind(this)}
                  helperText={
                    <SubscriptionFocus
                      context={editContext}
                      fieldName="x_opencti_order"
                    />
                  }
                />
              </Form>
            )}
          </Formik>
        </div>
      </div>
    );
  }
}

KillChainPhaseEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  killChainPhase: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const KillChainPhaseEditionFragment = createFragmentContainer(
  KillChainPhaseEditionContainer,
  {
    killChainPhase: graphql`
      fragment KillChainPhaseEdition_killChainPhase on KillChainPhase {
        id
        kill_chain_name
        phase_name
        x_opencti_order
        editContext {
          name
          focusOn
        }
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(KillChainPhaseEditionFragment);
