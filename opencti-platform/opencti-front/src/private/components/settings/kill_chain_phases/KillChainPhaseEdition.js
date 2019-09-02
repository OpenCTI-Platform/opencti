import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Formik, Field, Form } from 'formik';
import {
  compose,
  insert,
  find,
  propEq,
  pickAll,
  over,
  lensProp,
  defaultTo,
} from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import IconButton from '@material-ui/core/IconButton';
import { Close } from '@material-ui/icons';
import * as Yup from 'yup';
import inject18n from '../../../../components/i18n';
import {
  commitMutation,
  requestSubscription,
  WS_ACTIVATED,
} from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import {
  SubscriptionAvatars,
  SubscriptionFocus,
} from '../../../../components/Subscription';

const styles = theme => ({
  header: {
    backgroundColor: theme.palette.navAlt.backgroundHeader,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
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
    backgroundColor: theme.palette.navAlt.background,
    color: theme.palette.header.text,
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
    $input: EditInput!
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

const killChainPhaseValidation = t => Yup.object().shape({
  kill_chain_name: Yup.string().required(t('This field is required')),
  phase_name: Yup.string().required(t('This field is required')),
  phase_order: Yup.number()
    .typeError(t('The value must be a number'))
    .integer(t('The value must be a number'))
    .required(t('This field is required')),
});

class KillChainPhaseEditionContainer extends Component {
  componentDidMount() {
    const sub = requestSubscription({
      subscription,
      variables: {
        // eslint-disable-next-line
        id: this.props.killChainPhase.id
      },
    });
    this.setState({ sub });
  }

  componentWillUnmount() {
    this.state.sub.dispose();
  }

  handleChangeFocus(name) {
    if (WS_ACTIVATED) {
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
  }

  handleSubmitField(name, value) {
    killChainPhaseValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: killChainPhaseMutationFieldPatch,
          variables: {
            id: this.props.killChainPhase.id,
            input: { key: name, value },
          },
        });
      })
      .catch(() => false);
  }

  render() {
    const {
      t, classes, handleClose, killChainPhase, me,
    } = this.props;
    const { editContext } = killChainPhase;
    const missingMe = find(propEq('name', me.email))(editContext) === undefined;
    const editUsers = missingMe
      ? insert(0, { name: me.email }, editContext)
      : editContext;
    const initialValues = over(
      lensProp('phase_order'),
      defaultTo(''),
      pickAll(['kill_chain_name', 'phase_name', 'phase_order'], killChainPhase),
    );
    return (
      <div>
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={handleClose.bind(this)}
          >
            <Close fontSize="small" />
          </IconButton>
          <Typography variant="h6" classes={{ root: classes.title }}>
            {t('Update a kill chain phase')}
          </Typography>
          <SubscriptionAvatars users={editUsers} />
          <div className="clearfix" />
        </div>
        <div className={classes.container}>
          <Formik
            enableReinitialize={true}
            initialValues={initialValues}
            validationSchema={killChainPhaseValidation(t)}
            render={() => (
              <Form style={{ margin: '20px 0 20px 0' }}>
                <Field
                  name="kill_chain_name"
                  component={TextField}
                  label={t('Kill chain name')}
                  fullWidth={true}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onSubmit={this.handleSubmitField.bind(this)}
                  helperText={
                    <SubscriptionFocus
                      me={me}
                      users={editUsers}
                      fieldName="kill_chain_name"
                    />
                  }
                />
                <Field
                  name="phase_name"
                  component={TextField}
                  label={t('Phase name')}
                  fullWidth={true}
                  style={{ marginTop: 10 }}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onSubmit={this.handleSubmitField.bind(this)}
                  helperText={
                    <SubscriptionFocus
                      me={me}
                      users={editUsers}
                      fieldName="phase_name"
                    />
                  }
                />
                <Field
                  name="phase_order"
                  component={TextField}
                  label={t('Order')}
                  fullWidth={true}
                  type="number"
                  style={{ marginTop: 10 }}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onSubmit={this.handleSubmitField.bind(this)}
                  helperText={
                    <SubscriptionFocus
                      me={me}
                      users={editUsers}
                      fieldName="phase_order"
                    />
                  }
                />
              </Form>
            )}
          />
        </div>
      </div>
    );
  }
}

KillChainPhaseEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  killChainPhase: PropTypes.object,
  me: PropTypes.object,
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
        phase_order
        editContext {
          name
          focusOn
        }
      }
    `,
    me: graphql`
      fragment KillChainPhaseEdition_me on User {
        email
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(KillChainPhaseEditionFragment);
