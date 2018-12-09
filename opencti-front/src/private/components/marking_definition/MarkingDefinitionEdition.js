import React, { Component } from 'react';
import PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { commitMutation, createFragmentContainer, requestSubscription } from 'react-relay';
import { Formik, Field, Form } from 'formik';
import {
  compose, insert, find, propEq, pick,
} from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import IconButton from '@material-ui/core/IconButton';
import { Close } from '@material-ui/icons';
import * as Yup from 'yup';
import * as rxjs from 'rxjs/index';
import { debounceTime } from 'rxjs/operators/index';
import inject18n from '../../../components/i18n';
import environment from '../../../relay/environment';
import TextField from '../../../components/TextField';
import { SubscriptionAvatars, SubscriptionFocus } from '../../../components/Subscription';

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
    subscription MarkingDefinitionEditionSubscription($id: ID!) {
        markingDefinition(id: $id) {
            ...MarkingDefinitionEdition_markingDefinition
        }
    }
`;

const markingDefinitionMutationFieldPatch = graphql`
    mutation MarkingDefinitionEditionFieldPatchMutation($id: ID!, $input: EditInput!) {
        markingDefinitionEdit(id: $id) {
            fieldPatch(input: $input) {
                ...MarkingDefinitionEdition_markingDefinition
            }
        }
    }
`;

const markingDefinitionEditionFocus = graphql`
    mutation MarkingDefinitionEditionFocusMutation($id: ID!, $input: EditContext!) {
        markingDefinitionEdit(id: $id) {
            contextPatch(input : $input) {
                ...MarkingDefinitionEdition_markingDefinition
            }
        }
    }
`;

const markingDefinitionValidation = t => Yup.object().shape({
  definition_type: Yup.string()
    .required(t('This field is required')),
  definition: Yup.string()
    .required(t('This field is required')),
  color: Yup.string()
    .required(t('This field is required')),
  level: Yup.number()
    .typeError(t('The value must be a number'))
    .integer(t('The value must be a number'))
    .required(t('This field is required')),
});

// We wait 0.5 sec of interruption before saving.
const onFormChange$ = new rxjs.Subject().pipe(
  debounceTime(500),
);


class MarkingDefinitionEditionContainer extends Component {
  componentDidMount() {
    const sub = requestSubscription(
      environment,
      {
        subscription,
        variables: {
          // eslint-disable-next-line
          id: this.props.markingDefinition.id
        },
        onError: error => console.log(error),

      },
    );
    this.setState({
      sub,
    });
    this.subscription = onFormChange$.subscribe(
      (data) => {
        commitMutation(environment, {
          mutation: markingDefinitionMutationFieldPatch,
          variables: {
            id: data.id,
            input: data.input,
          },
        });
      },
    );
  }

  componentWillUnmount() {
    this.state.sub.dispose();
    if (this.subscription) {
      this.subscription.unsubscribe();
    }
  }

  handleChangeField(name, value) {
    // Validate the field first, if field is valid, debounce then save.
    markingDefinitionValidation(this.props.t).validateAt(name, { [name]: value }).then(() => {
      onFormChange$.next({ id: this.props.markingDefinition.id, input: { key: name, value } });
    }).catch((error) => {
      console.log(error.errors); // array of validation error messages
      return false;
    });
  }

  handleChangeFocus(name) {
    commitMutation(environment, {
      mutation: markingDefinitionEditionFocus,
      variables: {
        id: this.props.markingDefinition.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  render() {
    const {
      t, classes, handleClose, markingDefinition, me,
    } = this.props;
    const { editContext } = markingDefinition;
    // Add current user to the context if is not available yet.
    const missingMe = find(propEq('username', me.email))(editContext) === undefined;
    const editUsers = missingMe ? insert(0, { username: me.email }, editContext) : editContext;
    const initialValues = pick(['definition_type', 'definition', 'color', 'level'], markingDefinition);
    return (
      <div>
        <div className={classes.header}>
          <IconButton aria-label='Close' className={classes.closeButton} onClick={handleClose.bind(this)}>
            <Close fontSize='small'/>
          </IconButton>
          <Typography variant='h6' classes={{ root: classes.title }}>
            {t('Update a marking definition')}
          </Typography>
          <SubscriptionAvatars users={editUsers}/>
          <div className='clearfix'/>
        </div>
        <div className={classes.container}>
          <Formik
            enableReinitialize={true}
            initialValues={initialValues}
            validationSchema={markingDefinitionValidation(t)}
            render={() => (
              <Form style={{ margin: '20px 0 20px 0' }}>
                <Field name='definition_type' component={TextField} label={t('Type')} fullWidth={true}
                       onFocus={this.handleChangeFocus.bind(this)} onChange={this.handleChangeField.bind(this)}
                       helperText={<SubscriptionFocus users={editUsers} fieldName='definition_type'/>}/>
                <Field name='definition' component={TextField} label={t('Definition')} fullWidth={true} style={{ marginTop: 10 }}
                       onFocus={this.handleChangeFocus.bind(this)} onChange={this.handleChangeField.bind(this)}
                       helperText={<SubscriptionFocus users={editUsers} fieldName='definition'/>}/>
                <Field name='color' component={TextField} label={t('Color')} fullWidth={true} style={{ marginTop: 10 }}
                       onFocus={this.handleChangeFocus.bind(this)} onChange={this.handleChangeField.bind(this)}
                       helperText={<SubscriptionFocus users={editUsers} fieldName='color'/>}/>
                <Field name='level' component={TextField} label={t('Level')} fullWidth={true} type='number' style={{ marginTop: 10 }}
                       onFocus={this.handleChangeFocus.bind(this)} onChange={this.handleChangeField.bind(this)}
                       helperText={<SubscriptionFocus users={editUsers} fieldName='level'/>}/>
              </Form>
            )}
          />
        </div>
      </div>
    );
  }
}

MarkingDefinitionEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  markingDefinition: PropTypes.object,
  me: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const MarkingDefinitionEditionFragment = createFragmentContainer(MarkingDefinitionEditionContainer, {
  markingDefinition: graphql`
      fragment MarkingDefinitionEdition_markingDefinition on MarkingDefinition {
          id,
          definition_type,
          definition,
          color,
          level,
          editContext {
              username
              focusOn
          }
      }
  `,
  me: graphql`
      fragment MarkingDefinitionEdition_me on User {
          email
      }
  `,
});

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(MarkingDefinitionEditionFragment);
