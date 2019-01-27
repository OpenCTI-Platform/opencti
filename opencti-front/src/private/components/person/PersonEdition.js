import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Formik, Field, Form } from 'formik';
import {
  compose, insert, find, propEq, pick,
} from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import IconButton from '@material-ui/core/IconButton';
import { Close } from '@material-ui/icons';
import * as Yup from 'yup';
import inject18n from '../../../components/i18n';
import { commitMutation, requestSubscription, WS_ACTIVATED } from '../../../relay/environment';
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
    subscription PersonEditionSubscription($id: ID!) {
        stixDomainEntity(id: $id) {
            ... on User {
                ...PersonEdition_person
            }
        }
    }
`;

const personMutationFieldPatch = graphql`
    mutation PersonEditionFieldPatchMutation($id: ID!, $input: EditInput!) {
        userEdit(id: $id) {
            fieldPatch(input: $input) {
                ...PersonEdition_person
            }
        }
    }
`;

const personEditionFocus = graphql`
    mutation PersonEditionFocusMutation($id: ID!, $input: EditContext!) {
        userEdit(id: $id) {
            contextPatch(input : $input) {
                ...PersonEdition_person
            }
        }
    }
`;

const personValidation = t => Yup.object().shape({
  name: Yup.string()
    .required(t('This field is required')),
  description: Yup.string(),
});

class PersonEditionContainer extends Component {
  componentDidMount() {
    const sub = requestSubscription({
      subscription,
      variables: { id: this.props.person.id },
    });
    this.setState({ sub });
  }

  componentWillUnmount() {
    this.state.sub.dispose();
  }

  handleChangeFocus(name) {
    if (WS_ACTIVATED) {
      commitMutation({
        mutation: personEditionFocus,
        variables: {
          id: this.props.person.id,
          input: {
            focusOn: name,
          },
        },
      });
    }
  }

  handleSubmitField(name, value) {
    personValidation(this.props.t).validateAt(name, { [name]: value }).then(() => {
      commitMutation({
        mutation: personMutationFieldPatch,
        variables: { id: this.props.person.id, input: { key: name, value } },
      });
    }).catch(() => false);
  }

  render() {
    const {
      t, classes, handleClose, person, me,
    } = this.props;
    const { editContext } = person;
    // Add current user to the context if is not available yet.
    const missingMe = find(propEq('name', me.email))(editContext) === undefined;
    const editUsers = missingMe ? insert(0, { name: me.email }, editContext) : editContext;
    const initialValues = pick(['name', 'description'], person);
    return (
      <div>
        <div className={classes.header}>
          <IconButton aria-label='Close' className={classes.closeButton} onClick={handleClose.bind(this)}>
            <Close fontSize='small'/>
          </IconButton>
          <Typography variant='h6' classes={{ root: classes.title }}>
            {t('Update a person')}
          </Typography>
          <SubscriptionAvatars users={editUsers}/>
          <div className='clearfix'/>
        </div>
        <div className={classes.container}>
          <Formik
            enableReinitialize={true}
            initialValues={initialValues}
            validationSchema={personValidation(t)}
            render={() => (
              <Form style={{ margin: '20px 0 20px 0' }}>
                <Field name='name' component={TextField} label={t('Name')} fullWidth={true}
                       onFocus={this.handleChangeFocus.bind(this)}
                       onSubmit={this.handleSubmitField.bind(this)}
                       helperText={<SubscriptionFocus me={me} users={editUsers} fieldName='name'/>}/>
                <Field name='description' component={TextField} label={t('Description')}
                       fullWidth={true} multiline={true} rows={4} style={{ marginTop: 10 }}
                       onFocus={this.handleChangeFocus.bind(this)}
                       onSubmit={this.handleSubmitField.bind(this)}
                       helperText={<SubscriptionFocus me={me} users={editUsers} fieldName='description'/>}/>
              </Form>
            )}
          />
        </div>
      </div>
    );
  }
}

PersonEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  person: PropTypes.object,
  me: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const PersonEditionFragment = createFragmentContainer(PersonEditionContainer, {
  person: graphql`
      fragment PersonEdition_person on User {
          id
          name
          description
          editContext {
              name
              focusOn
          }
      }
  `,
  me: graphql`
      fragment PersonEdition_me on User {
          email
      }
  `,
});

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(PersonEditionFragment);
