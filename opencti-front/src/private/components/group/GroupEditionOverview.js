import React, { Component } from 'react';
import PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { commitMutation, createFragmentContainer } from 'react-relay';
import { Formik, Field, Form } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import { compose, pick } from 'ramda';
import * as Yup from 'yup';
import * as rxjs from 'rxjs';
import { debounceTime } from 'rxjs/operators';
import inject18n from '../../../components/i18n';
import TextField from '../../../components/TextField';
import { SubscriptionFocus } from '../../../components/Subscription';
import environment from '../../../relay/environment';

const styles = theme => ({
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

const groupMutationFieldPatch = graphql`
    mutation GroupEditionOverviewFieldPatchMutation($id: ID!, $input: EditInput!) {
        groupEdit(id: $id) {
            fieldPatch(input: $input) {
                ...GroupEditionOverview_group
            }
        }
    }
`;

const groupEditionOverviewFocus = graphql`
    mutation GroupEditionOverviewFocusMutation($id: ID!, $input: EditContext!) {
        groupEdit(id: $id) {
            contextPatch(input : $input) {
                ...GroupEditionOverview_group
            }
        }
    }
`;

const groupValidation = t => Yup.object().shape({
  name: Yup.string()
    .required(t('This field is required')),
  description: Yup.string(),
});

// We wait 0.5 sec of interruption before saving.
const onFormChange$ = new rxjs.Subject().pipe(
  debounceTime(500),
);

class GroupEditionOverviewComponent extends Component {
  constructor(props) {
    super(props);
    this.state = { markingDefinitions: [] };
  }

  componentDidMount() {
    this.subscription = onFormChange$.subscribe(
      (data) => {
        commitMutation(environment, {
          mutation: groupMutationFieldPatch,
          variables: {
            id: data.id,
            input: data.input,
          },
        });
      },
    );
  }

  componentWillUnmount() {
    if (this.subscription) {
      this.subscription.unsubscribe();
    }
  }

  handleChangeField(name, value) {
    // Validate the field first, if field is valid, debounce then save.
    groupValidation(this.props.t).validateAt(name, { [name]: value }).then(() => {
      onFormChange$.next({ id: this.props.group.id, input: { key: name, value } });
    });
  }

  handleChangeFocus(name) {
    commitMutation(environment, {
      mutation: groupEditionOverviewFocus,
      variables: {
        id: this.props.group.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  render() {
    const {
      t, group, editUsers, me,
    } = this.props;
    const initialValues = pick(['name', 'description'], group);
    return (
      <div>
        <Formik
          enableReinitialize={true}
          initialValues={initialValues}
          validationSchema={groupValidation(t)}
          render={() => (
            <Form style={{ margin: '20px 0 20px 0' }}>
              <Field name='name' component={TextField} label={t('Name')} fullWidth={true}
                     onFocus={this.handleChangeFocus.bind(this)}
                     onChange={this.handleChangeField.bind(this)}
                     helperText={<SubscriptionFocus me={me} users={editUsers} fieldName='name'/>}/>
              <Field name='description' component={TextField} label={t('Description')}
                     fullWidth={true} multiline={true} rows={4} style={{ marginTop: 10 }}
                     onFocus={this.handleChangeFocus.bind(this)}
                     onChange={this.handleChangeField.bind(this)}
                     helperText={<SubscriptionFocus me={me} users={editUsers} fieldName='description'/>}/>
            </Form>
          )}
        />
      </div>
    );
  }
}

GroupEditionOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  group: PropTypes.object,
  editUsers: PropTypes.array,
  me: PropTypes.object,
};

const GroupEditionOverview = createFragmentContainer(GroupEditionOverviewComponent, {
  group: graphql`
      fragment GroupEditionOverview_group on Group {
          id,
          name,
          description
      }
  `,
});

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(GroupEditionOverview);
