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
import {
  commitMutation,
  requestSubscription,
  WS_ACTIVATED,
} from '../../../relay/environment';
import TextField from '../../../components/TextField';
import {
  SubscriptionAvatars,
  SubscriptionFocus,
} from '../../../components/Subscription';

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
  subscription CityEditionSubscription($id: ID!) {
    stixDomainEntity(id: $id) {
      ... on City {
        ...CityEdition_city
      }
    }
  }
`;

const cityMutationFieldPatch = graphql`
  mutation CityEditionFieldPatchMutation($id: ID!, $input: EditInput!) {
    cityEdit(id: $id) {
      fieldPatch(input: $input) {
        ...CityEdition_city
      }
    }
  }
`;

const cityEditionFocus = graphql`
  mutation CityEditionFocusMutation($id: ID!, $input: EditContext!) {
    cityEdit(id: $id) {
      contextPatch(input: $input) {
        ...CityEdition_city
      }
    }
  }
`;

const cityValidation = t => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string(),
});

class CityEditionContainer extends Component {
  componentDidMount() {
    const sub = requestSubscription({
      subscription,
      variables: { id: this.props.city.id },
    });
    this.setState({ sub });
  }

  componentWillUnmount() {
    this.state.sub.dispose();
  }

  handleChangeFocus(name) {
    if (WS_ACTIVATED) {
      commitMutation({
        mutation: cityEditionFocus,
        variables: {
          id: this.props.city.id,
          input: {
            focusOn: name,
          },
        },
      });
    }
  }

  handleSubmitField(name, value) {
    cityValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: cityMutationFieldPatch,
          variables: { id: this.props.city.id, input: { key: name, value } },
        });
      })
      .catch(() => false);
  }

  render() {
    const {
      t, classes, handleClose, city, me,
    } = this.props;
    const { editContext } = city;
    // Add current user to the context if is not available yet.
    const missingMe = find(propEq('name', me.email))(editContext) === undefined;
    const editUsers = missingMe
      ? insert(0, { name: me.email }, editContext)
      : editContext;
    const initialValues = pick(['name', 'description'], city);
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
            {t('Update a city')}
          </Typography>
          <SubscriptionAvatars users={editUsers} />
          <div className="clearfix" />
        </div>
        <div className={classes.container}>
          <Formik
            enableReinitialize={true}
            initialValues={initialValues}
            validationSchema={cityValidation(t)}
            onSubmit={() => true}
            render={() => (
              <Form style={{ margin: '20px 0 20px 0' }}>
                <Field
                  name="name"
                  component={TextField}
                  label={t('Name')}
                  fullWidth={true}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onSubmit={this.handleSubmitField.bind(this)}
                  helperText={
                    <SubscriptionFocus
                      me={me}
                      users={editUsers}
                      fieldName="name"
                    />
                  }
                />
                <Field
                  name="description"
                  component={TextField}
                  label={t('Description')}
                  fullWidth={true}
                  multiline={true}
                  rows={4}
                  style={{ marginTop: 10 }}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onSubmit={this.handleSubmitField.bind(this)}
                  helperText={
                    <SubscriptionFocus
                      me={me}
                      users={editUsers}
                      fieldName="description"
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

CityEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  city: PropTypes.object,
  me: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const CityEditionFragment = createFragmentContainer(CityEditionContainer, {
  city: graphql`
    fragment CityEdition_city on City {
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
    fragment CityEdition_me on User {
      email
    }
  `,
});

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(CityEditionFragment);
