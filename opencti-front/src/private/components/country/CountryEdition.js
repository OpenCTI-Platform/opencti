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
    subscription CountryEditionSubscription($id: ID!) {
        stixDomainEntity(id: $id) {
            ... on Country {
                ...CountryEdition_country
            }
        }
    }
`;

const countryMutationFieldPatch = graphql`
    mutation CountryEditionFieldPatchMutation($id: ID!, $input: EditInput!) {
        countryEdit(id: $id) {
            fieldPatch(input: $input) {
                ...CountryEdition_country
            }
        }
    }
`;

const countryEditionFocus = graphql`
    mutation CountryEditionFocusMutation($id: ID!, $input: EditContext!) {
        countryEdit(id: $id) {
            contextPatch(input : $input) {
                ...CountryEdition_country
            }
        }
    }
`;

const countryValidation = t => Yup.object().shape({
  name: Yup.string()
    .required(t('This field is required')),
  description: Yup.string(),
});

class CountryEditionContainer extends Component {
  componentDidMount() {
    const sub = requestSubscription({
      subscription,
      variables: { id: this.props.country.id },
    });
    this.setState({ sub });
  }

  componentWillUnmount() {
    this.state.sub.dispose();
  }

  handleChangeFocus(name) {
    if (WS_ACTIVATED) {
      commitMutation({
        mutation: countryEditionFocus,
        variables: {
          id: this.props.country.id,
          input: {
            focusOn: name,
          },
        },
      });
    }
  }

  handleSubmitField(name, value) {
    countryValidation(this.props.t).validateAt(name, { [name]: value }).then(() => {
      commitMutation({
        mutation: countryMutationFieldPatch,
        variables: { id: this.props.country.id, input: { key: name, value } },
      });
    }).catch(() => false);
  }

  render() {
    const {
      t, classes, handleClose, country, me,
    } = this.props;
    const { editContext } = country;
    const missingMe = find(propEq('name', me.email))(editContext) === undefined;
    const editUsers = missingMe ? insert(0, { name: me.email }, editContext) : editContext;
    const initialValues = pick(['name', 'description'], country);
    return (
      <div>
        <div className={classes.header}>
          <IconButton aria-label='Close' className={classes.closeButton} onClick={handleClose.bind(this)}>
            <Close fontSize='small'/>
          </IconButton>
          <Typography variant='h6' classes={{ root: classes.title }}>
            {t('Update a country')}
          </Typography>
          <SubscriptionAvatars users={editUsers}/>
          <div className='clearfix'/>
        </div>
        <div className={classes.container}>
          <Formik
            enableReinitialize={true}
            initialValues={initialValues}
            validationSchema={countryValidation(t)}
            onSubmit={() => true}
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

CountryEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  country: PropTypes.object,
  me: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const CountryEditionFragment = createFragmentContainer(CountryEditionContainer, {
  country: graphql`
      fragment CountryEdition_country on Country {
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
      fragment CountryEdition_me on User {
          email
      }
  `,
});

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(CountryEditionFragment);
