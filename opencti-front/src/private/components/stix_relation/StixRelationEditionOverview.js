import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Formik, Field, Form } from 'formik';
import {
  compose, insert, find, propEq, pick, assoc, pipe,
} from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import MenuItem from '@material-ui/core/MenuItem';
import IconButton from '@material-ui/core/IconButton';
import Button from '@material-ui/core/Button';
import { Close } from '@material-ui/icons';
import * as Yup from 'yup';
import { dateFormat } from '../../../utils/Time';
import { resolveLink } from '../../../utils/Entity';
import inject18n from '../../../components/i18n';
import { commitMutation, requestSubscription } from '../../../relay/environment';
import TextField from '../../../components/TextField';
import { SubscriptionAvatars, SubscriptionFocus } from '../../../components/Subscription';
import Select from '../../../components/Select';

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
    subscription StixRelationEditionOverviewSubscription($id: ID!) {
        stixRelation(id: $id) {
            ...StixRelationEditionOverview_stixRelation
        }
    }
`;

const stixRelationMutationFieldPatch = graphql`
    mutation StixRelationEditionOverviewFieldPatchMutation($id: ID!, $input: EditInput!) {
        stixRelationEdit(id: $id) {
            fieldPatch(input: $input) {
                ...StixRelationEditionOverview_stixRelation
            }
        }
    }
`;

export const stixRelationEditionFocus = graphql`
    mutation StixRelationEditionOverviewFocusMutation($id: ID!, $input: EditContext!) {
        stixRelationEdit(id: $id) {
            contextPatch(input : $input) {
                ...StixRelationEditionOverview_stixRelation
            }
        }
    }
`;

const stixRelationValidation = t => Yup.object().shape({
  weight: Yup.number()
    .typeError(t('The value must be a number'))
    .integer(t('The value must be a number'))
    .required(t('This field is required')),
  first_seen: Yup.date()
    .typeError(t('The value must be a date (YYYY-MM-DD)'))
    .required(t('This field is required')),
  last_seen: Yup.date()
    .typeError(t('The value must be a date (YYYY-MM-DD)'))
    .required(t('This field is required')),
  description: Yup.string(),
});

class StixRelationEditionContainer extends Component {
  componentDidMount() {
    const sub = requestSubscription({
      subscription,
      variables: {
        // eslint-disable-next-line
        id: this.props.stixRelation.id
      },
    });
    this.setState({ sub });
  }

  componentWillUnmount() {
    this.state.sub.dispose();
  }

  handleChangeFocus(name) {
    commitMutation({
      mutation: stixRelationEditionFocus,
      variables: {
        id: this.props.stixRelation.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  handleSubmitField(name, value) {
    stixRelationValidation(this.props.t).validateAt(name, { [name]: value }).then(() => {
      commitMutation({
        mutation: stixRelationMutationFieldPatch,
        variables: { id: this.props.stixRelation.id, input: { key: name, value } },
      });
    }).catch(() => false);
  }

  render() {
    const {
      t, classes, handleClose, handleDelete, stixRelation, me, variant, stixDomainEntity,
    } = this.props;
    const { editContext } = stixRelation;
    const missingMe = find(propEq('name', me.email))(editContext) === undefined;
    const editUsers = missingMe ? insert(0, { name: me.email }, editContext) : editContext;
    const initialValues = pipe(
      assoc('first_seen', dateFormat(stixRelation.first_seen)),
      assoc('last_seen', dateFormat(stixRelation.last_seen)),
      pick(['weight', 'first_seen', 'last_seen', 'description']),
    )(stixRelation);
    const link = stixDomainEntity ? resolveLink(stixDomainEntity.type) : '';
    return (
      <div>
        <div className={classes.header}>
          <IconButton aria-label='Close' className={classes.closeButton} onClick={handleClose.bind(this)}>
            <Close fontSize='small'/>
          </IconButton>
          <Typography variant='h6' classes={{ root: classes.title }}>
            {t('Update a relationship')}
          </Typography>
          <SubscriptionAvatars users={editUsers}/>
          <div className='clearfix'/>
        </div>
        <div className={classes.container}>
          <Formik
            enableReinitialize={true}
            initialValues={initialValues}
            validationSchema={stixRelationValidation(t)}
            render={() => (
              <Form style={{ margin: '20px 0 20px 0' }}>
                <Field name='weight'
                       component={Select}
                       onFocus={this.handleChangeFocus.bind(this)}
                       onChange={this.handleSubmitField.bind(this)}
                       label={t('Confidence level')}
                       fullWidth={true}
                       inputProps={{
                         name: 'weight',
                         id: 'weight',
                       }}
                       containerstyle={{ marginTop: 10, width: '100%' }}
                       helpertext={<SubscriptionFocus me={me} users={editUsers} fieldName='weight'/>}
                >
                  <MenuItem value='1'>{t('Very low')}</MenuItem>
                  <MenuItem value='2'>{t('Low')}</MenuItem>
                  <MenuItem value='3'>{t('Medium')}</MenuItem>
                  <MenuItem value='4'>{t('High')}</MenuItem>
                  <MenuItem value='5'>{t('Very high')}</MenuItem>
                </Field>
                <Field name='first_seen' component={TextField} label={t('First seen')}
                       fullWidth={true} style={{ marginTop: 10 }}
                       onFocus={this.handleChangeFocus.bind(this)}
                       onSubmit={this.handleSubmitField.bind(this)}
                       helperText={<SubscriptionFocus me={me} users={editUsers} fieldName='first_seen'/>}/>
                <Field name='last_seen' component={TextField} label={t('Last seen')}
                       fullWidth={true} style={{ marginTop: 10 }}
                       onFocus={this.handleChangeFocus.bind(this)}
                       onSubmit={this.handleSubmitField.bind(this)}
                       helperText={<SubscriptionFocus me={me} users={editUsers} fieldName='last_seen'/>}/>
                <Field name='description' component={TextField} label={t('Description')}
                       fullWidth={true} multiline={true} rows={4} style={{ marginTop: 10 }}
                       onFocus={this.handleChangeFocus.bind(this)}
                       onSubmit={this.handleSubmitField.bind(this)}
                       helperText={<SubscriptionFocus me={me} users={editUsers} fieldName='description'/>}/>
              </Form>
            )}
          />
          {stixDomainEntity ? <Button variant='contained' color='primary' component={Link} to={`${link}/${stixDomainEntity.id}/knowledge/relations/${stixRelation.id}`} classes={{ root: classes.buttonLeft }}>
            {t('Details')}
          </Button> : ''}
          {variant !== 'noGraph'
            ? <Button variant='contained' onClick={handleDelete.bind(this)} classes={{ root: classes.button }}>
            {t('Delete')}
          </Button> : ''}
        </div>
      </div>
    );
  }
}

StixRelationEditionContainer.propTypes = {
  variant: PropTypes.string,
  handleClose: PropTypes.func,
  handleDelete: PropTypes.func,
  classes: PropTypes.object,
  stixDomainEntity: PropTypes.object,
  stixRelation: PropTypes.object,
  me: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const StixRelationEditionFragment = createFragmentContainer(StixRelationEditionContainer, {
  stixRelation: graphql`
      fragment StixRelationEditionOverview_stixRelation on StixRelation {
          id
          weight
          first_seen
          last_seen
          description
          editContext {
              name
              focusOn
          }
      }
  `,
  me: graphql`
      fragment StixRelationEditionOverview_me on User {
          email
      }
  `,
});

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(StixRelationEditionFragment);
