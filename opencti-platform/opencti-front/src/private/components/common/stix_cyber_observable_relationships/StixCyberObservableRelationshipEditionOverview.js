import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Form, Formik, Field } from 'formik';
import {
  assoc, compose, map, pathOr, pick, pipe,
} from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import MenuItem from '@material-ui/core/MenuItem';
import IconButton from '@material-ui/core/IconButton';
import Button from '@material-ui/core/Button';
import { Close } from '@material-ui/icons';
import * as Yup from 'yup';
import { dateFormat } from '../../../../utils/Time';
import { resolveLink } from '../../../../utils/Entity';
import inject18n from '../../../../components/i18n';
import {
  commitMutation,
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import {
  SubscriptionAvatars,
  SubscriptionFocus,
} from '../../../../components/Subscription';
import SelectField from '../../../../components/SelectField';
import DatePickerField from '../../../../components/DatePickerField';
import { attributesQuery } from '../../settings/attributes/AttributesLines';
import Loader from '../../../../components/Loader';

const styles = (theme) => ({
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
    $input: EditInput!
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
  first_seen: Yup.date()
    .typeError(t('The value must be a date (YYYY-MM-DD)'))
    .required(t('This field is required')),
  last_seen: Yup.date()
    .typeError(t('The value must be a date (YYYY-MM-DD)'))
    .required(t('This field is required')),
  role_played: Yup.string(),
});

class StixCyberObservableRelationEditionContainer extends Component {
  componentDidMount() {
    const sub = requestSubscription({
      subscription,
      variables: {
        // eslint-disable-next-line
        id: this.props.stixCyberObservableRelationship.id,
      },
    });
    this.setState({ sub });
  }

  componentWillUnmount() {
    this.state.sub.dispose();
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
            input: { key: name, value },
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
      handleDelete,
      stixCyberObservableRelationship,
      stixDomainObject,
    } = this.props;
    const { editContext } = stixCyberObservableRelationship;
    const killChainPhases = pipe(
      pathOr([], ['killChainPhases', 'edges']),
      map((n) => ({
        label: `[${n.node.kill_chain_name}] ${n.node.phase_name}`,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(stixCyberObservableRelationship);
    const markingDefinitions = pipe(
      pathOr([], ['markingDefinitions', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(stixCyberObservableRelationship);
    const initialValues = pipe(
      assoc(
        'first_seen',
        dateFormat(stixCyberObservableRelationship.first_seen),
      ),
      assoc('last_seen', dateFormat(stixCyberObservableRelationship.last_seen)),
      assoc('killChainPhases', killChainPhases),
      assoc('markingDefinitions', markingDefinitions),
      pick([
        'weight',
        'first_seen',
        'last_seen',
        'description',
        'role_played',
        'killChainPhases',
        'markingDefinitions',
      ]),
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
          >
            <Close fontSize="small" />
          </IconButton>
          <Typography variant="h6" classes={{ root: classes.title }}>
            {t('Update a relationship')}
          </Typography>
          <SubscriptionAvatars context={editContext} />
          <div className="clearfix" />
        </div>
        <div className={classes.container}>
          <QueryRenderer
            query={attributesQuery}
            variables={{ type: 'role_played' }}
            render={({ props }) => {
              if (props && props.attributes) {
                const rolesPlayedEdges = props.attributes.edges;
                return (
                  <Formik
                    enableReinitialize={true}
                    initialValues={initialValues}
                    validationSchema={stixCyberObservableRelationshipValidation(
                      t,
                    )}
                    render={() => (
                      <Form style={{ margin: '20px 0 20px 0' }}>
                        <Field
                          component={SelectField}
                          name="role_played"
                          onFocus={this.handleChangeFocus.bind(this)}
                          onChange={this.handleSubmitField.bind(this)}
                          label={t('Played role')}
                          fullWidth={true}
                          containerstyle={{ width: '100%' }}
                          helpertext={
                            <SubscriptionFocus
                              context={editContext}
                              fieldName="role_played"
                            />
                          }
                        >
                          {rolesPlayedEdges.map((rolePlayedEdge) => (
                            <MenuItem
                              key={rolePlayedEdge.node.value}
                              value={rolePlayedEdge.node.value}
                            >
                              {rolePlayedEdge.node.value}
                            </MenuItem>
                          ))}
                        </Field>
                        <Field
                          component={DatePickerField}
                          name="first_seen"
                          label={t('First seen')}
                          invalidDateMessage={t(
                            'The value must be a date (YYYY-MM-DD)',
                          )}
                          fullWidth={true}
                          style={{ marginTop: 20 }}
                          onFocus={this.handleChangeFocus.bind(this)}
                          onSubmit={this.handleSubmitField.bind(this)}
                          helperText={
                            <SubscriptionFocus
                              context={editContext}
                              fieldName="first_seen"
                            />
                          }
                        />
                        <Field
                          component={DatePickerField}
                          name="last_seen"
                          label={t('Last seen')}
                          invalidDateMessage={t(
                            'The value must be a date (YYYY-MM-DD)',
                          )}
                          fullWidth={true}
                          style={{ marginTop: 20 }}
                          onFocus={this.handleChangeFocus.bind(this)}
                          onSubmit={this.handleSubmitField.bind(this)}
                          helperText={
                            <SubscriptionFocus
                              context={editContext}
                              fieldName="last_seen"
                            />
                          }
                        />
                        <Field
                          component={TextField}
                          name="description"
                          label={t('Description')}
                          fullWidth={true}
                          multiline={true}
                          rows={4}
                          style={{ marginTop: 20 }}
                          onFocus={this.handleChangeFocus.bind(this)}
                          onSubmit={this.handleSubmitField.bind(this)}
                          helperText={
                            <SubscriptionFocus
                              context={editContext}
                              fieldName="description"
                            />
                          }
                        />
                      </Form>
                    )}
                  />
                );
              }
              return <Loader variant="inElement" />;
            }}
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
          {typeof handleDelete === 'function' ? (
            <Button
              variant="contained"
              onClick={handleDelete.bind(this)}
              classes={{ root: classes.button }}
            >
              {t('Delete')}
            </Button>
          ) : (
            ''
          )}
        </div>
      </div>
    );
  }
}

StixCyberObservableRelationshipEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  handleDelete: PropTypes.func,
  classes: PropTypes.object,
  stixDomainObject: PropTypes.object,
  stixCyberObservableRelationship: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const StixCyberObservableRelationshipEditionFragment = createFragmentContainer(
  StixCyberObservableRelationEditionContainer,
  {
    stixCyberObservableRelationship: graphql`
      fragment StixCyberObservableRelationshipEditionOverview_stixCyberObservableRelationship on StixCyberObservableRelationship {
        id
        weight
        first_seen
        last_seen
        description
        relationship_type
        role_played
        markingDefinitions {
          edges {
            node {
              id
              definition
              definition_type
            }
          }
        }
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
)(StixCyberObservableRelationshipEditionFragment);
