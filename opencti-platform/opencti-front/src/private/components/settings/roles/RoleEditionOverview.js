import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Form, Formik } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import {
  compose,
  pick,
  map,
  pipe,
  flatten,
  uniq,
  find,
  propEq,
  dropLast,
} from 'ramda';
import * as Yup from 'yup';
import ListItem from '@material-ui/core/ListItem';
import ListItemText from '@material-ui/core/ListItemText';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import Checkbox from '@material-ui/core/Checkbox';
import List from '@material-ui/core/List';
import ListSubheader from '@material-ui/core/ListSubheader';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import { SubscriptionFocus } from '../../../../components/Subscription';
import TextField from '../../../../components/TextField';
import inject18n from '../../../../components/i18n';
import Loader from '../../../../components/Loader';
import Switch from '../../../../components/SwitchField';

const styles = (theme) => ({
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

const roleMutationFieldPatch = graphql`
  mutation RoleEditionOverviewFieldPatchMutation($id: ID!, $input: EditInput!) {
    roleEdit(id: $id) {
      fieldPatch(input: $input) {
        ...RoleEditionOverview_role
      }
    }
  }
`;

const roleEditionOverviewFocus = graphql`
  mutation RoleEditionOverviewFocusMutation($id: ID!, $input: EditContext!) {
    roleEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const roleEditionAddCapability = graphql`
  mutation RoleEditionOverviewAddCapabilityMutation(
    $id: ID!
    $input: RelationAddInput!
  ) {
    roleEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...RoleEditionOverview_role
        }
      }
    }
  }
`;

const roleEditionRemoveCapability = graphql`
  mutation RoleEditionOverviewDelCapabilityMutation($id: ID!, $name: String!) {
    roleEdit(id: $id) {
      removeCapability(name: $name) {
        ...RoleEditionOverview_role
      }
    }
  }
`;

const roleEditionOverviewCapabilities = graphql`
  query RoleEditionOverviewCapabilitiesQuery {
    capabilities(first: 1000) {
      edges {
        node {
          id
          name
          description
        }
      }
    }
  }
`;

const roleValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string(),
  default_assignation: Yup.bool(),
});

class RoleEditionOverviewComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: roleEditionOverviewFocus,
      variables: {
        id: this.props.role.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  handleSubmitField(name, value) {
    roleValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: roleMutationFieldPatch,
          variables: { id: this.props.role.id, input: { key: name, value } },
        });
      })
      .catch(() => false);
  }

  handleToggle(capability, event) {
    const roleId = this.props.role.id;
    if (event.target.checked) {
      commitMutation({
        mutation: roleEditionAddCapability,
        variables: {
          id: roleId,
          input: {
            fromRole: 'position',
            toId: capability.id,
            toRole: 'capability',
            through: 'role_capability',
          },
        },
      });
    } else {
      commitMutation({
        mutation: roleEditionRemoveCapability,
        variables: {
          id: roleId,
          name: capability.name,
        },
      });
    }
  }

  render() {
    const {
      t, role, context, classes,
    } = this.props;
    const initialValues = pick(
      ['name', 'description', 'default_assignation'],
      role,
    );
    return (
      <div>
        <Formik
          enableReinitialize={true}
          initialValues={initialValues}
          validationSchema={roleValidation(t)}
          onSubmit={() => true}
        >
          {() => (
            <Form style={{ margin: '20px 0 20px 0' }}>
              <TextField
                name="name"
                label={t('Name')}
                fullWidth={true}
                onFocus={this.handleChangeFocus.bind(this)}
                onSubmit={this.handleSubmitField.bind(this)}
                helperText={
                  <SubscriptionFocus context={context} fieldName="name" />
                }
              />
              <TextField
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
                    context={context}
                    fieldName="description"
                  />
                }
              />
              <Switch
                name="default_assignation"
                label={t('Assign at user creation')}
                onChange={this.handleSubmitField.bind(this)}
              />
              <QueryRenderer
                query={roleEditionOverviewCapabilities}
                variables={{}}
                render={({ props }) => {
                  if (props) {
                    // Compute every capabilities
                    const inheritedCapabilities = pipe(
                      map((n) => {
                        const allCapabilities = n.name.split('_');
                        if (allCapabilities.length === 1) return [];
                        return dropLast(1, n.name.split('_'));
                      }),
                      flatten,
                      uniq,
                    )(role.capabilities);
                    return (
                      <List
                        dense={true}
                        className={classes.root}
                        subheader={
                          <ListSubheader
                            component="div"
                            style={{ paddingLeft: 0 }}
                          >
                            {t('Capabilities')}
                          </ListSubheader>
                        }
                      >
                        {props.capabilities.edges.map((edge) => {
                          const capability = edge.node;
                          const paddingLeft = capability.name.split('_').length * 20 - 20;
                          const roleCapability = find(
                            propEq('name', capability.name),
                          )(role.capabilities);
                          const isDisabled = inheritedCapabilities.includes(
                            capability.name,
                          );
                          const isChecked = roleCapability !== undefined;
                          return (
                            <ListItem
                              key={capability.name}
                              divider={true}
                              style={{ paddingLeft }}
                            >
                              <ListItemText primary={capability.description} />
                              <ListItemSecondaryAction>
                                <Checkbox
                                  onChange={this.handleToggle.bind(
                                    this,
                                    capability,
                                  )}
                                  checked={isChecked}
                                  disabled={isDisabled}
                                />
                              </ListItemSecondaryAction>
                            </ListItem>
                          );
                        })}
                      </List>
                    );
                  }
                  return <Loader variant="inElement" />;
                }}
              />
            </Form>
          )}
        </Formik>
      </div>
    );
  }
}

RoleEditionOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  role: PropTypes.object,
  context: PropTypes.array,
};

const RoleEditionOverview = createFragmentContainer(
  RoleEditionOverviewComponent,
  {
    role: graphql`
      fragment RoleEditionOverview_role on Role {
        id
        name
        default_assignation
        description
        capabilities {
          id
          name
          description
        }
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(RoleEditionOverview);
