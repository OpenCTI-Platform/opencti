import React from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import { Form, Formik, Field } from 'formik';
import * as R from 'ramda';
import * as Yup from 'yup';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import Checkbox from '@mui/material/Checkbox';
import List from '@mui/material/List';
import ListSubheader from '@mui/material/ListSubheader';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import { SubscriptionFocus } from '../../../../components/Subscription';
import TextField from '../../../../components/TextField';
import MarkDownField from '../../../../components/MarkDownField';
import inject18n from '../../../../components/i18n';
import Loader from '../../../../components/Loader';
import SwitchField from '../../../../components/SwitchField';

const roleMutationFieldPatch = graphql`
  mutation RoleEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
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
    $input: InternalRelationshipAddInput
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
  mutation RoleEditionOverviewDelCapabilityMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    roleEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
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
  description: Yup.string().nullable(),
  default_assignation: Yup.bool(),
});

const RoleEditionOverviewComponent = ({ t, role, context }) => {
  const initialValues = R.pick(
    ['name', 'description', 'default_assignation'],
    role,
  );
  const handleChangeFocus = (name) => {
    commitMutation({
      mutation: roleEditionOverviewFocus,
      variables: {
        id: role.id,
        input: {
          focusOn: name,
        },
      },
    });
  };
  const handleSubmitField = (name, value) => {
    roleValidation(t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: roleMutationFieldPatch,
          variables: { id: role.id, input: { key: name, value } },
        });
      })
      .catch(() => false);
  };
  const handleToggle = (capability, event) => {
    const roleId = role.id;
    if (event.target.checked) {
      commitMutation({
        mutation: roleEditionAddCapability,
        variables: {
          id: roleId,
          input: {
            toId: capability.id,
            relationship_type: 'has-capability',
          },
        },
      });
    } else {
      commitMutation({
        mutation: roleEditionRemoveCapability,
        variables: {
          id: roleId,
          toId: capability.id,
          relationship_type: 'has-capability',
        },
      });
    }
  };
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
            <Field
              component={TextField}
              variant="standard"
              name="name"
              label={t('Name')}
              fullWidth={true}
              onFocus={handleChangeFocus}
              onSubmit={handleSubmitField}
              helperText={
                <SubscriptionFocus context={context} fieldName="name" />
              }
            />
            <Field
              component={MarkDownField}
              name="description"
              label={t('Description')}
              fullWidth={true}
              multiline={true}
              rows={4}
              style={{ marginTop: 20 }}
              onFocus={handleChangeFocus}
              onSubmit={handleSubmitField}
              helperText={
                <SubscriptionFocus context={context} fieldName="description" />
              }
            />
            <Field
              component={SwitchField}
              type="checkbox"
              name="default_assignation"
              label={t('Granted by default at user creation')}
              containerstyle={{ marginTop: 20 }}
              onChange={handleSubmitField}
              helperText={
                <SubscriptionFocus
                  context={context}
                  fieldName="default_assignation"
                />
              }
            />
            <QueryRenderer
              query={roleEditionOverviewCapabilities}
              variables={{}}
              render={({ props }) => {
                if (props) {
                  return (
                    <List
                      dense={true}
                      subheader={
                        <ListSubheader
                          component="div"
                          sx={{
                            paddingLeft: 0,
                            backgroundColor: 'transparent',
                          }}
                        >
                          {t('Capabilities')}
                        </ListSubheader>
                      }
                    >
                      {props.capabilities.edges.map((edge) => {
                        const capability = edge.node;
                        const paddingLeft = capability.name.split('_').length * 20 - 20;
                        const roleCapability = R.find(
                          R.propEq('name', capability.name),
                        )(role.capabilities);
                        const matchingCapabilities = R.filter(
                          (r) => capability.name !== r.name
                            && R.includes(capability.name, r.name)
                            && capability.name !== 'BYPASS',
                          role.capabilities,
                        );
                        const isDisabled = matchingCapabilities.length > 0;
                        const isChecked = isDisabled || roleCapability !== undefined;
                        return (
                          <ListItem
                            key={capability.name}
                            divider={true}
                            style={{ paddingLeft }}
                          >
                            <ListItemText primary={capability.description} />
                            <ListItemSecondaryAction>
                              <Checkbox
                                onChange={(event) => handleToggle(capability, event)
                                }
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
};

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

export default inject18n(RoleEditionOverview);
