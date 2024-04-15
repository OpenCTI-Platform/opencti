import React, { FunctionComponent } from 'react';
import UserConfidenceLevelField from '@components/settings/users/UserConfidenceLevelField';
import { UserEdition_user$data } from '@components/settings/users/__generated__/UserEdition_user.graphql';
import { Form, Formik } from 'formik';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import { Add } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import * as Yup from 'yup';
import { useMutation } from 'react-relay';
import { userEditionOverviewFocus, userMutationFieldPatch } from '@components/settings/users/UserEditionOverview';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { useFormatter } from '../../../../components/i18n';

const useStyles = makeStyles(() => ({
  createButton: {
    marginTop: '5px',
  },
}));

interface UserEditionConfidenceProps {
  user: UserEdition_user$data;
  context:
  | readonly ({
    readonly focusOn: string | null | undefined;
    readonly name: string;
  } | null)[]
  | null | undefined;
}

const userConfidenceValidation = (t: (value: string) => string) => Yup.object().shape({
  user_confidence_level_enabled: Yup.boolean(),
  user_confidence_level: Yup.number()
    .min(0, t('The value must be greater than or equal to 0'))
    .max(100, t('The value must be less than or equal to 100'))
    .when('user_confidence_level_enabled', {
      is: true,
      then: (schema) => schema.required(t('This field is required')).nullable(),
      otherwise: (schema) => schema.nullable(),
    }),
});

const UserEditionConfidence: FunctionComponent<UserEditionConfidenceProps> = ({ user, context }) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  console.log('user', user);
  const initialValues = {
    user_confidence_level_enabled: !!user.user_confidence_level,
    user_confidence_level: user.user_confidence_level?.max_confidence,
  };

  const [commitFocus] = useMutation(userEditionOverviewFocus);
  const [commitFieldPatch] = useMutation(userMutationFieldPatch);

  const handleChangeFocus = (name: string) => {
    commitFocus({
      variables: {
        id: user.id,
        input: {
          focusOn: name,
        },
      },
    });
  };

  const handleSubmitField = (name: string, value: string | null) => {
    userConfidenceValidation(t_i18n)
      .validateAt(name, { [name]: value })
      .then(() => {
        // specific case for user confidence level: to update an object we have several use-cases
        if (name === 'user_confidence_level') {
          if (user.user_confidence_level && value) {
            // We edit an existing value inside the object: use object_path
            commitFieldPatch({
              variables: {
                id: user.id,
                input: {
                  key: 'user_confidence_level',
                  object_path: '/user_confidence_level/max_confidence',
                  value: parseInt(value, 10),
                },
              },
            });
          } else if (!user.user_confidence_level && value) {
            // We have no user_confidence_level and we add one: push a complete object
            commitFieldPatch({
              variables: {
                id: user.id,
                input: {
                  key: 'user_confidence_level',
                  value: {
                    max_confidence: parseInt(value, 10),
                    overrides: [],
                  },
                },
              },
            });
          } else if (user.user_confidence_level && !value) {
            // we have an existing value but we want to remove it: push [null] (and not null!)
            commitFieldPatch({
              variables: {
                id: user.id,
                input: {
                  key: 'user_confidence_level',
                  value: [null],
                },
              },
            });
          }
        } else {
          // simple case for all flat attributes
          commitFieldPatch({
            variables: {
              id: user.id,
              input: { key: name, value: value || '' },
            },
          });
        }
      })
      .catch(() => false);
  };

  return (
    <>
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        onSubmit={() => {}}
      >
        <Form>
          <UserConfidenceLevelField
            name="user_confidence_level"
            label={t_i18n('Max Confidence Level')}
            onFocus={handleChangeFocus}
            onSubmit={handleSubmitField}
            containerStyle={fieldSpacingContainerStyle}
            editContext={context}
            user={user}
          />
        </Form>
      </Formik>
      <Typography variant="h4" gutterBottom={true} style={{ float: 'left', marginTop: '20px' }}>
        {t_i18n('Add a specific max confidence level for an entity type')}
      </Typography>
      <IconButton
        color="primary"
        aria-label="Add"
        onClick={() => console.log('onClick!')}
        classes={{ root: classes.createButton }}
        size="large"
      >
        <Add fontSize="small" />
      </IconButton>
    </>
  );
};

export default UserEditionConfidence;
