import React from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import { ConnectionHandler } from 'relay-runtime';
import makeStyles from '@mui/styles/makeStyles';
import ConfidenceField from '../../common/form/ConfidenceField';
import Drawer, { DrawerVariant } from '../../common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import useGranted, { SETTINGS_SETACCESSES } from '../../../../utils/hooks/useGranted';
import { useSchemaCreationValidation, useMandatorySchemaAttributes } from '../../../../utils/hooks/useSchemaAttributes';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles((theme) => ({
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
}));

const groupMutation = graphql`
  mutation GroupCreationMutation($input: GroupAddInput!) {
    groupAdd(input: $input) {
      ...GroupLine_node
    }
  }
`;

const sharedUpdater = (store, userId, paginationOptions, newEdge) => {
  const userProxy = store.get(userId);
  const conn = ConnectionHandler.getConnection(
    userProxy,
    'Pagination_groups',
    paginationOptions,
  );
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

const OBJECT_TYPE = 'Group';

const GroupCreation = ({ paginationOptions }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();

  const mandatoryAttributes = useMandatorySchemaAttributes(OBJECT_TYPE);
  const basicShape = {
    name: Yup.string(),
    description: Yup.string().nullable(),
    group_confidence_level: Yup.number()
      .min(0, t_i18n('The value must be greater than or equal to 0'))
      .max(100, t_i18n('The value must be less than or equal to 100')),
  };
  const validator = useSchemaCreationValidation(
    OBJECT_TYPE,
    basicShape,
  );

  const hasSetAccess = useGranted([SETTINGS_SETACCESSES]);

  const onSubmit = (values, { setSubmitting, resetForm }) => {
    const { group_confidence_level, ...rest } = values;
    const finalValues = {
      ...rest,
      group_confidence_level: {
        max_confidence: parseInt(group_confidence_level, 10),
        overrides: [],
      },
    };
    commitMutation({
      mutation: groupMutation,
      variables: {
        input: finalValues,
      },
      updater: (store) => {
        const payload = store.getRootField('groupAdd');
        const newEdge = payload.setLinkedRecord(payload, 'node');
        const container = store.getRoot();
        sharedUpdater(
          store,
          container.getDataID(),
          paginationOptions,
          newEdge,
        );
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
      },
    });
  };

  return (
    <Drawer
      title={t_i18n('Create a group')}
      variant={DrawerVariant.createWithPanel}
    >
      {({ onClose }) => (
        <Formik
          initialValues={{
            name: '',
            description: '',
            group_confidence_level: 100,
          }}
          validationSchema={validator}
          onSubmit={onSubmit}
          onReset={onClose}
        >
          {({ submitForm, handleReset, isSubmitting }) => (
            <Form style={{ margin: '20px 0 20px 0' }}>
              <Field
                component={TextField}
                name="name"
                label={t_i18n('Name')}
                required={(mandatoryAttributes.includes('name'))}
                fullWidth={true}
              />
              <Field
                component={MarkdownField}
                name="description"
                label={t_i18n('Description')}
                required={(mandatoryAttributes.includes('description'))}
                fullWidth={true}
                multiline={true}
                rows={4}
                style={{ marginTop: 20 }}
              />
              {hasSetAccess && (
                <ConfidenceField
                  name="group_confidence_level"
                  required={(mandatoryAttributes.includes('group_confidence_level'))}
                  label={t_i18n('Max Confidence Level')}
                  entityType="Group"
                  containerStyle={fieldSpacingContainerStyle}
                />
              )}
              <div className={classes.buttons}>
                <Button
                  variant="contained"
                  onClick={handleReset}
                  disabled={isSubmitting}
                  classes={{ root: classes.button }}
                >
                  {t_i18n('Cancel')}
                </Button>
                <Button
                  variant="contained"
                  color="secondary"
                  onClick={submitForm}
                  disabled={isSubmitting}
                  classes={{ root: classes.button }}
                >
                  {t_i18n('Create')}
                </Button>
              </div>
            </Form>
          )}
        </Formik>
      )}
    </Drawer>
  );
};

export default GroupCreation;
