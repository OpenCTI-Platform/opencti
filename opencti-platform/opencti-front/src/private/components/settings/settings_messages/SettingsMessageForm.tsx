import React from 'react';
import Box from '@mui/material/Box';
import { graphql } from 'react-relay';
import { FormikConfig } from 'formik/dist/types';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import Button from '@common/button/Button';
import Drawer from '@components/common/drawer/Drawer';
import ObjectMembersField from '@components/common/form/ObjectMembersField';
import ColorPickerField from '../../../../components/ColorPickerField';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import SwitchField from '../../../../components/fields/SwitchField';
import { SettingsMessagesLine_settingsMessage$data } from './__generated__/SettingsMessagesLine_settingsMessage.graphql';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const settingsMessageEditionPatch = graphql`
  mutation SettingsMessageFormPatchMutation(
    $id: ID!
    $input: SettingsMessageInput!
  ) {
    settingsEdit(id: $id) {
      editMessage(input: $input) {
        messages_administration {
          ...SettingsMessagesLine_settingsMessage
        }
      }
    }
  }
`;

const messageValidation = () => Yup.object().shape({
  message: Yup.string().required(),
  activated: Yup.boolean().required(),
  dismissible: Yup.boolean().required(),
  color: Yup.string().nullable(),
  recipients: Yup.array().nullable(),
});

type SettingsMessageInput = Partial<
  Pick<
    SettingsMessagesLine_settingsMessage$data,
'id' | 'activated' | 'message' | 'dismissible'
  > & { recipients: FieldOption[] }
>;

const SettingsMessageForm = ({
  settingsId,
  message,
  handleClose,
  creation = false,
  open,
}: {
  settingsId: string;
  message?: SettingsMessagesLine_settingsMessage$data;
  handleClose: () => void;
  creation?: boolean;
  open?: boolean;
}) => {
  const { t_i18n } = useFormatter();
  const [commit] = useApiMutation(settingsMessageEditionPatch);
  const onSubmit: FormikConfig<SettingsMessageInput>['onSubmit'] = (
    values,
    { setSubmitting },
  ) => {
    commit({
      variables: {
        id: settingsId,
        input: {
          ...values,
          recipients: values.recipients?.map(({ value }) => value),
        },
      },
      onCompleted: () => {
        setSubmitting(false);
      },
    });
  };
  const initialValues = message
    ? {
        id: message.id,
        message: message.message,
        activated: message.activated,
        dismissible: message.dismissible,
        color: message.color,
        recipients: message.recipients?.map(({ id, name }) => ({
          label: name,
          value: id,
        })),
      }
    : {
        message: '',
        activated: false,
        dismissible: false,
        color: '',
        recipients: [],
      };
  return (
    <Drawer
      title={creation ? `${t_i18n('Create a message')}` : `${t_i18n('Update a message')}`}
      open={open}
      onClose={handleClose}
    >
      {({ onClose }) => (
        <Formik<SettingsMessageInput>
          enableReinitialize={true}
          initialValues={initialValues}
          validationSchema={messageValidation()}
          onSubmit={(values, formikHelpers) => {
            onSubmit(values, formikHelpers);
            onClose();
          }}
          onReset={onClose}
        >
          {({ submitForm, handleReset, isSubmitting, isValid }) => (
            <Form>
              <Field
                component={TextField}
                variant="outlined"
                name="message"
                label={t_i18n('Message')}
                fullWidth={true}
              />
              <Field
                component={ColorPickerField}
                name="color"
                label={t_i18n('Color')}
                fullWidth={true}
                style={{ marginTop: 20 }}
              />
              <ObjectMembersField
                name="recipients"
                label={t_i18n('Recipients')}
                style={fieldSpacingContainerStyle}
                multiple={true}
              />
              <Field
                component={SwitchField}
                type="checkbox"
                name="activated"
                label={t_i18n('Activated')}
                containerstyle={{ marginTop: 20 }}
              />
              <Field
                component={SwitchField}
                type="checkbox"
                name="dismissible"
                label={t_i18n('Dismissible')}
                containerstyle={{ marginTop: 10 }}
              />
              <Box sx={{ marginTop: 2, textAlign: 'right' }}>
                <Button
                  variant="secondary"
                  onClick={handleReset}
                  disabled={isSubmitting}
                  sx={{ marginLeft: 2 }}
                >
                  {t_i18n('Cancel')}
                </Button>
                <Button
                  onClick={submitForm}
                  disabled={isSubmitting || !isValid}
                  sx={{ marginLeft: 2 }}
                >
                  {creation ? `${t_i18n('Create')}` : `${t_i18n('Update')}`}
                </Button>
              </Box>
            </Form>
          )}
        </Formik>
      )}
    </Drawer>
  );
};

export default SettingsMessageForm;
