import React, { FunctionComponent } from 'react';
import { Form, Formik } from 'formik';
import { Text } from '@filigran/design-system';
import { useTheme } from '@mui/material/styles';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import CreatorField from '@components/common/form/CreatorField';
import { useFormatter } from '../../../../../components/i18n';
import type { Theme } from '../../../../../components/Theme';
import type { FieldOption } from '../../../../../utils/field';

interface ConfigPresetServiceAccountDialogProps {
  open: boolean;
  itemLabel: string;
  value: FieldOption | null;
  onClose: () => void;
  onSubmit: (value: FieldOption) => void;
}

// Without a default group for the ingestion users, the platform cannot create a service account: the connector writes with an existing user
const ConfigPresetServiceAccountDialog: FunctionComponent<ConfigPresetServiceAccountDialogProps> = ({ open, itemLabel, value, onClose, onSubmit }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  return (
    <Dialog open={open} size="small" title={t_i18n('Service account of {name}', { values: { name: itemLabel } })} onClose={onClose}>
      <Text variant="content-base">{t_i18n('No default group is defined for the service accounts: choose the user this connector writes with.')}</Text>
      <Formik<{ user_id: FieldOption | null }> initialValues={{ user_id: value }} onSubmit={({ user_id: userId }) => userId && onSubmit(userId)}>
        {({ values, submitForm }) => (
          <Form>
            <CreatorField name="user_id" label={t_i18n('Service account responsible for data creation')} showConfidence />
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: theme.spacing(1), marginTop: theme.spacing(3) }}>
              <Button variant="secondary" onClick={onClose}>{t_i18n('Cancel')}</Button>
              <Button disabled={!values.user_id} onClick={submitForm}>{t_i18n('Save')}</Button>
            </div>
          </Form>
        )}
      </Formik>
    </Dialog>
  );
};

export default ConfigPresetServiceAccountDialog;
