import React, { FunctionComponent, useState } from 'react';
import { Field, useFormikContext } from 'formik';
import Alert from '@mui/material/Alert';
import Box from '@mui/material/Box';
import Tooltip from '@mui/material/Tooltip';
import makeStyles from '@mui/styles/makeStyles';
import { InformationOutline } from 'mdi-material-ui';
import { UserEditionOverview_user$data } from '@components/settings/users/__generated__/UserEditionOverview_user.graphql';
import InputSliderField from '../../../../components/InputSliderField';
import { useFormatter } from '../../../../components/i18n';
import UserConfidenceLevel from './UserConfidenceLevel';
import type { Theme } from '../../../../components/Theme';
import SwitchField from '../../../../components/SwitchField';

const useStyles = makeStyles((theme: Theme) => ({
  alert: {
    width: '100%',
    marginTop: 20,
    paddingBottom: 0,
  },
  message: {
    width: '100%',
    overflow: 'visible',
    paddingBottom: 0,
    color: theme.palette.text?.secondary,
  },
}));

interface UserConfidenceLevelFieldProps {
  name: string;
  label?: string;
  onSubmit?: (name: string, value: string | null) => void;
  onFocus?: (name: string, value: string) => void;
  editContext?:
  | readonly ({
    readonly focusOn: string | null | undefined;
    readonly name: string;
  } | null)[]
  | null;
  containerStyle?: Record<string, string | number>;
  disabled?: boolean;
  currentUser?: UserEditionOverview_user$data; // only for edition
}

const UserConfidenceLevelField: FunctionComponent<UserConfidenceLevelFieldProps> = ({
  name,
  label,
  onFocus,
  onSubmit,
  editContext,
  containerStyle,
  disabled,
  currentUser,
}) => {
  const { t_i18n } = useFormatter();
  const finalLabel = label || t_i18n('Confidence level');
  const classes = useStyles();
  const { setFieldValue, initialValues } = useFormikContext<Record<string, boolean>>();
  const [switchValue, setSwitchValue] = useState(Number.isInteger(initialValues[name]));

  const handleSwitchChange = async () => {
    if (switchValue) {
      await setFieldValue(name, null);
      onSubmit?.(name, null);
    } else {
      await setFieldValue(name, 100);
      onSubmit?.(name, '100');
    }
    setSwitchValue(!switchValue);
  };
  return (
    <Alert
      classes={{ root: classes.alert, message: classes.message }}
      severity="info"
      icon={false}
      variant="outlined"
      sx={{ position: 'relative' }}
    >
      { currentUser && !!currentUser.effective_confidence_level && (
        <Box>
          {t_i18n('Effective Max Confidence Level:')}
          &nbsp;
          <UserConfidenceLevel confidenceLevel={currentUser.effective_confidence_level} />
        </Box>
      )}
      { currentUser && currentUser.effective_confidence_level === null && (currentUser.groups?.edges ?? []).length > 0 && (
        <Box
          sx={{ color: 'error.main' }}
        >
          {t_i18n('This user does not inherit a Max Confidence Level from their group. Configure user\'s groups with a Max Confidence Level.')}
        </Box>
      )}
      { currentUser && currentUser.effective_confidence_level === null && (currentUser.groups?.edges ?? []).length === 0 && (
        <Box
          sx={{ color: 'error.main' }}
        >
          {t_i18n('This user has no Max Confidence Level and does not inherit one from groups. Add a group to this user to resolve the issue.')}
        </Box>
      )}
      <Box sx={{ display: 'flex', alignItems: 'center' }}>
        {/* we still use a technical field for this switch to be able to do lazy yup validation ; do NOT submit! */}
        <Field
          component={SwitchField}
          type="checkbox"
          name="user_confidence_level_enabled"
          label={t_i18n('Enable user Max Confidence Level')}
          // controlled field
          checked={switchValue}
          onChange={handleSwitchChange}
        />
        <Tooltip
          sx={{ zIndex: 2 }}
          title={t_i18n('The user\'s Max Confidence Level overrides Max Confidence Level inherited from user\'s groups')}
        >
          <InformationOutline fontSize="small" color="primary" />
        </Tooltip>
      </Box>
      <Field
        component={InputSliderField}
        containerstyle={containerStyle}
        fullWidth={true}
        entityType={'User'}
        attributeName={name}
        name={name}
        label={finalLabel}
        onFocus={onFocus}
        onSubmit={onSubmit}
        editContext={editContext}
        disabled={!switchValue || disabled}
        variant="edit"
      />
    </Alert>
  );
};

export default UserConfidenceLevelField;
