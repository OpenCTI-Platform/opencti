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
          {t_i18n('Effective max confidence level:')}
          &nbsp;
          <UserConfidenceLevel confidenceLevel={currentUser.effective_confidence_level} />
        </Box>
      )}
      { currentUser && currentUser.effective_confidence_level === null && (currentUser.groups?.edges ?? []).length > 0 && (
        <Box
          sx={{ color: 'error.main' }}
        >
          {t_i18n('This user does not inherit a max confidence level from their group. Configure user\'s groups with a max confidence level.')}
        </Box>
      )}
      { currentUser && currentUser.effective_confidence_level === null && (currentUser.groups?.edges ?? []).length === 0 && (
        <Box
          sx={{ color: 'error.main' }}
        >
          {t_i18n('This user is not a member of any group and does not inherit a max confidence level.')}
        </Box>
      )}
      <Box sx={{ display: 'flex', alignItems: 'center' }}>
        {/* we still use a technical field for this switch to be able to do lazy yup validation ; do NOT submit! */}
        <Field
          component={SwitchField}
          type="checkbox"
          name="user_confidence_level_enabled"
          label={t_i18n('Enable user max confidence level')}
          // controlled field
          checked={switchValue}
          onChange={handleSwitchChange}
        />
        <Tooltip
          sx={{ zIndex: 2 }}
          title={t_i18n('The user\'s max confidence level overrides the max confidence that might be set at groups level.')}
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
