import React from 'react';
// FDS-WORKAROUND #36: top margin posed in `style`, the shipped sheet has no `mt-*` — remove when it ships consumer utilities — see fds-migration/LIBRARY-FEEDBACK.md #36
import { Paper } from '@filigran/design-system';
import { Field } from 'formik';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import Divider from '@mui/material/Divider';
import TextField from '../../../../components/TextField';
import { useFormatter } from '../../../../components/i18n';

interface AuthProviderUserInfoFieldsProps {
  fieldPrefix?: string;
  emailRequired?: boolean;
  nameRequired?: boolean;
  emailPlaceholder?: string;
  namePlaceholder?: string;
  firstnamePlaceholder?: string;
  lastnamePlaceholder?: string;
}

const AuthProviderUserInfoFields = ({
  fieldPrefix = '',
  emailRequired = true,
  nameRequired = true,
  emailPlaceholder,
  namePlaceholder,
  firstnamePlaceholder,
  lastnamePlaceholder,
}: AuthProviderUserInfoFieldsProps) => {
  const { t_i18n } = useFormatter();
  const prefix = fieldPrefix ? `${fieldPrefix}.` : '';

  return (
    <Paper padding={0} className="overflow-hidden" style={{ marginTop: 20 }}>
      <Box sx={{ px: 2, py: 1.5, backgroundColor: 'action.hover', display: 'flex', alignItems: 'center' }}>
        <Typography variant="caption" color="textSecondary">
          {t_i18n('User information mapping')}
        </Typography>
      </Box>
      <Divider />
      <Box sx={{
        display: 'grid',
        gridTemplateColumns: '1fr 1fr',
        columnGap: 2,
        rowGap: 0,
        px: 2,
        pt: 1,
        pb: 2,
      }}
      >
        <Field
          component={TextField}
          variant="standard"
          name={`${prefix}email_expr`}
          label={t_i18n('Email expression')}
          placeholder={emailPlaceholder}
          fullWidth
          required={emailRequired}
          className="mt-2.5"
        />
        <Field
          component={TextField}
          variant="standard"
          name={`${prefix}name_expr`}
          label={t_i18n('Name expression')}
          placeholder={namePlaceholder}
          fullWidth
          required={nameRequired}
          className="mt-2.5"
        />
        <Field
          component={TextField}
          variant="standard"
          name={`${prefix}firstname_expr`}
          label={t_i18n('First name expression')}
          placeholder={firstnamePlaceholder}
          fullWidth
          className="mt-2.5"
        />
        <Field
          component={TextField}
          variant="standard"
          name={`${prefix}lastname_expr`}
          label={t_i18n('Last name expression')}
          placeholder={lastnamePlaceholder}
          fullWidth
          className="mt-2.5"
        />
      </Box>
    </Paper>
  );
};

export default AuthProviderUserInfoFields;
