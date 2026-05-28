import AuthorizedMembersField from '@components/common/form/AuthorizedMembersField';
import AccordionDetails from '@mui/material/AccordionDetails';
import Typography from '@mui/material/Typography';
import { LockOutlined } from '@mui/icons-material';
import { Field } from 'formik';
import React from 'react';
import { Accordion, AccordionSummary } from '../Accordion';
import { useFormatter } from '../i18n';
import { type Creator } from '../../utils/authorizedMembers';

interface SavedFilterSharingSectionProps {
  canShare: boolean;
  owner: Creator;
}

const SavedFilterSharingSection = ({
  canShare,
  owner,
}: SavedFilterSharingSectionProps) => {
  const { t_i18n } = useFormatter();


  if (!canShare) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 16 }}>
        <LockOutlined fontSize="small" color="disabled" />
        <Typography variant="body2" color="text.secondary">
          {t_i18n('Private')}
        </Typography>
      </div>
    );
  }

  return (
    <div style={{ marginTop: 16 }}>
      <Accordion>
        <AccordionSummary id="sharing-section">
          <Typography>{t_i18n('Sharing')}</Typography>
        </AccordionSummary>
        <AccordionDetails sx={{ p: 2 }}>
          <Field
            name="authorized_members"
            component={AuthorizedMembersField}
            owner={owner}
            enableAccesses
            addMeUserWithAdminRights
            hideInfo
            customAccessRights={['view', 'admin']}
          />
        </AccordionDetails>
      </Accordion>
    </div>
  );
};

export default SavedFilterSharingSection;
