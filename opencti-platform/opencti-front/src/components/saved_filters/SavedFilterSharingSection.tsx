import AuthorizedMembersField from '@components/common/form/AuthorizedMembersField';
import AccordionDetails from '@mui/material/AccordionDetails';
import Typography from '@mui/material/Typography';
import { Field } from 'formik';
import React from 'react';
import { Accordion, AccordionSummary } from '../Accordion';
import { useFormatter } from '../i18n';
import { type Creator } from '../../utils/authorizedMembers';

interface SavedFilterSharingSectionProps {
  owner: Creator;
  isEditMode?: boolean;
}

const SavedFilterSharingSection = ({
  owner,
  isEditMode = false,
}: SavedFilterSharingSectionProps) => {
  const { t_i18n } = useFormatter();

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
            showAllMembersLine
            addMeUserWithAdminRights={!isEditMode}
            hideInfo
            customAccessRights={['view', 'admin']}
          />
        </AccordionDetails>
      </Accordion>
    </div>
  );
};

export default SavedFilterSharingSection;
