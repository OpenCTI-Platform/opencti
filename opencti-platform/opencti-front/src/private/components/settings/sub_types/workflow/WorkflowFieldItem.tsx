import { useState } from 'react';
import { Accordion, AccordionDetails, AccordionSummary, IconButton, Typography } from '@mui/material';
import { DeleteOutlined, ExpandMoreOutlined } from '@mui/icons-material';
import { Field, FieldProps } from 'formik';
import DeleteDialog from '../../../../../components/DeleteDialog';
import useDeletion from '../../../../../utils/hooks/useDeletion';
import AuthorizedMembersField from '@components/common/form/AuthorizedMembersField';
import { camelCaseToSentenceCase } from '../../../../../utils/String';
import { useFormatter } from '../../../../../components/i18n';
import WorkflowConditionFilters from './WorkflowConditionFilters';

interface WorkflowFieldItemProps extends FieldProps {
  onDelete: () => void;
}

const WorkflowFieldItem = ({ field, onDelete }: WorkflowFieldItemProps) => {
  const { t_i18n } = useFormatter();
  const { name, value } = field;
  const isCondition = name === 'conditions';
  const showExpandAccordionDetails = isCondition || !!value.params;

  const [expanded, setExpanded] = useState(showExpandAccordionDetails);
  const deletion = useDeletion({});

  return (
    <>
      <Accordion expanded={expanded} variant="outlined" sx={{ width: '100%', mb: 2 }}>
        <AccordionSummary expandIcon={showExpandAccordionDetails && <ExpandMoreOutlined />} onClick={() => showExpandAccordionDetails && setExpanded(!expanded)}>
          <Typography sx={{ display: 'inline-flex', alignItems: 'center', fontWeight: 'bold', flexGrow: 1 }}>
            {isCondition ? t_i18n('Condition') : camelCaseToSentenceCase(value.type)}
          </Typography>
          <IconButton
            color="error"
            onClick={(e) => {
              e.stopPropagation();
              deletion.handleOpenDelete();
            }}
          >
            <DeleteOutlined fontSize="small" />
          </IconButton>
        </AccordionSummary>
        <AccordionDetails sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          {isCondition ? (
            <Field name={name} component={WorkflowConditionFilters} />
          ) : (
            value.type === 'updateAuthorizedMembers' && (
              <Field name={`${name}.params.authorized_members`} component={AuthorizedMembersField} showAllMembersLine canDeactivate={false} enableAccesses hideInfo addMeUserWithAdminRights />
            )
          )}
        </AccordionDetails>
      </Accordion>

      <DeleteDialog
        message={t_i18n('Are you sure?')}
        deletion={deletion}
        submitDelete={() => {
          onDelete();
          deletion.handleCloseDelete();
        }}
      />
    </>
  );
};

export default WorkflowFieldItem;
