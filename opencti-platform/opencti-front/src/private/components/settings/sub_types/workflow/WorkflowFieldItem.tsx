import { useState } from 'react';
import { Accordion, AccordionDetails, AccordionSummary, IconButton, Typography } from '@mui/material';
import { DeleteOutlined, ExpandMoreOutlined } from '@mui/icons-material';
import { Field, FieldProps } from 'formik';
import TextField from '../../../../../components/TextField';
import DeleteDialog from '../../../../../components/DeleteDialog';
import useDeletion from '../../../../../utils/hooks/useDeletion';
import AuthorizedMembersField from '@components/common/form/AuthorizedMembersField';
import { camelCaseToSentenceCase } from '../../../../../utils/String';
import { useFormatter } from '../../../../../components/i18n';

interface WorkflowFieldItemProps extends FieldProps {
  onDelete: () => void;
}

const WorkflowFieldItem = ({ field, onDelete }: WorkflowFieldItemProps) => {
  const { t_i18n } = useFormatter();
  const { name, value } = field;
  const isCondition = 'operator' in value || 'field' in value;
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
            <div style={{ display: 'flex', gap: '10px' }}>
              <Field component={TextField} name={`${name}.field`} label={t_i18n('Field')} variant="standard" fullWidth />
              <Field component={TextField} name={`${name}.operator`} label={t_i18n('Operator')} variant="standard" fullWidth />
              <Field component={TextField} name={`${name}.value`} label={t_i18n('Value')} variant="standard" fullWidth />
            </div>
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
