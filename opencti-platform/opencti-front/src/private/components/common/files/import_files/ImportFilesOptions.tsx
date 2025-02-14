import { Option } from '@components/common/form/ReferenceField';
import AssociatedEntityField, { AssociatedEntityOption } from '@components/common/form/AssociatedEntityField';
import { Box } from '@mui/material';
import ObjectMarkingField from '@components/common/form/ObjectMarkingField';
import React from 'react';
import { fieldSpacingContainerStyle } from '../../../../../utils/field';
import { useFormatter } from '../../../../../components/i18n';

interface ImportFilesOptionsProps {
  setFieldValue: (name: string, values: Option[] | AssociatedEntityOption) => void;
  entityId?: string;
}

const ImportFilesOptions = ({ setFieldValue, entityId }: ImportFilesOptionsProps) => {
  const { t_i18n } = useFormatter();
  return (
    <Box sx={{
      display: 'flex',
      flexDirection: 'column',
      gap: 2,
      width: '50%',
    }}
    >
      <ObjectMarkingField
        name="fileMarkings"
        label={t_i18n('File marking definition levels')}
        style={fieldSpacingContainerStyle}
        setFieldValue={setFieldValue}
        required={false}
      />
      {!entityId
        && (
          <div style={{ paddingTop: '10px' }}>
            <AssociatedEntityField
              label={t_i18n('Associated entity')}
              name="associatedEntity"
              onChange={setFieldValue}
            />
          </div>
        )}
    </Box>
  );
};

export default ImportFilesOptions;
