import React from 'react';
import { Option } from '@components/common/form/ReferenceField';
import { AssociatedEntityOption } from '@components/common/form/AssociatedEntityField';
import { Box } from '@mui/material';
import ObjectMarkingField from '@components/common/form/ObjectMarkingField';
import { FormikContextType, FormikProvider } from 'formik';
import StixCoreObjectsField from '@components/common/form/StixCoreObjectsField';
import { useFormatter } from '../../../../../components/i18n';
import { fieldSpacingContainerStyle } from '../../../../../utils/field';

interface ImportFilesOptionsProps {
  optionsFormikContext: FormikContextType<{ fileMarkings: Option[]; associatedEntity: AssociatedEntityOption }>;
  entityId?: string;
}

const ImportFilesOptions = ({ optionsFormikContext, entityId }: ImportFilesOptionsProps) => {
  const { t_i18n } = useFormatter();
  return (
    <FormikProvider value={optionsFormikContext}>
      <Box sx={{
        display: 'flex',
        flexDirection: 'column',
        justifySelf: 'center',
        gap: 2,
        width: '50%',
      }}
      >
        <ObjectMarkingField
          name="fileMarkings"
          label={t_i18n('File marking definition levels')}
          style={fieldSpacingContainerStyle}
          setFieldValue={optionsFormikContext.setFieldValue}
          required={false}
        />
        {!entityId
        && (
          <div style={{ paddingTop: '10px' }}>
            <StixCoreObjectsField
              name="entity"
              label={t_i18n('Associated entity')}
              multiple={false}
              setFieldValue={optionsFormikContext.setFieldValue}
              values={optionsFormikContext.values.associatedEntity}
            />
          </div>
        )}
      </Box>
    </FormikProvider>
  );
};

export default ImportFilesOptions;
