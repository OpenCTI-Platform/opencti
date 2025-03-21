import React from 'react';
import { Box } from '@mui/material';
import ObjectMarkingField from '@components/common/form/ObjectMarkingField';
import { OptionsFormValues } from '@components/common/files/import_files/ImportFilesDialog';
import { FormikContextType, FormikProvider } from 'formik';
import StixCoreObjectsField from '@components/common/form/StixCoreObjectsField';
import { useFormatter } from '../../../../../components/i18n';
import { fieldSpacingContainerStyle } from '../../../../../utils/field';

interface ImportFilesOptionsProps {
  optionsFormikContext: FormikContextType<OptionsFormValues>;
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
              name="associatedEntity"
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
