import React from 'react';
import { Box } from '@mui/material';
import ObjectMarkingField from '@components/common/form/ObjectMarkingField';
import { OptionsFormValues } from '@components/common/files/import_files/ImportFilesDialog';
import { Field, FormikContextType, FormikProvider } from 'formik';
import MenuItem from '@mui/material/MenuItem';
import StixCoreObjectsField from '@components/common/form/StixCoreObjectsField';
import { useFormatter } from '../../../../../components/i18n';
import { fieldSpacingContainerStyle } from '../../../../../utils/field';
import TextField from '../../../../../components/TextField';
import SelectField from '../../../../../components/fields/SelectField';
import { DraftContext } from '../../../../../utils/hooks/useDraftContext';
import useHelper from '../../../../../utils/hooks/useHelper';

interface ImportFilesOptionsProps {
  optionsFormikContext: FormikContextType<OptionsFormValues>;
  entityId?: string;
  draftContext?: DraftContext | null;
  isWorkbenchEnabled: boolean;
}

const ImportFilesOptions = ({
  optionsFormikContext,
  entityId,
  draftContext,
  isWorkbenchEnabled,
}: ImportFilesOptionsProps) => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();

  const isDraftFeatureEnabled = isFeatureEnable('DRAFT_WORKSPACE');

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
        {!draftContext && isDraftFeatureEnabled && (
          <Field
            component={SelectField}
            variant="standard"
            name="validationMode"
            label={t_i18n('Validation mode')}
            fullWidth={true}
            containerstyle={{ marginTop: 20, width: '100%' }}
          >
            <MenuItem
              key={'workbench'}
              value={'workbench'}
              disabled={!isWorkbenchEnabled}
            >
              {'Workbench'}
            </MenuItem>
            <MenuItem
              key={'draft'}
              value={'draft'}
            >
              {'Draft'}
            </MenuItem>
          </Field>
        )}
        {optionsFormikContext.values.validationMode === 'draft' && (
          <Field
            name="name"
            label={t_i18n('Name')}
            component={TextField}
            variant="standard"
            fullWidth={true}
          />
        )}
      </Box>
    </FormikProvider>
  );
};

export default ImportFilesOptions;
