import Button from 'src/components/common/button/Button';
import { Box } from '@mui/material';
import { Field } from 'formik';
import TextField from 'src/components/TextField';
import MarkdownField, { MarkdownImagesController } from 'src/components/fields/markdownField/MarkdownField';
import PeriodicityField from 'src/components/fields/PeriodicityField';
import SelectField from 'src/components/fields/SelectField';
import SwitchField from 'src/components/fields/SwitchField';
import FormButtonContainer from 'src/components/common/form/FormButtonContainer';
import MenuItem from '@mui/material/MenuItem';
import { useFormatter } from 'src/components/i18n';
import { SecurityCoverageFormValues, SecurityCoverageMode } from './SecurityCoverageCreation-types';
import { CoverageInformationFieldAdd } from 'src/private/components/common/form/CoverageInformationField';
import CreatedByField from 'src/private/components/common/form/CreatedByField';
import ObjectLabelField from 'src/private/components/common/form/ObjectLabelField';
import ObjectMarkingField from 'src/private/components/common/form/ObjectMarkingField';
import { fieldSpacingContainerStyle } from 'src/utils/field';
import ConfidenceField from 'src/private/components/common/form/ConfidenceField';
import OpenVocabField from 'src/private/components/common/form/OpenVocabField';

interface CoverageDetailsStepProps {
  values: SecurityCoverageFormValues;
  mode: SecurityCoverageMode | null;
  setFieldValue: (field: string, value: unknown) => void;
  onClose: () => void;
  isSubmitting: boolean;
  registerMarkdownImagesController: (controller: MarkdownImagesController) => void;
}
const CoverageDetailsStep = ({
  values,
  mode,
  setFieldValue,
  onClose,
  isSubmitting,
  registerMarkdownImagesController,
}: CoverageDetailsStepProps) => {
  const { t_i18n } = useFormatter();
  return (
    <Box>
      <Field
        component={TextField}
        variant="standard"
        name="name"
        label={t_i18n('Name')}
        fullWidth={true}
        required
      />
      <Field
        component={MarkdownField}
        name="description"
        label={t_i18n('Description')}
        fullWidth={true}
        multiline={true}
        rows={4}
        style={fieldSpacingContainerStyle}
        autoPersistOnBlur={false}
        registerMarkdownImagesController={registerMarkdownImagesController}
        uploadFileMarkings={values.objectMarking.map((v) => v.value)}
      />
      <ConfidenceField
        containerStyle={fieldSpacingContainerStyle}
        entityType="Security-Coverage"
      />
      <PeriodicityField
        name="periodicity"
        label={mode === SecurityCoverageMode.AUTO ? t_i18n('Coverage recurrence (every x)') : t_i18n('Coverage validity period')}
        style={fieldSpacingContainerStyle}
        setFieldValue={setFieldValue}
      />
      {mode === SecurityCoverageMode.AUTO && (
        <>
          <PeriodicityField
            name="duration"
            label={t_i18n('Duration')}
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
          />
          <Field
            component={SelectField}
            variant="standard"
            name="type_affinity"
            onChange={(name: string, value: string) => setFieldValue(name, value)}
            label={t_i18n('Type affinity')}
            fullWidth={true}
            containerstyle={{ width: '100%', marginTop: 20 }}
          >
            <MenuItem key="ENDPOINT" value="ENDPOINT">
              {t_i18n('Endpoint')}
            </MenuItem>
          </Field>
          <OpenVocabField
            label={t_i18n('Platform(s) affinity')}
            type="platforms_ov"
            name="platforms_affinity"
            onChange={(name, value) => setFieldValue(name, value)}
            containerStyle={fieldSpacingContainerStyle}
            multiple={true}
          />
        </>
      )}
      <Field
        component={SwitchField}
        type="checkbox"
        disabled={true}
        name="auto_enrichment_disable"
        label={t_i18n('Force manual coverage (prevent enrichment connectors from running)')}
        containerstyle={fieldSpacingContainerStyle}
      />
      {mode === SecurityCoverageMode.MANUAL && (
        <>
          <CoverageInformationFieldAdd
            name="coverage_information"
            values={values.coverage_information}
            setFieldValue={setFieldValue}
          />
          <Field
            component={TextField}
            variant="standard"
            name="external_uri"
            label={t_i18n('Source external link')}
            fullWidth={true}
            style={fieldSpacingContainerStyle}
          />
        </>
      )}
      <CreatedByField
        name="createdBy"
        style={fieldSpacingContainerStyle}
        setFieldValue={setFieldValue}
      />
      <ObjectLabelField
        name="objectLabel"
        style={fieldSpacingContainerStyle}
        setFieldValue={setFieldValue}
        values={values.objectLabel}
      />
      <ObjectMarkingField
        name="objectMarking"
        style={fieldSpacingContainerStyle}
        setFieldValue={setFieldValue}
      />
      <FormButtonContainer>
        <Button
          variant="secondary"
          onClick={onClose}
          disabled={isSubmitting}
        >
          {t_i18n('Cancel')}
        </Button>
        <Button
          type="submit"
          disabled={isSubmitting || !values.name || (mode === SecurityCoverageMode.MANUAL && (!values.coverage_information || values.coverage_information.length === 0))}
        >
          {t_i18n('Create')}
        </Button>
      </FormButtonContainer>
    </Box>
  );
};

export default CoverageDetailsStep;
