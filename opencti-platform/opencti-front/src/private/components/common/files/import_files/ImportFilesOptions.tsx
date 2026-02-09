import React from 'react';
import { Box, Tooltip } from '@mui/material';
import ObjectMarkingField from '@components/common/form/ObjectMarkingField';
import { OptionsFormValues } from '@components/common/files/import_files/ImportFilesDialog';
import { Field, FormikContextType, FormikProvider } from 'formik';
import MenuItem from '@mui/material/MenuItem';
import StixCoreObjectsField from '@components/common/form/StixCoreObjectsField';
import { useImportFilesContext } from '@components/common/files/import_files/ImportFilesContext';
import { InformationOutline } from 'mdi-material-ui';
import AuthorizedMembersField from '@components/common/form/AuthorizedMembersField';
import { useFormatter } from '../../../../../components/i18n';
import { fieldSpacingContainerStyle } from '../../../../../utils/field';
import TextField from '../../../../../components/TextField';
import SelectField from '../../../../../components/fields/SelectField';
import { DraftContext } from '../../../../../utils/hooks/useDraftContext';
import useAuth from '../../../../../utils/hooks/useAuth';
import MarkdownField from '../../../../../components/fields/MarkdownField';
import ObjectAssigneeField from '@components/common/form/ObjectAssigneeField';
import ObjectParticipantField from '@components/common/form/ObjectParticipantField';
import CreatedByField from '@components/common/form/CreatedByField';
import useHelper from '../../../../../utils/hooks/useHelper';
import { useIsMandatoryAttribute } from '../../../../../utils/hooks/useEntitySettings';
import { DRAFTWORKPACE_TYPE } from '@components/drafts/DraftCreation';

interface ImportFilesOptionsProps {
  optionsFormikContext: FormikContextType<OptionsFormValues>;
  draftContext?: DraftContext | null;
}

const ImportFilesOptions = ({
  optionsFormikContext,
  draftContext,
}: ImportFilesOptionsProps) => {
  const { isFeatureEnable } = useHelper();
  const { t_i18n } = useFormatter();
  const { me: owner, settings } = useAuth();
  const { mandatoryAttributes } = useIsMandatoryAttribute(DRAFTWORKPACE_TYPE);
  const showAllMembersLine = !settings.platform_organization?.id;
  const {
    importMode,
    entityId,
    files,
    isForcedImportToDraft,
  } = useImportFilesContext();
  const isWorkbenchEnabled = files.length === 1;

  return (
    <FormikProvider value={optionsFormikContext}>
      <Box sx={{
        display: 'flex',
        flexDirection: 'column',
        justifySelf: 'center',
        gap: 2,
        width: '50%',
        marginInline: 'auto',
      }}
      >
        <ObjectMarkingField
          name="fileMarkings"
          label={t_i18n('File marking definition levels')}
          style={fieldSpacingContainerStyle}
          setFieldValue={optionsFormikContext.setFieldValue}
          required={false}
        />
        <div style={{ paddingTop: 8 }}>
          <StixCoreObjectsField
            name="associatedEntity"
            label={t_i18n('Associated entity')}
            multiple={false}
            disabled={!!entityId}
          />
        </div>
        {importMode !== 'auto' && !draftContext && (
          <>
            <div>
              <Field
                component={SelectField}
                variant="standard"
                name="validationMode"
                containerstyle={{ marginTop: 16, width: '100%', marginRight: 10 }}
                disabled={isForcedImportToDraft}
                label={(
                  <>
                    {t_i18n('Validation mode')}
                    <Tooltip
                      title={t_i18n('Import all data into a new draft or an analyst workbench, to validate the data before ingestion. Note that creating a workbench is not possible when several files are selected.')}
                    >
                      <InformationOutline
                        style={{ display: 'flex', marginTop: -22, marginLeft: 115 }}
                        fontSize="small"
                        color="primary"
                      />
                    </Tooltip>
                  </>
                )}
              >
                <MenuItem
                  key="draft"
                  value="draft"
                >
                  {t_i18n('Draft')}
                </MenuItem>
                <MenuItem
                  key="workbench"
                  value="workbench"
                  disabled={!isWorkbenchEnabled}
                >
                  {t_i18n('Workbench')}
                </MenuItem>
              </Field>
            </div>
            {optionsFormikContext.values.validationMode === 'draft' && (
              <>
                <Field
                  name="name"
                  label={t_i18n('Draft name')}
                  required={mandatoryAttributes.includes('name')}
                  component={TextField}
                  variant="standard"
                />
                {isFeatureEnable('DRAFT_METADATA') && (
                  <>
                    <Field
                      component={MarkdownField}
                      name="description"
                      label={t_i18n('Description')}
                      required={mandatoryAttributes.includes('description')}
                      fullWidth={true}
                      multiline={true}
                      rows="4"
                      style={fieldSpacingContainerStyle}
                      askAi={true}
                    />
                    <ObjectAssigneeField
                      name="objectAssignee"
                      style={fieldSpacingContainerStyle}
                      required={mandatoryAttributes.includes('objectAssignee')}
                    />
                    <ObjectParticipantField
                      name="objectParticipant"
                      style={fieldSpacingContainerStyle}
                      required={mandatoryAttributes.includes('objectParticipant')}
                    />
                    <CreatedByField
                      name="createdBy"
                      required={mandatoryAttributes.includes('createdBy')}
                      style={fieldSpacingContainerStyle}
                      setFieldValue={optionsFormikContext.setFieldValue}
                    />
                  </>
                )}
                <Field
                  name="authorizedMembers"
                  component={AuthorizedMembersField}
                  owner={owner}
                  showAllMembersLine={showAllMembersLine}
                  canDeactivate={true}
                  addMeUserWithAdminRights
                  isCanUseEnable
                  enableAccesses
                  applyAccesses
                />
              </>
            )}
          </>
        )}
      </Box>
    </FormikProvider>
  );
};

export default ImportFilesOptions;
