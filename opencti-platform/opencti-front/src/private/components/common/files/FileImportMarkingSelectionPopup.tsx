import { Formik } from 'formik';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import React, { useState } from 'react';
import ObjectMarkingField from '@components/common/form/ObjectMarkingField';
import Button from '@mui/material/Button';
import { Option } from '@components/common/form/ReferenceField';
import FilterIconButton from 'src/components/FilterIconButton';
import useFiltersState from 'src/utils/filters/useFiltersState';
import { emptyFilterGroup, getDefaultFilterObject, useFilterDefinition } from 'src/utils/filters/filtersUtils';
import { FormControlLabel, Switch } from '@mui/material';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { useFormatter } from '../../../../components/i18n';

type FileImportMarkingSelectionPopupProps = {
  closePopup: () => void;
  handleUpload: (fileMarkings: string[], associatedEntityId: string | undefined) => void;
  isOpen: boolean
  entityId: string
};

export type SubmittedMarkingsType = {
  fileMarkings: Option[];
};

const FileImportMarkingSelectionPopup = ({ closePopup, handleUpload, isOpen, entityId }: FileImportMarkingSelectionPopupProps) => {
  const { t_i18n } = useFormatter();
  const defaultInstanceTriggerFilters = {
    ...emptyFilterGroup,
    filters: [getDefaultFilterObject('connectedToId', useFilterDefinition('connectedToId', ['Instance']))],
  };
  const [associatedEntityFilters, associatedEntityFiltersHelpers] = useFiltersState(defaultInstanceTriggerFilters, defaultInstanceTriggerFilters);
  const [associateWithEntity, setAssociateWithEntity] = useState(false);

  const handleSubmit = (values: SubmittedMarkingsType) => {
    const fileMarkings = values.fileMarkings.map(({ value }) => value);
    closePopup();
    if (entityId !== undefined) {
      handleUpload(fileMarkings, entityId);
    } else if (associateWithEntity) {
      handleUpload(fileMarkings, associatedEntityFilters.filters[0].values[0]);
    } else {
      handleUpload(fileMarkings, undefined); // if no entityID and not associated with entity, upload as global
    }
  };

  return (
    <>
      <Formik
        enableReinitialize={true}
        initialValues={{
          fileMarkings: [],
        }}
        onSubmit={handleSubmit}
      >
        {({ resetForm, submitForm, setFieldValue }) => (
          <Dialog open={isOpen} fullWidth={true} PaperProps={{ elevation: 1 }} onClose={() => {
            resetForm();
            closePopup();
          }}
          >
            <DialogTitle>{t_i18n('Select file marking definitions')}</DialogTitle>
            <DialogContent>
              <ObjectMarkingField
                name="fileMarkings"
                label={t_i18n('File marking definition levels')}
                style={fieldSpacingContainerStyle}
                setFieldValue={setFieldValue}
              />
              {!entityId
                && (
                  <div style={{ paddingTop: '10px' }}>
                    <FormControlLabel control=
                      {
                        <Switch
                          checked={associateWithEntity}
                          onChange={(event: React.ChangeEvent<HTMLInputElement>) => setAssociateWithEntity(event.target.checked)}
                        />
                      }
                      label={t_i18n('Add related entity')}
                    />
                    {associateWithEntity && (
                      <FilterIconButton
                        filters={associatedEntityFilters}
                        redirection
                        entityTypes={['Instance']}
                        helpers={{
                          ...associatedEntityFiltersHelpers,
                          handleSwitchLocalMode: () => undefined, // connectedToId filter can only have the 'or' local mode
                        }}
                        filtersRestrictions={{ preventLocalModeSwitchingFor: ['connectedToId'], preventRemoveFor: ['connectedToId'] }}
                        noMultiSelect
                      />
                    )}
                  </div>
                )}
            </DialogContent>
            <DialogActions>
              <Button onClick={() => {
                resetForm();
                closePopup();
              }}
              >
                {t_i18n('Cancel')}
              </Button>
              <Button
                color="secondary"
                onClick={submitForm}
              >
                {t_i18n('Validate')}
              </Button>
            </DialogActions>
          </Dialog>
        )}
      </Formik>
    </>
  );
};

export default FileImportMarkingSelectionPopup;
