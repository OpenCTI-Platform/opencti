import { Accordion, AccordionDetails } from '@mui/material';
import React, { FunctionComponent, useState } from 'react';
import { DeleteOutlined, ExpandMoreOutlined } from '@mui/icons-material';
import AccordionSummary from '@mui/material/AccordionSummary';
import Typography from '@mui/material/Typography';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@common/button/IconButton';
import Button from '@common/button/Button';
import { SelectChangeEvent } from '@mui/material/Select';
import TextField from '@mui/material/TextField';
import MUIAutocomplete from '@mui/material/Autocomplete';
import { FieldProps } from 'formik';
import { OverrideFormData } from '@components/settings/users/edition/UserEditionConfidence';
import ConfidenceField from '@components/common/form/ConfidenceField';
import { useTheme } from '@mui/styles';
import { useFormatter } from '../../../../../components/i18n';
import useDeletion from '../../../../../utils/hooks/useDeletion';
import DeleteDialog from '../../../../../components/DeleteDialog';
import ItemIcon from '../../../../../components/ItemIcon';
import type { Theme } from '../../../../../components/Theme';
import { isEmptyField } from '../../../../../utils/utils';
import useSchema, { AvailableEntityOption } from '../../../../../utils/hooks/useSchema';

interface UserConfidenceOverridesFieldComponentProps
  extends FieldProps<OverrideFormData> {
  index: number;
  onDelete: () => void;
  onSubmit: (index: number, value: OverrideFormData | null) => void;
  currentOverrides: OverrideFormData[];
}

const filterOverridableEntityTypes = (entity_type: string | null) => {
  return entity_type !== 'entity_Stix-Meta-Objects' && entity_type !== 'entity_Stix-Cyber-Observables';
};

const ConfidenceOverrideField: FunctionComponent<UserConfidenceOverridesFieldComponentProps> = ({
  form,
  field,
  index,
  onDelete,
  onSubmit,
  currentOverrides,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const { availableEntityTypes } = useSchema();
  const entityTypesToOverride = availableEntityTypes.filter((entity_type) => filterOverridableEntityTypes(entity_type.type));
  const deletion = useDeletion({});
  const { setDeleting, handleCloseDelete, handleOpenDelete } = deletion;
  const { value, name } = field;
  const { setFieldValue } = form;

  const handleDeleteOverride = (event: React.MouseEvent) => {
    event.stopPropagation(); // to avoid open/close the accordion
    handleOpenDelete();
  };

  const handleSubmitDelete = async () => {
    onDelete(); // will remove from Formik values
    onSubmit(index, null);
    setDeleting(false);
    handleCloseDelete();
  };

  const handleSubmitEntityType = async (entityType: AvailableEntityOption | null) => {
    const newValue = entityType === null
      ? null : { entity_type: entityType.value, max_confidence: value.max_confidence };
    await setFieldValue(name, newValue);
    onSubmit(index, newValue);
  };

  const handleSubmitConfidence = async (_: string, maxConfidence: string) => {
    const newValue = { entity_type: value.entity_type, max_confidence: maxConfidence };
    await setFieldValue(name, newValue);
    onSubmit(index, newValue);
  };

  // -- ACCORDION --

  const [open, setOpen] = useState<boolean>(false);
  const toggle = () => {
    setOpen((oldValue) => {
      return !oldValue;
    });
  };

  // -- MUI Autocomplete --

  const searchType = (event: React.SyntheticEvent) => {
    const selectChangeEvent = event as SelectChangeEvent;
    const val = selectChangeEvent?.target.value ?? '';
    return entityTypesToOverride.filter(
      (type) => type.value.includes(val)
        || t_i18n(`entity_${type.label}`).includes(val),
    );
  };

  const overrideLabel = (
    idx: number,
    override: OverrideFormData,
  ) => {
    const number = `#${idx + 1}`;
    if (isEmptyField(override.entity_type)) {
      return `${number} ${t_i18n('New override of an entity')}`;
    }
    const label = `${t_i18n(`entity_${override.entity_type}`)}: ${override.max_confidence}`;
    return `${number} ${label[0].toUpperCase()}${label.slice(1)}`;
  };

  return (
    <>
      <Accordion
        expanded={open}
        variant="outlined"
        style={{ width: '100%', marginBottom: '20px' }}
      >
        <AccordionSummary expandIcon={<ExpandMoreOutlined />} onClick={toggle}>
          <div style={{ display: 'inline-flex', alignItems: 'center' }}>
            <Typography>
              {overrideLabel(index, value)}
            </Typography>
            <Tooltip title={t_i18n('Delete')}>
              <IconButton color="error" onClick={handleDeleteOverride}>
                <DeleteOutlined fontSize="small" />
              </IconButton>
            </Tooltip>
          </div>
        </AccordionSummary>
        <AccordionDetails style={{ width: '100%' }}>
          <>
            <MUIAutocomplete<AvailableEntityOption, false, boolean>
              selectOnFocus
              openOnFocus
              autoHighlight
              getOptionLabel={(option) => t_i18n(`entity_${option.label}`)}
              noOptionsText={t_i18n('No available options')}
              options={entityTypesToOverride}
              disableClearable
              getOptionDisabled={(option) => currentOverrides?.some((selectedOption) => selectedOption.entity_type === option.id)}
              groupBy={(option) => t_i18n(option.type) ?? t_i18n('Unknown')}
              value={entityTypesToOverride.find((e) => e.id === value.entity_type) || null}
              onInputChange={(event) => searchType(event)}
              onChange={(_, selectedValue) => handleSubmitEntityType(selectedValue)}
              renderInput={(params) => (
                <TextField
                  {...params}
                  label={t_i18n('Entity type')}
                  variant="outlined"
                  size="small"
                />
              )}
              // Need to ignore because there is a property key in the object but the
              // type given by MUI does not reference it
              // eslint-disable-next-line @typescript-eslint/ban-ts-comment
              // @ts-ignore
              renderOption={({ key, ...props }, option) => (
                // Separate key and other props because asked by React to avoid warnings.
                <li key={key} {...props}>
                  <div style={{
                    paddingTop: 4,
                    display: 'inline-block',
                    color: theme.palette.primary.main,
                  }}
                  >
                    <ItemIcon type={option.label} />
                  </div>
                  <div style={{
                    display: 'inline-block',
                    flexGrow: 1,
                    marginLeft: 10,
                  }}
                  >
                    {t_i18n(`entity_${option.label}`)}
                  </div>
                </li>
              )}
            />
            {value.entity_type && (
              <ConfidenceField
                name={`${name}.max_confidence`}
                entityType={value.entity_type}
                variant="edit"
                onSubmit={handleSubmitConfidence}
              />
            )}
            <div style={{ textAlign: 'right', marginTop: '20px' }}>
              <Button
                color="error"
                onClick={handleOpenDelete}
              >
                {t_i18n('Delete')}
              </Button>
            </div>
          </>
        </AccordionDetails>
      </Accordion>
      <DeleteDialog
        deletion={deletion}
        submitDelete={handleSubmitDelete}
        message={t_i18n('Do you want to delete this line?')}
      />
    </>
  );
};

export default ConfidenceOverrideField;
