import { Accordion, AccordionDetails } from '@mui/material';
import React, { FunctionComponent, useState } from 'react';
import { DeleteOutlined, ExpandMoreOutlined } from '@mui/icons-material';
import AccordionSummary from '@mui/material/AccordionSummary';
import Typography from '@mui/material/Typography';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@mui/material/IconButton';
import makeStyles from '@mui/styles/makeStyles';
import Button from '@mui/material/Button';
import { SelectChangeEvent } from '@mui/material/Select';
import TextField from '@mui/material/TextField';
import MUIAutocomplete from '@mui/material/Autocomplete';
import { FieldProps, useFormikContext } from 'formik';
import { ConfidenceFormData, Override } from '@components/settings/users/edition/UserEditionConfidence';
import ConfidenceField from '@components/common/form/ConfidenceField';
import { useFormatter } from '../../../../../components/i18n';
import useDeletion from '../../../../../utils/hooks/useDeletion';
import DeleteDialog from '../../../../../components/DeleteDialog';
import ItemIcon from '../../../../../components/ItemIcon';
import type { Theme } from '../../../../../components/Theme';
import { isEmptyField } from '../../../../../utils/utils';
import useSchema, { AvailableEntityOption } from '../../../../../utils/hooks/useSchema';

const useStyles = makeStyles<Theme>((theme) => ({
  container: {
    display: 'inline-flex',
    alignItems: 'center',
  },
  icon: {
    paddingTop: 4,
    display: 'inline-block',
    color: theme.palette.primary.main,
  },
  text: {
    display: 'inline-block',
    flexGrow: 1,
    marginLeft: 10,
  },
}));

export interface OverrideState {
  entity_type: string | null;
  max_confidence: string | null;
}

interface UserConfidenceOverridesFieldComponentProps
  extends FieldProps {
  index: number;
  onDelete: () => void;
  onSubmit: (index: number, value: OverrideState | null) => void;
}

const UserConfidenceOverrideField: FunctionComponent<UserConfidenceOverridesFieldComponentProps> = ({
  index,
  onDelete,
  onSubmit,
}) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const { availableEntityTypes } = useSchema();
  const deletion = useDeletion({});
  const { setDeleting, handleCloseDelete, handleOpenDelete } = deletion;
  const { values, setFieldValue } = useFormikContext<ConfidenceFormData>();
  const value = values.overrides[index];

  const handleDeleteOverride = (event: MouseEvent) => {
    event.stopPropagation(); // to avoid open/close the accordion
    handleOpenDelete();
  };

  const handleSubmitDelete = async () => {
    onDelete(); // will remove from Formik values
    onSubmit(index, null);
    setDeleting(false);
    handleCloseDelete();
  };

  const [state, setState] = useState<OverrideState>(value);

  const handleSubmitEntityType = async (newValue: AvailableEntityOption | null) => {
    await setFieldValue(`overrides[${index}].entity_type`, newValue?.value);
    setState((s) => ({ ...s, entity_type: newValue?.value }));
    onSubmit(index, newValue === null ? null : { entity_type: newValue.value, max_confidence: state.max_confidence ?? '0' });
  };

  const handleSubmitConfidence = async (name: string, newValue: string) => {
    await setFieldValue(`overrides[${index}].max_confidence`, newValue);
    setState((s) => ({ ...s, max_confidence: newValue }));
    onSubmit(index, { entity_type: state.entity_type, max_confidence: newValue });
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
    return availableEntityTypes.filter(
      (type) => type.value.includes(val)
        || t_i18n(`entity_${type.label}`).includes(val),
    );
  };

  const overrideLabel = (
    idx: number,
    override: Override,
  ) => {
    const number = `#${idx + 1}`;
    if (isEmptyField(override.entity_type)) {
      return `${number} ${t_i18n('New override of an entity')}`;
    }
    const label = `${t_i18n(`entity_${override.entity_type}`)}`;
    return `${number} ${label[0].toUpperCase()}${label.slice(1)}`;
  };

  return (
    <>
      <Accordion
        expanded={open}
        variant="outlined"
        style={{ width: '100%', marginBottom: '20px' }}
      >
        <AccordionSummary expandIcon={<ExpandMoreOutlined/>} onClick={toggle}>
          <div className={classes.container}>
            <Typography>
              {overrideLabel(index, value)}
            </Typography>
            <Tooltip title={t_i18n('Delete')}>
              <IconButton color="error" onClick={handleDeleteOverride}>
                <DeleteOutlined fontSize="small"/>
              </IconButton>
            </Tooltip>
          </div>
        </AccordionSummary>
        <AccordionDetails style={{ width: '100%' }}>
          <>
            <MUIAutocomplete<AvailableEntityOption>
              selectOnFocus
              openOnFocus
              autoHighlight
              getOptionLabel={(option) => t_i18n(`entity_${option.label}`)}
              noOptionsText={t_i18n('No available options')}
              options={availableEntityTypes}
              groupBy={(option) => t_i18n(option.type) ?? t_i18n('Unknown')}
              value={availableEntityTypes.find((e) => e.id === value.entity_type) || null}
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
              renderOption={(props, option) => (
                <li {...props}>
                  <div className={classes.icon}>
                    <ItemIcon type={option.label} />
                  </div>
                  <div className={classes.text}>
                    {t_i18n(`entity_${option.label}`)}
                  </div>
                </li>
              )}
            />
            {value.entity_type && (
              <ConfidenceField
                name={`overrides[${index}].max_confidence`}
                entityType={value.entity_type}
                variant="edit"
                onSubmit={handleSubmitConfidence}
              />
            )}
            <div style={{ textAlign: 'right', marginTop: '20px' }}>
              <Button
                variant="contained"
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
        title={t_i18n('Do you want to delete this line?')}
        deletion={deletion}
        submitDelete={handleSubmitDelete}
      />
    </>
  );
};

export default UserConfidenceOverrideField;
