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
import { FieldProps } from 'formik';
import { Option } from '@components/common/form/ReferenceField';
import { AvailableEntityOption } from '@components/settings/users/UserEditionConfidence';
import ConfidenceField from '@components/common/form/ConfidenceField';
import { useFormatter } from '../../../../components/i18n';
import useDeletion from '../../../../utils/hooks/useDeletion';
import DeleteDialog from '../../../../components/DeleteDialog';
import ItemIcon from '../../../../components/ItemIcon';
import type { Theme } from '../../../../components/Theme';

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

interface UserConfidenceOverridesFieldComponentProps
  extends FieldProps {
  index: number;
  availableTypes: { value: string; type: string; id: string; label: string }[];
  onDelete: () => void;
  prefixLabel: string;
}

const UserConfidenceOverridesField: FunctionComponent<UserConfidenceOverridesFieldComponentProps> = ({
  index,
  form,
  field,
  onDelete,
  availableTypes,
  prefixLabel,
}) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();

  const { name, value } = field;
  const { setFieldValue } = form;

  const deletion = useDeletion({});
  const { setDeleting, handleCloseDelete, handleOpenDelete } = deletion;

  // -- EVENTS --

  const handleChangeEntityType = async (option: Option | null) => {
    const newValue = {
      ...value,
      entity_type: option?.value,
    };
    await setFieldValue(name, newValue);
  };

  const deleteLine = async () => {
    onDelete();
    setDeleting(false);
    handleCloseDelete();
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
    return availableTypes.filter(
      (type) => type.value.includes(val)
        || t_i18n(`${prefixLabel}${type.label}`).includes(val),
    );
  };

  return (
    <>
      <Accordion
        expanded={open}
        variant="outlined"
        style={{ width: '100%' }}
      >
        <AccordionSummary expandIcon={<ExpandMoreOutlined/>} onClick={toggle}>
          <div className={classes.container}>
            <Typography>
              {index}
            </Typography>
            <Tooltip title={t_i18n('Delete')}>
              <IconButton color="error" onClick={handleOpenDelete}>
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
              getOptionLabel={(option) => t_i18n(`${prefixLabel}${option.label}`)}
              noOptionsText={t_i18n('No available options')}
              options={availableTypes}
              groupBy={(option) => t_i18n(option.type) ?? t_i18n('Unknown')}
              value={availableTypes.find((e) => e.id === value.entity_type) || null}
              onInputChange={(event) => searchType(event)}
              onChange={(_, val) => handleChangeEntityType(val)}
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
                    {t_i18n(`${prefixLabel}${option.label}`)}
                  </div>
                </li>
              )}
            />
            {value.entity_type && (
              <ConfidenceField
                name={`${name}.max_confidence`}
                entityType={value.entity_type}
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
        submitDelete={deleteLine}
      />
    </>
  );
};

export default UserConfidenceOverridesField;
