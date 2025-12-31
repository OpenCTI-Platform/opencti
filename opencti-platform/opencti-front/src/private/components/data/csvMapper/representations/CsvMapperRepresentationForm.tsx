import React, { FunctionComponent, useState } from 'react';
import { Field, FieldProps } from 'formik';
import CsvMapperRepresentationAttributesForm from '@components/data/csvMapper/representations/attributes/CsvMapperRepresentationAttributesForm';
import MUIAutocomplete from '@mui/material/Autocomplete';
import { SelectChangeEvent } from '@mui/material/Select';
import TextField from '@mui/material/TextField';
import makeStyles from '@mui/styles/makeStyles';
import Tooltip from '@mui/material/Tooltip';
import { Accordion, AccordionDetails } from '@mui/material';
import { DeleteOutlined, ExpandMoreOutlined } from '@mui/icons-material';
import Typography from '@mui/material/Typography';
import AccordionSummary from '@mui/material/AccordionSummary';
import classNames from 'classnames';
import { representationLabel } from '@components/data/csvMapper/representations/RepresentationUtils';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import { CsvMapperRepresentationFormData } from '@components/data/csvMapper/representations/Representation';
import CsvMapperConditionalEntityMapping from '@components/data/csvMapper/representations/CsvMapperConditionalEntityMapping';
import { useFormatter } from '../../../../../components/i18n';
import ItemIcon from '../../../../../components/ItemIcon';
import type { Theme } from '../../../../../components/Theme';
import useDeletion from '../../../../../utils/hooks/useDeletion';
import DeleteDialog from '../../../../../components/DeleteDialog';
import { FieldOption } from '../../../../../utils/field';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
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
  container: {
    display: 'inline-flex',
    alignItems: 'center',
  },
  red: {
    borderColor: 'rgb(244, 67, 54)',
  },
}));

export interface RepresentationFormEntityOption extends FieldOption {
  type: string;
  id: string;
}

interface CsvMapperRepresentationFormProps
  extends FieldProps<CsvMapperRepresentationFormData> {
  index: number;
  availableTypes: { value: string; type: string; id: string; label: string }[];
  handleRepresentationErrors: (key: string, value: boolean) => void;
  prefixLabel: string;
  onDelete: () => void;
  selectedOption: string;
}

const CsvMapperRepresentationForm: FunctionComponent<
  CsvMapperRepresentationFormProps
> = ({
  form,
  field,
  index,
  availableTypes = [],
  handleRepresentationErrors,
  prefixLabel,
  onDelete,
}) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();

  const { name, value } = field;
  const { setFieldValue } = form;

  const deletion = useDeletion({});
  const { setDeleting, handleCloseDelete, handleOpenDelete } = deletion;

  // -- ERRORS --
  const [hasError, setHasError] = useState<boolean>(false);
  let errors: Map<string, string> = new Map();
  const handleErrors = (key: string, val: string | null) => {
    errors = { ...errors, [key]: val };
    const hasErrors = Object.values(errors).filter((v) => v !== null).length > 0;
    setHasError(hasErrors);
    handleRepresentationErrors(value.id, hasErrors);
  };

  // -- EVENTS --

  const handleChangeEntityType = async (option: FieldOption | null) => {
    const newValue: CsvMapperRepresentationFormData = {
      ...value,
      attributes: {},
      target_type: option?.value ?? undefined,
    };
    await setFieldValue(name, newValue);
  };

  const deleteRepresentation = async () => {
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
        className={classNames({
          [classes.red]: hasError,
        })}
      >
        <AccordionSummary expandIcon={<ExpandMoreOutlined />} onClick={toggle}>
          <div className={classes.container}>
            <Typography>
              {representationLabel(index, value, t_i18n)}
            </Typography>
            <Tooltip title={t_i18n('Delete')}>
              <IconButton
                variant="tertiary"
                intent="destructive"
                onClick={handleOpenDelete}
              >
                <DeleteOutlined fontSize="small" />
              </IconButton>
            </Tooltip>
          </div>
        </AccordionSummary>
        <AccordionDetails style={{ width: '100%' }}>
          <>
            <MUIAutocomplete<RepresentationFormEntityOption>
              selectOnFocus
              openOnFocus
              autoHighlight
              getOptionLabel={(option) => t_i18n(`${prefixLabel}${option.label}`)}
              noOptionsText={t_i18n('No available options')}
              options={availableTypes}
              groupBy={(option) => t_i18n(option.type) ?? t_i18n('Unknown')}
              value={availableTypes.find((e) => e.id === value.target_type) || null}
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
            <div style={{ marginTop: 20 }}>
              {field.name.startsWith('entity_representation') && (
                <Field
                  component={CsvMapperConditionalEntityMapping}
                  representation={value}
                  representationName={name}
                />
              )}
              <CsvMapperRepresentationAttributesForm
                handleErrors={handleErrors}
                representation={value}
                representationName={name}
              />
            </div>
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
        submitDelete={deleteRepresentation}
        message={t_i18n('Do you want to delete this representation?')}
      />
    </>
  );
};

export default CsvMapperRepresentationForm;
