import React, { FunctionComponent, useEffect, useState } from 'react';
import { Formik } from 'formik';
import { useQueryLoader } from 'react-relay';
import CsvMapperRepresentationAttributesForm, {
  schemaAttributesQuery,
} from '@components/data/csvMapper/representations/attributes/CsvMapperRepresentationAttributesForm';
import * as R from 'ramda';
import MUIAutocomplete from '@mui/material/Autocomplete';
import { SelectChangeEvent } from '@mui/material/Select';
import TextField from '@mui/material/TextField';
import { Option } from '@components/common/form/ReferenceField';
import makeStyles from '@mui/styles/makeStyles';
import Tooltip from '@mui/material/Tooltip';
import { Accordion, AccordionDetails } from '@mui/material';
import { DeleteOutlined, ExpandMoreOutlined } from '@mui/icons-material';
import Typography from '@mui/material/Typography';
import AccordionSummary from '@mui/material/AccordionSummary';
import classNames from 'classnames';
import { representationLabel } from '@components/data/csvMapper/representations/RepresentationUtils';
import IconButton from '@mui/material/IconButton';
import Button from '@mui/material/Button';
import { Representation } from '@components/data/csvMapper/representations/Representation';
import { Attribute } from '@components/data/csvMapper/representations/attributes/Attribute';
import {
  CsvMapperRepresentationAttributesFormQuery,
} from '@components/data/csvMapper/representations/attributes/__generated__/CsvMapperRepresentationAttributesFormQuery.graphql';
import { useFormatter } from '../../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../../components/Loader';
import ItemIcon from '../../../../../components/ItemIcon';
import { Theme } from '../../../../../components/Theme';
import { isEmptyField } from '../../../../../utils/utils';

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

interface CsvMapperRepresentationFormProps {
  idx: number;
  availableEntityTypes: { value: string, type: string, id: string, label: string }[];
  representationData: Representation;
  representations: Representation[];
  onChange: (value: Representation) => void;
  onDelete: (value: Representation) => void;
  handleRepresentationErrors: (key: string, value: boolean) => void;
  prefixLabel: string;
}

const CsvMapperRepresentationForm: FunctionComponent<CsvMapperRepresentationFormProps> = ({
  idx,
  availableEntityTypes = [],
  representationData,
  representations,
  onChange,
  onDelete,
  handleRepresentationErrors,
  prefixLabel,
}) => {
  const { t } = useFormatter();
  const classes = useStyles();

  const [representation, setRepresentation] = useState<Representation>(representationData);
  const [inputValue, setInputValue] = useState(representationData.target.entity_type);

  // -- ERRORS --
  const [hasError, setHasError] = useState<boolean>(false);
  let errors: Map<string, string> = new Map();
  const handleErrors = (key: string, value: string | null) => {
    errors = { ...errors, [key]: value };
    const hasErrors = Object.values(errors).filter((v) => v !== null).length > 0;
    setHasError(hasErrors);
    handleRepresentationErrors(representation.id, hasErrors);
  };

  // -- EVENTS --

  const handleChange = (...changes: { name: string, value: string | Attribute[] }[]) => {
    let newRepresentation = representation;
    changes.forEach((change) => {
      newRepresentation = R.assocPath(change.name.split('.'), change.value, newRepresentation);
    });
    setRepresentation(newRepresentation);
    onChange(newRepresentation);
  };
  const handleChangeEntityType = (name: string, option: Option | null) => {
    if (option === null) {
      return;
    }
    const type = option.type === 'entity_Stix-Core-Relationship' ? 'relationship' : 'entity';
    const typeChange = { name: 'type', value: type };
    const { value } = option;
    setInputValue(value);
    handleChange({ name, value }, typeChange);
  };

  // -- ATTRIBUTES --

  const [queryRef, fetchLoadQuery] = useQueryLoader<CsvMapperRepresentationAttributesFormQuery>(
    schemaAttributesQuery,
  );

  useEffect(
    () => {
      if (representation.target.entity_type) {
        fetchLoadQuery({ entityType: representation.target.entity_type }, { fetchPolicy: 'store-and-network' });
      }
    },
    [representation.target.entity_type],
  );

  // -- ACCORDION --

  const [open, setOpen] = useState<boolean>(false);
  const toggle = () => {
    setOpen((oldValue) => {
      return !oldValue;
    });
  };

  // -- UTILS --

  const inputLabel = (value: string) => {
    const entityType = availableEntityTypes.find((entity) => entity.value === value);
    return isEmptyField(entityType) ? value : t(`${prefixLabel}${value}`);
  };

  // -- MUI Autocomplete --

  const searchType = (event: React.SyntheticEvent) => {
    const selectChangeEvent = event as SelectChangeEvent;
    const value = selectChangeEvent?.target.value ?? '';
    if (event !== null) {
      setInputValue(value);
    }
    return availableEntityTypes.filter((type) => type.value.includes(value) || t(`${prefixLabel}${type.label}`).includes(value));
  };

  return (
    <Accordion
      expanded={open}
      variant="outlined"
      style={{ width: '100%' }}
      className={classNames({
        [classes.red]: hasError,
      })}
    >
      <AccordionSummary
        expandIcon={<ExpandMoreOutlined />}
        onClick={toggle}
      >
        <div className={classes.container}>
          <Typography>
            {t(representationLabel(idx, representation))}
          </Typography>
          <Tooltip title={t('Delete')}>
            <IconButton
              color="error"
              onClick={() => onDelete(representation)}
            >
              <DeleteOutlined fontSize="small"/>
            </IconButton>
          </Tooltip>
        </div>
      </AccordionSummary>
      <AccordionDetails style={{ width: '100%' }}>
        <Formik
          key={representation.id}
          initialValues={representation}
          onSubmit={() => {}}
        >
          {() => (
            <>
              <MUIAutocomplete
                selectOnFocus={true}
                openOnFocus={true}
                autoSelect={false}
                autoHighlight={true}
                getOptionLabel={(option: Option) => t(`${prefixLabel}${option.label}`)}
                noOptionsText={t('No available options')}
                options={availableEntityTypes}
                groupBy={(option) => t(option.type) ?? t('Unknown')}
                inputValue={inputLabel(inputValue)}
                onInputChange={(event) => searchType(event)}
                onChange={(_, value) => handleChangeEntityType('target.entity_type', value)}
                renderInput={(params) => (
                  <TextField
                    {...params}
                    label={t('Entity type')}
                    variant="outlined"
                    size="small"
                  />
                )}
                renderOption={(props, option) => (
                  <li {...props}>
                    <div className={classes.icon}>
                      <ItemIcon type={option.label} />
                    </div>
                    <div className={classes.text}>{t(`${prefixLabel}${option.label}`)}</div>
                  </li>
                )}
              />
              {queryRef && (
                <React.Suspense
                  fallback={<Loader variant={LoaderVariant.inElement} />}
                >
                  <div style={{ marginTop: 20 }}>
                    <CsvMapperRepresentationAttributesForm
                      queryRef={queryRef}
                      entityType={representation.target.entity_type}
                      representations={representations}
                      attributes={representation.attributes}
                      setAttributes={(attributes) => handleChange({ name: 'attributes', value: attributes })}
                      handleErrors={handleErrors}
                    />
                  </div>
                </React.Suspense>
              )}
              <div style={{ textAlign: 'right', marginTop: '20px' }}>
                <Button
                  variant="contained"
                  color="error"
                  onClick={() => onDelete(representation)}
                >
                  {t('Delete')}
                </Button>
              </div>
            </>
          )}
        </Formik>
      </AccordionDetails>
    </Accordion>
  );
};
export default CsvMapperRepresentationForm;
