import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { Field, useFormikContext } from 'formik';
import { InformationOutline } from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import { AttributeWithMetadata } from '@components/data/csvMapper/representations/attributes/Attribute';
import { CsvMapper } from '@components/data/csvMapper/CsvMapper';
import { useFormatter } from '../../../../../../components/i18n';
import TextField from '../../../../../../components/TextField';

const useStyles = makeStyles(() => ({
  container: {
    display: 'flex',
    justifyContent: 'right',
  },
}));

interface CsvMapperRepresentationAttributeOptionsProps {
  attribute: AttributeWithMetadata;
  indexRepresentation: number
}

const CsvMapperRepresentationAttributeOptions: FunctionComponent<CsvMapperRepresentationAttributeOptionsProps> = ({
  attribute,
  indexRepresentation,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();

  const formikContext = useFormikContext<CsvMapper>();
  const selectedAttributes = formikContext.values.representations[indexRepresentation].attributes;
  const indexAttribute = selectedAttributes.findIndex((a) => a.key === attribute.key);

  const onChange = (name: string, value: string) => {
    formikContext.setFieldValue(
      `representations[${indexRepresentation}].attributes[${indexAttribute}].column.configuration`,
      { [name]: value },
    );
  };

  // we disabled the option if the attribute is not in the mapper
  // user must select a column before being able to set an option
  const enabled = !!selectedAttributes.find((a) => a.key === attribute.key);

  return (
    <div>
      {attribute.type === 'date'
        && <div className={classes.container}>
          <Field style={{ margin: 0 }}
             disabled={!enabled}
             component={TextField}
             type="standard"
             name="pattern_date"
             value={selectedAttributes[indexAttribute]?.column?.configuration?.pattern_date || ''}
             onChange={onChange}
             placeholder={t('Date pattern')}
          />
          <Tooltip
            title={t(
              'By default we accept iso date (YYYY-MM-DD), but you can specify your own date format in ISO notation (for instance DD.MM.YYYY)',
            )}
          >
            <InformationOutline
              fontSize="small"
              color="primary"
              style={{ cursor: 'default' }}
            />
          </Tooltip>
        </div>
      }
      {attribute.multiple
        && <div className={classes.container}>
          <Field style={{ margin: 0 }}
             disabled={!enabled}
             component={TextField}
             type="standard"
             name="separator"
             value={selectedAttributes[indexAttribute]?.column?.configuration?.separator || ''}
             onChange={onChange}
             placeholder={t('List separator')}
          />
          <Tooltip
            title={t(
              'If this field contains multiple values, you can specify the separator used between each values (for instance | or +)',
            )}
          >
            <InformationOutline
              fontSize="small"
              color="primary"
              style={{ cursor: 'default' }}
            />
          </Tooltip>
        </div>
      }
    </div>
  );
};

export default CsvMapperRepresentationAttributeOptions;
