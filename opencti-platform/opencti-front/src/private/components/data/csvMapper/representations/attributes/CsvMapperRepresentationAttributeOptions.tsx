import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { Field } from 'formik';
import { InformationOutline } from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import { Attribute } from '@components/data/csvMapper/representations/attributes/Attribute';
import { useFormatter } from '../../../../../../components/i18n';
import TextField from '../../../../../../components/TextField';

const useStyles = makeStyles(() => ({
  container: {
    display: 'flex',
    justifyContent: 'right',
  },
}));

interface CsvMapperRepresentationAttributeOptionsProps {
  attribute: Attribute;
  onChange: (attribute: Attribute, name: string, value: string | string[] | boolean | null) => void;
}

const CsvMapperRepresentationAttributeOptions: FunctionComponent<CsvMapperRepresentationAttributeOptionsProps> = ({
  attribute,
  onChange,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();

  return (
    <div>
      {attribute.type === 'date'
        && <div className={classes.container}>
          <Field style={{ margin: 0 }}
                 component={TextField}
                 type="standard"
                 name="column.configuration.pattern_date"
                 onChange={(name: string, value: string) => onChange(attribute, name, value)}
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
                 component={TextField}
                 type="standard"
                 name="column.configuration.separator"
                 onChange={(name: string, value: string) => onChange(attribute, name, value)}
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
