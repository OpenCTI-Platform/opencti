import React, { useState } from 'react';
import { pathOr, pipe, map, union, append } from 'ramda';
import { Field } from 'formik';
import { Label } from 'mdi-material-ui';
import makeStyles from '@mui/styles/makeStyles';
import { fetchQuery } from '../../../../relay/environment';
import AutocompleteField from '../../../../components/AutocompleteField';
import { statusTemplatesSearchQuery } from '../../settings/StatusTemplatesQuery';
import StatusTemplateCreation from '../../settings/workflow/StatusTemplateCreation';
import { useFormatter } from '../../../../components/i18n';

const useStyles = makeStyles(() => ({
  icon: {
    paddingTop: 4,
    display: 'inline-block',
  },
  text: {
    display: 'inline-block',
    flexGrow: 1,
    marginLeft: 10,
  },
  autoCompleteIndicator: {
    display: 'none',
  },
}));

const StatusTemplateField = ({ name, setFieldValue, helpertext }) => {
  const classes = useStyles();
  const { t } = useFormatter();

  const [statusTemplateCreation, setStatusTemplateCreation] = useState(false);
  const [statusTemplateInput, setStatusTemplateInput] = useState('');
  const [statusTemplates, setStatusTemplates] = useState([]);

  const handleOpenStatusTemplateCreation = () => setStatusTemplateCreation(true);

  const handleCloseStatusTemplateCreation = () => setStatusTemplateCreation(false);

  const searchStatusTemplates = (event) => {
    setStatusTemplateInput(event && event.target.value !== 0 ? event.target.value : '');
    fetchQuery(statusTemplatesSearchQuery, {
      search: event && event.target.value !== 0 ? event.target.value : '',
    })
      .toPromise()
      .then((data) => {
        const NewStatusTemplates = pipe(
          pathOr([], ['statusTemplates', 'edges']),
          map((n) => ({
            label: n.node.name,
            value: n.node.id,
            color: n.node.color,
          })),
        )(data);
        setStatusTemplates(union(statusTemplates, NewStatusTemplates));
      });
  };

  return (
    <div>
      <Field
        component={AutocompleteField}
        name={name}
        multiple={false}
        textfieldprops={{
          variant: 'standard',
          label: t('Name'),
          helperText: helpertext,
          onFocus: searchStatusTemplates,
        }}
        noOptionsText={t('No available options')}
        options={statusTemplates}
        onInputChange={searchStatusTemplates}
        openCreate={handleOpenStatusTemplateCreation}
        renderOption={(props, option) => (
          <li {...props}>
            <div className={classes.icon} style={{ color: option.color }}>
              <Label />
            </div>
            <div className={classes.text}>{option.label}</div>
          </li>
        )}
        classes={{ clearIndicator: classes.autoCompleteIndicator }}
      />
      <StatusTemplateCreation
        contextual={true}
        inputValueContextual={statusTemplateInput}
        openContextual={statusTemplateCreation}
        handleCloseContextual={handleCloseStatusTemplateCreation}
        creationCallback={(data) => {
          setFieldValue(
            name,
            append(
              {
                name: data.statusTemplateAdd.name,
                id: data.statusTemplateAdd.id,
              },
            ),
          );
        }}
      />
    </div>
  );
};

export default StatusTemplateField;
