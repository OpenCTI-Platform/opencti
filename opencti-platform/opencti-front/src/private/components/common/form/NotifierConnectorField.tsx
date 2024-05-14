import React, { FunctionComponent, useState } from 'react';
import { Field } from 'formik';
import makeStyles from '@mui/styles/makeStyles';
import { graphql } from 'react-relay';
import { fetchQuery } from '../../../../relay/environment';
import AutocompleteField from '../../../../components/AutocompleteField';
import { useFormatter } from '../../../../components/i18n';
import { NotifierConnectorFieldSearchQuery$data } from './__generated__/NotifierConnectorFieldSearchQuery.graphql';
import ItemIcon from '../../../../components/ItemIcon';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
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

interface NotifierConnectorFieldProps {
  name: string;
  style?: { marginTop: number };
  helpertext?: string;
  disabled?: boolean;
  onChange?: (
    name: string,
    value: { label: string; value: string; schema: string },
  ) => void;
  required?: boolean;
}

const NotifierConnectorFieldQuery = graphql`
  query NotifierConnectorFieldSearchQuery {
    connectorsForNotification {
      id
      name
      connector_schema
      connector_schema_ui
    }
  }
`;

const NotifierConnectorField: FunctionComponent<
NotifierConnectorFieldProps
> = ({ name, style, onChange, disabled, helpertext, required = false }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();

  const [connectors, setConnectors] = useState<
  { label: string | undefined; value: string | undefined }[]
  >([]);

  const searchNotifierConnectors = (
    event: React.ChangeEvent<HTMLInputElement>,
  ) => {
    fetchQuery(NotifierConnectorFieldQuery, {
      search: event && event.target.value ? event.target.value : '',
    })
      .toPromise()
      .then((data) => {
        const notifierConnectors = (
          (data as NotifierConnectorFieldSearchQuery$data)
            ?.connectorsForNotification ?? []
        ).map((n) => ({
          label: n?.name,
          value: n?.id,
          schema: n?.connector_schema,
          ui_schema: n?.connector_schema_ui,
        }));
        setConnectors(notifierConnectors);
      });
  };

  return (
    <div style={{ width: '100%' }}>
      <Field
        component={AutocompleteField}
        name={name}
        multiple={false}
        style={style}
        disabled={disabled}
        onChange={onChange}
        textfieldprops={{
          variant: 'standard',
          label: t_i18n('Notification connector'),
          helperText: helpertext,
          onFocus: searchNotifierConnectors,
          required,
        }}
        noOptionsText={t_i18n('No available options')}
        options={connectors}
        onInputChange={searchNotifierConnectors}
        renderOption={(
          props: React.HTMLAttributes<HTMLLIElement>,
          option: { label: string },
        ) => (
          <li {...props}>
            <div className={classes.icon }>
              <ItemIcon type="Notifier" />
            </div>
            <div className={classes.text}>{option.label}</div>
          </li>
        )}
        classes={{ clearIndicator: classes.autoCompleteIndicator }}
      />
    </div>
  );
};

export default NotifierConnectorField;
