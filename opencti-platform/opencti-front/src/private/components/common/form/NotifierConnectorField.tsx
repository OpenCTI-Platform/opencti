import React, { FunctionComponent, useState } from 'react';
import { Field } from 'formik';
import makeStyles from '@mui/styles/makeStyles';
import { graphql } from 'react-relay';
import { fetchQuery } from '../../../../relay/environment';
import { ComboboxChangeMeta } from '@filigran/design-system';
import ComboboxField from '../../../../components/ComboboxField';
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

  const searchNotifierConnectors = (search: string) => {
    fetchQuery(NotifierConnectorFieldQuery, { search })
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
        component={ComboboxField}
        // MUI hid its clear indicator here with display:none; the library defaults
        // clearable to true, so the affordance must be declined explicitly.
        name={name}
        multiple={false}
        style={style}
        disabled={disabled}
        onChange={onChange}
        label={t_i18n('Notification connector')}
        helperText={helpertext}
        required={required}
        noOptionsText={t_i18n('No available options')}
        options={connectors}
        // Fires on the keystroke only: `select`, `clear` and `reset` reach this callback too, and querying on them
        // is the bug the pre-library sites guarded against by testing for a DOM event.
        onInputChange={(search: string, meta: ComboboxChangeMeta) => {
          if (meta.cause === 'type') searchNotifierConnectors(search);
        }}
        onFocusInput={() => searchNotifierConnectors('')}
        renderOption={(option: { label: string }) => (
          <>
            <div className={classes.icon}>
              <ItemIcon type="Notifier" />
            </div>
            <div className={classes.text}>{option.label}</div>
          </>
        )}
      />
    </div>
  );
};

export default NotifierConnectorField;
