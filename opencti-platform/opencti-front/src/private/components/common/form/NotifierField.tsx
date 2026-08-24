import React, { FunctionComponent, useState } from 'react';
import { Field } from 'formik';
import makeStyles from '@mui/styles/makeStyles';
import { graphql } from 'react-relay';
import { fetchQuery } from '../../../../relay/environment';
import { ComboboxChangeMeta } from '@filigran/design-system';
import ComboboxField from '../../../../components/ComboboxField';
import { useFormatter } from '../../../../components/i18n';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import { NotifierFieldSearchQuery$data } from './__generated__/NotifierFieldSearchQuery.graphql';
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

interface NotifierFieldProps {
  label?: string;
  name: string;
  style?: { marginTop: number };
  helpertext?: string;
  onChange: (name: string, value: FieldOption[]) => void;
  required?: boolean;
}

export const NotifierFieldQuery = graphql`
  query NotifierFieldSearchQuery {
    notificationNotifiers {
      id
      name
      description
      notifier_connector {
        name
      }
    }
  }
`;

const NotifierField: FunctionComponent<NotifierFieldProps> = ({
  label,
  name,
  style,
  helpertext,
  onChange,
  required = false,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const [notifiersTemplates, setNotifiersTemplates] = useState<FieldOption[]>([]);
  const searchNotifiers = (search: string) => {
    fetchQuery(NotifierFieldQuery, { search })
      .toPromise()
      .then((data) => {
        const notifierOptions = (
          (data as NotifierFieldSearchQuery$data)?.notificationNotifiers ?? []
        )
          .map((n) => ({
            label: n.name,
            value: n.id,
            type: n.notifier_connector.name,
          }))
          .sort(({ type: aType }, { type: bType }) => aType.localeCompare(bType));
        setNotifiersTemplates(notifierOptions);
      });
  };

  return (
    <div style={{ width: '100%' }}>
      <Field
        component={ComboboxField}
        name={name}
        multiple={true}
        style={fieldSpacingContainerStyle ?? style}
        label={label ?? t_i18n('Notifiers')}
        helperText={helpertext}
        required={required}
        noOptionsText={t_i18n('No available options')}
        options={notifiersTemplates}
        // Fires on the keystroke only: `select`, `clear` and `reset` reach this
        // callback too, and querying on them is the bug the pre-library sites
        // guarded against by testing for a DOM event.
        onInputChange={(search: string, meta: ComboboxChangeMeta) => {
          if (meta.cause === 'type') searchNotifiers(search);
        }}
        onFocusInput={() => searchNotifiers('')}
        isOptionEqualToValue={(option: FieldOption, { value }: FieldOption) => option.value === value
        }
        onChange={onChange}
        groupBy={(option: FieldOption) => option.type}
        renderOption={(option: FieldOption) => (
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

export default NotifierField;
