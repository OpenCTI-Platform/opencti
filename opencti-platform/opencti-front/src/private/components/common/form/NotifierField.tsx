import React, { FunctionComponent, useState } from 'react';
import { Field } from 'formik';
import makeStyles from '@mui/styles/makeStyles';
import { graphql } from 'react-relay';
import { fetchQuery } from '../../../../relay/environment';
import AutocompleteField from '../../../../components/AutocompleteField';
import { useFormatter } from '../../../../components/i18n';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { NotifierFieldSearchQuery$data } from './__generated__/NotifierFieldSearchQuery.graphql';
import { Option } from './ReferenceField';
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
  label?: string
  name: string;
  style?: { marginTop: number };
  helpertext?: string;
  onChange: (name: string, value: Option[]) => void;
  required?: boolean
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
  const [notifiersTemplates, setNotifiersTemplates] = useState<Option[]>([]);
  const searchNotifiers = (event: React.ChangeEvent<HTMLInputElement>) => {
    fetchQuery(NotifierFieldQuery, {
      search: event && event.target.value ? event.target.value : '',
    })
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
        component={AutocompleteField}
        name={name}
        multiple={true}
        style={fieldSpacingContainerStyle ?? style}
        textfieldprops={{
          variant: 'standard',
          label: label ?? t_i18n('Notifiers'),
          helperText: helpertext,
          onFocus: searchNotifiers,
        }}
        required={required}
        noOptionsText={t_i18n('No available options')}
        options={notifiersTemplates}
        onInputChange={searchNotifiers}
        isOptionEqualToValue={(option: Option, { value }: Option) => option.value === value
        }
        onChange={onChange}
        groupBy={(option: Option) => option.type}
        renderOption={(
          props: React.HTMLAttributes<HTMLLIElement>,
          option: Option,
        ) => (<li {...props} key={option.value}>
          <div className={classes.icon}>
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

export default NotifierField;
