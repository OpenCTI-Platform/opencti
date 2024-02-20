import React, { FunctionComponent } from 'react';
import { Field } from 'formik';
import ListItemText from '@mui/material/ListItemText';
import makeStyles from '@mui/styles/makeStyles';
import AutocompleteField from '../../../../components/AutocompleteField';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import type { Theme } from '../../../../components/Theme';
import useAuth from '../../../../utils/hooks/useAuth';

const useStyles = makeStyles<Theme>((theme) => ({
  icon: {
    paddingTop: 4,
    paddingRight: 4,
    display: 'inline-block',
    color: theme.palette.primary.main,
  },
}));

interface ObservableTypesFieldProps {
  name: string;
  label: string;
  multiple?: boolean;
  onChange?: (name: string, value: string | string[]) => void;
  style?: Record<string, string | number>;
}
const ObservableTypesField: FunctionComponent<ObservableTypesFieldProps> = ({
  name,
  label,
  multiple,
  onChange,
  style,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();

  const { schema } = useAuth();
  const { scos } = schema;
  const allObservableTypes = scos.map((sco) => sco.id);

  return (
    <Field
      component={AutocompleteField}
      name={name}
      multiple={multiple || false}
      fullWidth={true}
      textfieldprops={{
        variant: 'standard',
        label,
      }}
      options={allObservableTypes}
      onChange={typeof onChange === 'function' ? onChange : null}
      isOptionEqualToValue={(option: string, value: string) => option === value}
      style={style}
      renderOption={(
        props: React.HTMLAttributes<HTMLLIElement>,
        option: string,
      ) => (
        <li {...props}>
          <div className={classes.icon}>
            <ItemIcon type={option} />
          </div>
          <ListItemText primary={t_i18n(`entity_${option}`)} />
        </li>
      )}
    />
  );
};

export default ObservableTypesField;
