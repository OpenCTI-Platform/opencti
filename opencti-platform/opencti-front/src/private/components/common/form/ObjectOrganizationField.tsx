import React, { CSSProperties, HTMLAttributes, SyntheticEvent, useState } from 'react';
import { Field } from 'formik';
import { graphql } from 'react-relay';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import { makeStyles } from '@mui/styles';
import { fetchQuery } from '../../../../relay/environment';
import AutocompleteField from '../../../../components/AutocompleteField';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import { Theme } from '../../../../components/Theme';
import { FieldOption } from '../../../../utils/field';
import { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import { ObjectOrganizationFieldQuery$data } from '@components/common/form/__generated__/ObjectOrganizationFieldQuery.graphql';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>(() => ({
  icon: {
    paddingTop: 4,
    display: 'inline-block',
  },
  text: {
    display: 'inline-block',
    flexGrow: 1,
    marginLeft: 10,
  },
  message: {
    width: '100%',
    overflow: 'hidden',
  },
  autoCompleteIndicator: {
    display: 'none',
  },
}));

export const searchObjectOrganizationFieldQuery = graphql`
  query ObjectOrganizationFieldQuery($search: String, $filters: FilterGroup) {
    organizations(orderBy: name, search: $search, filters: $filters) {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;

interface ObjectOrganizationFieldBaseProps {
  name: string;
  label: string;
  style: CSSProperties;
  helpertext?: string;
  disabled?: boolean;
  defaultOrganizations?: { name: string; id: string }[];
  outlined?: boolean;
  alert?: boolean;
  filters?: FilterGroup | null;
}

interface ObjectOrganizationFieldMultipleProps
  extends ObjectOrganizationFieldBaseProps {
  multiple?: true;
  onChange?: (
    name: string,
    value: FieldOption[],
    resetForm?: () => void,
  ) => void;
}

interface ObjectOrganizationFieldSingleProps
  extends ObjectOrganizationFieldBaseProps {
  multiple: false;
  onChange?: (
    name: string,
    value: FieldOption,
    resetForm?: () => void,
  ) => void;
}

type ObjectOrganizationFieldProps = ObjectOrganizationFieldMultipleProps | ObjectOrganizationFieldSingleProps;

const ObjectOrganizationField = ({
  name,
  label,
  style,
  onChange,
  helpertext,
  disabled,
  defaultOrganizations,
  outlined = true,
  multiple = true,
  alert = true,
  filters = null,
}: ObjectOrganizationFieldProps) => {
  const defaultStateOrganizations = (defaultOrganizations ?? []).map((n) => ({
    label: n.name,
    value: n.id,
  }));
  const [organizations, setOrganizations] = useState(defaultStateOrganizations);
  const classes = useStyles();
  const { t_i18n } = useFormatter();

  const searchOrganizations = (event?: SyntheticEvent<Element, Event>) => {
    if (event?.target instanceof HTMLInputElement) {
      fetchQuery(searchObjectOrganizationFieldQuery, {
        search: event.target.value ?? '',
        filters,
      })
        .toPromise()
        .then((data) => {
          const searchResults = (data as ObjectOrganizationFieldQuery$data).organizations?.edges.map((n) => ({
            label: n.node.name,
            value: n.node.id,
          }));
          setOrganizations(searchResults ?? []);
        });
    }
  };

  if (outlined === false) {
    return (
      <Field
        component={AutocompleteField}
        name={name}
        multiple={multiple}
        disabled={disabled}
        style={style}
        textfieldprops={{
          variant: 'standard',
          label: label ? t_i18n(label) : '',
          helperText: helpertext,
          onFocus: searchOrganizations,
        }}
        noOptionsText={t_i18n('No available options')}
        options={organizations}
        onInputChange={searchOrganizations}
        onChange={typeof onChange === 'function' ? onChange : null}
        renderOption={(
          renderProps: HTMLAttributes<HTMLLIElement>,
          option: { label: string },
        ) => (
          <li {...renderProps}>
            <div className={classes.icon}>
              <ItemIcon type="Organization" />
            </div>
            <div className={classes.text}>{option.label}</div>
          </li>
        )}
      />
    );
  }
  const FieldElement = (
    <Field
      component={AutocompleteField}
      name={name}
      multiple={multiple}
      style={style}
      disabled={disabled}
      textfieldprops={{
        variant: 'standard',
        label: t_i18n(label) ?? '',
        helperText: helpertext,
        onFocus: searchOrganizations,
      }}
      noOptionsText={t_i18n('No available options')}
      options={organizations}
      onInputChange={searchOrganizations}
      onChange={typeof onChange === 'function' ? onChange : null}
      renderOption={(
        renderProps: HTMLAttributes<HTMLLIElement>,
        option: { label: string },
      ) => (
        <li {...renderProps}>
          <div className={classes.icon}>
            <ItemIcon type="Organization" />
          </div>
          <div className={classes.text}>{option.label}</div>
        </li>
      )}
      classes={{ clearIndicator: classes.autoCompleteIndicator }}
    />
  );
  if (!alert) {
    return FieldElement;
  }
  return (
    <Alert
      severity="warning"
      variant="outlined"
      style={style}
      classes={{ message: classes.message }}
    >
      <AlertTitle>{t_i18n('Organizations restriction')}</AlertTitle>
      <div style={{ marginTop: 10 }}>{FieldElement}</div>
    </Alert>
  );
};

export default ObjectOrganizationField;
