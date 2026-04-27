import React, { useState } from 'react';
import { Field } from 'formik';
import { graphql } from 'react-relay';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import { makeStyles } from '@mui/styles';
import { fetchQuery } from '../../../../relay/environment';
import AutocompleteField from '../../../../components/AutocompleteField';
import { useFormatter } from '../../../../components/i18n';
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
    marginInlineStart: 10,
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

const ObjectOrganizationField = (props) => {
  const {
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
  } = props;

  const defaultStateOrganizations = (defaultOrganizations ?? []).map((n) => ({
    label: n.name,
    value: n.id,
  }));
  const [organizations, setOrganizations] = useState(defaultStateOrganizations);
  const classes = useStyles();
  const { t_i18n } = useFormatter();

  const searchOrganizations = (event) => {
    fetchQuery(searchObjectOrganizationFieldQuery, {
      search: (event && event.target && event.target.value) ?? '',
      filters,
    })
      .toPromise()
      .then((data) => {
        const searchResults = data.organizations.edges.map((n) => ({
          label: n.node.name,
          value: n.node.id,
        }));
        setOrganizations(searchResults);
      });
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
        renderOption={(renderProps, option) => (
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
      renderOption={(renderProps, option) => (
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
