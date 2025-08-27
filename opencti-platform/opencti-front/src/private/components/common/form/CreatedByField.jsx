import React, { useEffect, useState } from 'react';
import { filter, map, pathOr, pipe, union } from 'ramda';
import { debounce } from 'rxjs/operators';
import { Subject, timer } from 'rxjs';
import { Field } from 'formik';
import makeStyles from '@mui/styles/makeStyles';
import { fetchQuery } from '../../../../relay/environment';
import AutocompleteField from '../../../../components/AutocompleteField';
import IdentityCreation from '../identities/IdentityCreation';
import { identitySearchIdentitiesSearchQuery } from '../identities/IdentitySearch';
import ItemIcon from '../../../../components/ItemIcon';
import { canUse } from '../../../../utils/authorizedMembers';
import { useFormatter } from '../../../../components/i18n';

const SEARCH$ = new Subject().pipe(debounce(() => timer(1500)));

const useStyles = makeStyles((theme) => ({
  icon: {
    paddingTop: 4,
    display: 'inline-block',
    color: theme.palette.primary.main,
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

const CreatedByField = (props) => {
  const {
    name,
    style,
    label,
    setFieldValue,
    onChange,
    helpertext,
    disabled,
    dryrun,
    required = false,
    defaultCreatedBy,
  } = props;
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const [identityCreation, setIdentityCreation] = useState(false);
  const [keyword, setKeyword] = useState('');
  const [identities, setIdentities] = useState(defaultCreatedBy
    ? [
      {
        label: defaultCreatedBy.name,
        value: defaultCreatedBy.id,
        type: defaultCreatedBy.entity_type,
        entity: defaultCreatedBy,
      },
    ]
    : []);

  const searchIdentities = () => {
    fetchQuery(identitySearchIdentitiesSearchQuery, {
      types: ['Individual', 'Organization', 'System'],
      search: keyword,
      first: 10,
    })
      .toPromise()
      .then((data) => {
        const resultIdentities = pipe(
          pathOr([], ['identities', 'edges']),
          filter((n) => !('currentUserAccessRight' in n.node) || canUse([n.node.currentUserAccessRight, ...(n.node.organizations?.edges.map((o) => o.node.currentUserAccessRight)) ?? []])),
          map((n) => ({
            label: n.node.name,
            value: n.node.id,
            type: n.node.entity_type,
            entity: n.node,
          })),
        )(data);
        setIdentities(union(identities, resultIdentities));
      });
  };

  useEffect(() => {
    const subscription = SEARCH$.subscribe({
      next: () => searchIdentities(),
    });
    return () => {
      subscription.unsubscribe();
    };
  }, []);

  const handleSearch = (event) => {
    if (event && event.target && event.target.value) {
      setKeyword(event.target.value);
      SEARCH$.next({ action: 'Search' });
    }
  };

  const handleOpenIdentityCreation = () => {
    setIdentityCreation(true);
  };

  const handleCloseIdentityCreation = () => {
    setIdentityCreation(false);
  };
  return (
    <>
      <Field
        component={AutocompleteField}
        style={style}
        name={name}
        required={required}
        disabled={disabled}
        textfieldprops={{
          variant: 'standard',
          label: label ?? t_i18n('Author'),
          helperText: helpertext,
          onFocus: searchIdentities,
          required,
        }}
        noOptionsText={t_i18n('No available options')}
        options={identities.sort((a, b) => a.label.localeCompare(b.label))}
        onInputChange={handleSearch}
        openCreate={handleOpenIdentityCreation}
        onChange={typeof onChange === 'function' ? onChange : null}
        renderOption={({ key, ...innerProps }, option) => (
          <li key={key} {...innerProps}>
            <div className={classes.icon}>
              <ItemIcon type={option.type} />
            </div>
            <div className={classes.text}>{option.label}</div>
          </li>
        )}
        classes={{ clearIndicator: classes.autoCompleteIndicator }}
      />
      <IdentityCreation
        contextual={true}
        onlyAuthors={true}
        inputValue={keyword}
        open={identityCreation}
        handleClose={handleCloseIdentityCreation}
        dryrun={dryrun}
        creationCallback={(data) => {
          setFieldValue(name, {
            label: data.identityAdd.name,
            value: data.identityAdd.id,
            type: data.identityAdd.entity_type,
            entity: data.identityAdd,
          });
          if (typeof onChange === 'function') {
            onChange(name, {
              label: data.identityAdd.name,
              value: data.identityAdd.id,
              type: data.identityAdd.entity_type,
              entity: data.identityAdd,
            });
          }
        }}
      />
    </>
  );
};

export default CreatedByField;
