import React, { useEffect, useState } from 'react';
import { filter, map, pathOr, pipe, union } from 'ramda';
import { Field } from 'formik';
import makeStyles from '@mui/styles/makeStyles';
import { fetchQuery } from '../../../../relay/environment';
import ComboboxField from '../../../../components/ComboboxField';
import IdentityCreation from '../identities/IdentityCreation';
import { identitySearchIdentitiesSearchQuery } from '../identities/IdentitySearch';
import ItemIcon from '../../../../components/ItemIcon';
import { canUse } from '../../../../utils/authorizedMembers';
import { useFormatter } from '../../../../components/i18n';
import useHelper from '../../../../utils/hooks/useHelper';

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
    clearable = false,
  } = props;
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const featureFlagAccessRestriction = isFeatureEnable('ACCESS_RESTRICTION_CAN_USE');
  const [identityCreation, setIdentityCreation] = useState(false);
  const [keyword, setKeyword] = useState('');
  const [debouncedKeyword, setDebouncedKeyword] = useState(keyword); // Debounced value

  useEffect(() => {
    // Set a timeout to update debounced value after 500ms
    const handler = setTimeout(() => {
      setDebouncedKeyword(keyword);
    }, 1500);

    // Cleanup the timeout if `query` changes before 500ms
    return () => {
      clearTimeout(handler);
    };
  }, [keyword]);

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
      search: debouncedKeyword,
      first: 10,
    })
      .toPromise()
      .then((data) => {
        if (featureFlagAccessRestriction) {
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
        } else {
          const resultIdentities = pipe(
            pathOr([], ['identities', 'edges']),
            map((n) => ({
              label: n.node.name,
              value: n.node.id,
              type: n.node.entity_type,
              entity: n.node,
            })),
          )(data);
          setIdentities(union(identities, resultIdentities));
        }
      });
  };

  useEffect(() => {
    if (debouncedKeyword) {
      searchIdentities();
    }
  }, [debouncedKeyword]);

  const handleSearch = (search, meta) => {
    // Only a keystroke moves the keyword. Selecting, clearing or reopening also
    // report an input change, and each one used to re-run the identity search.
    if (meta.cause === 'type' && search) {
      setKeyword(search);
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
        component={ComboboxField}
        style={style}
        name={name}
        required={required}
        disabled={disabled}
        label={label ?? t_i18n('Author')}
        helperText={helpertext}
        clearable={clearable}
        noOptionsText={t_i18n('No available options')}
        options={identities.sort((a, b) => a.label.localeCompare(b.label))}
        onInputChange={handleSearch}
        onFocusInput={searchIdentities}
        onCreateOption={handleOpenIdentityCreation}
        onChange={typeof onChange === 'function' ? onChange : null}
        renderOption={(option) => (
          <>
            <div className={classes.icon}>
              <ItemIcon type={option.type} />
            </div>
            <div className={classes.text}>{option.label}</div>
          </>
        )}
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
