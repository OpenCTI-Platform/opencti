import React, { useEffect, useMemo, useState } from 'react';
import { Field } from 'formik';
import { fetchQuery } from '../../../../relay/environment';
import AutocompleteField from '../../../../components/AutocompleteField';
import IdentityCreation from '../identities/IdentityCreation';
import { identitySearchIdentitiesSearchQuery } from '../identities/IdentitySearch';
import ItemIcon from '../../../../components/ItemIcon';
import type { IdentitySearchIdentitiesSearchQuery$data } from '@components/common/identities/__generated__/IdentitySearchIdentitiesSearchQuery.graphql';
import { canUse } from '../../../../utils/authorizedMembers';
import { useFormatter } from '../../../../components/i18n';
import useHelper from '../../../../utils/hooks/useHelper';
import { FieldOption } from '../../../../utils/field';

interface CreatedByFieldProps {
  name: string;
  style?: React.CSSProperties;
  label?: string;
  setFieldValue: (field: string, value: FieldOption) => void;
  onChange?: (name: string, value: FieldOption) => void;
  helpertext?: React.ReactNode;
  disabled?: boolean;
  dryrun?: boolean;
  required?: boolean;
  defaultCreatedBy?: {
    id: string;
    name: string;
    entity_type: string;
  };
}

const CreatedByField = ({
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
}: CreatedByFieldProps) => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const featureFlagAccessRestriction = isFeatureEnable('ACCESS_RESTRICTION_CAN_USE');

  const [identityCreation, setIdentityCreation] = useState(false);
  const [keyword, setKeyword] = useState('');
  const [debouncedKeyword, setDebouncedKeyword] = useState(keyword);

  const [identities, setIdentities] = useState<IdentityOption[]>(
    defaultCreatedBy
      ? [
          {
            label: defaultCreatedBy.name,
            value: defaultCreatedBy.id,
            type: defaultCreatedBy.entity_type,
            entity: defaultCreatedBy,
          },
        ]
      : [],
  );

  /* -------------------------------- Debounce -------------------------------- */

  useEffect(() => {
    const handler = setTimeout(() => {
      setDebouncedKeyword(keyword);
    }, 1500);

    return () => clearTimeout(handler);
  }, [keyword]);

  /* ---------------------------- Identity search ------------------------------ */

  const searchIdentities = async () => {
    const data = (await fetchQuery(identitySearchIdentitiesSearchQuery, {
      types: ['Individual', 'Organization', 'System'],
      search: debouncedKeyword,
      first: 10,
    }).toPromise()) as IdentitySearchIdentitiesSearchQuery$data;

    const edges = data?.identities?.edges ?? [];

    const mapped = edges
      .filter((edge) => {
        if (!featureFlagAccessRestriction) return true;

        const rights = [
          edge?.node.currentUserAccessRight,
          ...(edge?.node.organizations?.edges?.map(
            (o) => o.node.currentUserAccessRight,
          ) ?? []),
        ];

        return !edge?.node.currentUserAccessRight || canUse(rights);
      })
      .map((edge) => ({
        label: edge?.node.name,
        value: edge?.node.id,
        type: edge?.node.entity_type,
        entity: edge?.node,
      }))
      .filter((edge) => edge.label && edge.value);

    setIdentities((prev) => {
      const map = new Map(prev.map((i) => [i.value, i]));
      mapped.forEach((i) => map.set(i.value, i));
      return Array.from(map.values());
    });
  };

  useEffect(() => {
    if (debouncedKeyword) {
      searchIdentities();
    }
  }, [debouncedKeyword]);

  /* -------------------------------- Handlers -------------------------------- */

  const handleSearch = (_: unknown, value?: string) => {
    if (value) {
      setKeyword(value);
    }
  };

  /* ------------------------------- Rendering -------------------------------- */

  const sortedOptions = useMemo(
    () => [...identities].sort((a, b) => a.label.localeCompare(b.label)),
    [identities],
  );

  return (
    <>
      <Field
        component={AutocompleteField}
        name={name}
        style={style}
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
        options={sortedOptions}
        onInputChange={handleSearch}
        openCreate={() => setIdentityCreation(true)}
        onChange={typeof onChange === 'function' ? onChange : null}
        renderOption={(props: React.HTMLAttributes<HTMLLIElement>, option: FieldOption) => (
          <li {...props}>
            <span
              style={{
                paddingTop: 4,
                display: 'inline-block',
                color: 'primary.main',
              }}
            >
              <ItemIcon type={option.type} />
            </span>
            <span
              style={{
                display: 'inline-block',
                flexGrow: 1,
                marginLeft: 10,
              }}
            >
              {option.label}
            </span>
          </li>
        )}
        classes={{ clearIndicator: { display: 'none' } }}
      />

      <IdentityCreation
        contextual
        onlyAuthors
        inputValue={keyword}
        open={identityCreation}
        handleClose={() => setIdentityCreation(false)}
        dryrun={dryrun}
        creationCallback={(data: any) => {
          const value = {
            label: data.identityAdd.name,
            value: data.identityAdd.id,
            type: data.identityAdd.entity_type,
            entity: data.identityAdd,
          };

          setFieldValue(name, value);
          onChange?.(name, value);
        }}
      />
    </>
  );
};

export default CreatedByField;
