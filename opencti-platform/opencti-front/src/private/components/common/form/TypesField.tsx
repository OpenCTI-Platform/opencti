import React, { FunctionComponent, useState } from 'react';
import { Field } from 'formik';
import { graphql } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { fetchQuery } from '../../../../relay/environment';
import AutocompleteField from '../../../../components/AutocompleteField';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import { TypesFieldTypesQuery$data } from './__generated__/TypesFieldTypesQuery.graphql';

interface SearchTypesProps {
  name: string,
  label: string,
  style: Record<string, string | number>,
  helpertext?: string,
  multiple: boolean,
  types: ('Stix-Domain-Object' | 'Stix-Cyber-Observable' | 'stix-core-relationship' | 'stix-cyber-observable-relationship' | 'stix-meta-relationship')[],
}

interface SearchOption {
  label: string,
  value: string
}

const typesFieldTypesQuery = graphql`
  query TypesFieldTypesQuery($isDomain: Boolean!, $isObservable: Boolean!, $isCoreRelationship: Boolean!,
    $isObservableRelationship: Boolean!, $isMetaRelationship: Boolean!) {
    stixDomainObjectTypes: subTypes(type: "Stix-Domain-Object") @include(if: $isDomain) {
      edges {
        node {
          id
          label
        }
      }
    }
    stixCyberObservableTypes: subTypes(type: "Stix-Cyber-Observable") @include(if: $isObservable) {
      edges {
        node {
          id
          label
        }
      }
    }
    stixCoreRelationshipTypes: subTypes(type: "stix-core-relationship") @include(if: $isCoreRelationship) {
      edges {
        node {
          id
          label
        }
      }
    }
    stixCyberObservableRelationshipTypes: subTypes(type: "stix-cyber-observable-relationship") @include(if: $isObservableRelationship) {
      edges {
        node {
          id
          label
        }
      }
    }
    stixMetaRelationshipTypes: subTypes(type: "stix-meta-relationship")  @include(if: $isMetaRelationship) {
      edges {
        node {
          id
          label
        }
      }
    }
  }
`;

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

const TypesField: FunctionComponent<SearchTypesProps> = ({ types, name, label, style, helpertext, multiple }) => {
  const [dataTypes, setDataTypes] = useState<SearchOption[]>([]);
  const classes = useStyles();
  const { t } = useFormatter();
  const optionBuilder = (type: string, data: { node: { id: string, label: string } }[]) => {
    return data.map((n) => ({
      label: t(`${type}_${n.node.label}`),
      value: n.node.id,
    }))
      .sort((a, b) => a.label.localeCompare(b.label))
      .filter(({ value }, index, arr) => arr.findIndex((o) => o.value === value) === index);
  };
  const searchTypes = () => {
    fetchQuery(typesFieldTypesQuery, {
      isDomain: types.includes('Stix-Domain-Object'),
      isObservable: types.includes('Stix-Cyber-Observable'),
      isCoreRelationship: types.includes('stix-core-relationship'),
      isObservableRelationship: types.includes('stix-cyber-observable-relationship'),
      isMetaRelationship: types.includes('stix-meta-relationship'),
    })
      .toPromise()
      .then((data) => {
        const fetchData = data as TypesFieldTypesQuery$data;
        const relationships = optionBuilder('relationship', [
          ...(fetchData.stixCoreRelationshipTypes?.edges ?? []),
          ...(fetchData.stixCyberObservableRelationshipTypes?.edges ?? []),
          ...(fetchData.stixMetaRelationshipTypes?.edges ?? []),
        ]);
        const entities = optionBuilder('entity', [
          ...(fetchData.stixDomainObjectTypes?.edges ?? []),
          ...(fetchData.stixCyberObservableTypes?.edges ?? []),
        ]);
        setDataTypes([...relationships, ...entities]);
      });
  };
  return (
    <div>
      <Field
        component={AutocompleteField}
        style={style}
        name={name}
        multiple={multiple}
        textfieldprops={{
          variant: 'standard',
          label: label || t('Types'),
          helperText: helpertext,
          onFocus: searchTypes,
        }}
        noOptionsText={t('No available options')}
        options={dataTypes}
        onInputChange={searchTypes}
        renderOption={(renderProps: object, option: SearchOption) => (
          <li {...renderProps}>
            <div className={classes.icon}>
              <ItemIcon type={option.value} />
            </div>
            <div className={classes.text}>{option.label}</div>
          </li>
        )}
        classes={{ clearIndicator: classes.autoCompleteIndicator }}
      />
    </div>
  );
};

export default TypesField;
