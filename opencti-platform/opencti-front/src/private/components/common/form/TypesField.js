import React, { useState } from 'react';
import { Field } from 'formik';
import * as R from 'ramda';
import { graphql } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { fetchQuery } from '../../../../relay/environment';
import AutocompleteField from '../../../../components/AutocompleteField';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';

const typesFieldTypesQuery = graphql`
  query TypesFieldTypesQuery {
    stixDomainObjectTypes: subTypes(type: "Stix-Domain-Object") {
      edges {
        node {
          id
          label
        }
      }
    }
    stixCyberObservableTypes: subTypes(type: "Stix-Cyber-Observable") {
      edges {
        node {
          id
          label
        }
      }
    }
    stixCoreRelationshipTypes: subTypes(type: "stix-core-relationship") {
      edges {
        node {
          id
          label
        }
      }
    }
    stixCyberObservableRelationshipTypes: subTypes(
      type: "stix-cyber-observable-relationship"
    ) {
      edges {
        node {
          id
          label
        }
      }
    }
    stixMetaRelationshipTypes: subTypes(type: "stix-meta-relationship") {
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

const TypesField = (props) => {
  const { types, name, label, style, helpertext, multiple } = props;
  const [dataTypes, setDataTypes] = useState([]);
  const classes = useStyles();
  const { t } = useFormatter();
  const searchTypes = () => {
    fetchQuery(typesFieldTypesQuery)
      .toPromise()
      .then((data) => {
        let finaltypes = [];
        if (types.includes('Stix-Domain-Object')) {
          finaltypes = R.union(
            finaltypes,
            data.stixDomainObjectTypes.edges.map((n) => ({
              label: t(`entity_${n.node.label}`),
              value: n.node.id,
            })),
          );
        }
        if (types.includes('Stix-Cyber-Observable')) {
          finaltypes = R.union(
            finaltypes,
            data.stixCyberObservableTypes.edges.map((n) => ({
              label: t(`entity_${n.node.label}`),
              value: n.node.id,
            })),
          );
        }
        if (types.includes('stix-core-relationship')) {
          finaltypes = R.union(
            finaltypes,
            data.stixCoreRelationshipTypes.edges.map((n) => ({
              label: t(`relationship_${n.node.label}`),
              value: n.node.id,
            })),
          );
        }
        if (types.includes('stix-cyber-observable-relationship')) {
          finaltypes = R.union(
            finaltypes,
            data.stixCyberObservableRelationshipTypes.edges.map((n) => ({
              label: t(`relationship_${n.node.label}`),
              value: n.node.id,
            })),
          );
        }
        if (types.includes('stix-meta-relationship')) {
          finaltypes = R.union(
            finaltypes,
            data.stixDomainObjectTypes.edges.map((n) => ({
              label: t(`relationship_${n.node.label}`),
              value: n.node.id,
            })),
          );
        }
        finaltypes = R.sortBy(R.prop('label'), finaltypes);
        setDataTypes(finaltypes);
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
        renderOption={(renderProps, option) => (
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
