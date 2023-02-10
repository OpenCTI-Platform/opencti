import React, { FunctionComponent, useState } from 'react';
import { Field } from 'formik';
import makeStyles from '@mui/styles/makeStyles';
import { graphql } from 'react-relay';
import { fetchQuery } from '../../../../relay/environment';
import AutocompleteField from '../../../../components/AutocompleteField';
import { useFormatter } from '../../../../components/i18n';
import { CreatorFieldSearchQuery$data } from './__generated__/CreatorFieldSearchQuery.graphql';
import ItemIcon from '../../../../components/ItemIcon';

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

interface CreatorFieldProps {
  name: string;
  label: string;
  onChange?: (name: string, value: unknown) => void;
  containerStyle?: Record<string, string | number>;
  helpertext?: string;
}

const CreatorFieldQuery = graphql`
  query CreatorFieldSearchQuery($search: String) {
    creators(search: $search) {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;

const CreatorField: FunctionComponent<CreatorFieldProps> = ({ name, label, containerStyle, onChange, helpertext }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const [creators, setCreators] = useState<
  {
    label: string | undefined;
    value: string | undefined;
  }[]
  >([]);

  const searchCreators = (event: React.ChangeEvent<HTMLInputElement>) => {
    fetchQuery(CreatorFieldQuery, {
      search: event && event.target.value ? event.target.value : '',
    })
      .toPromise()
      .then((data) => {
        const NewCreators = (
          (data as CreatorFieldSearchQuery$data)?.creators
            ?.edges ?? []
        ).map((n) => ({
          label: n?.node.name,
          value: n?.node.id,
        }));
        const templateValues = [...creators, ...NewCreators];
        // Keep only the unique list of options
        const uniqTemplates = templateValues.filter((item, index) => {
          return (
            templateValues.findIndex((e) => e.value === item.value) === index
          );
        });
        setCreators(uniqTemplates);
      });
  };

  return (
    <div style={{ width: '100%' }}>
      <Field
        component={AutocompleteField}
        name={name}
        textfieldprops={{
          variant: 'standard',
          label: t(label),
          helperText: helpertext,
          onFocus: searchCreators,
        }}
        onChange={onChange}
        style={containerStyle}
        noOptionsText={t('No available options')}
        options={creators}
        onInputChange={searchCreators}
        renderOption={(
          props: React.HTMLAttributes<HTMLLIElement>,
          option: { color: string; label: string },
        ) => (
          <li {...props}>
            <div className={classes.icon} style={{ color: option.color }}>
                <ItemIcon type="User" />
            </div>
            <div className={classes.text}>{option.label}</div>
          </li>
        )}
        classes={{ clearIndicator: classes.autoCompleteIndicator }}
      />
    </div>
  );
};

export default CreatorField;
