import React, { FunctionComponent, useState } from 'react';
import { Option } from '@components/common/form/ReferenceField';
import { Field } from 'formik';
import { graphql } from 'react-relay';
import { DraftContextFieldQuery$data } from '@components/drafts/__generated__/DraftContextFieldQuery.graphql';
import { fetchQuery } from '../../../relay/environment';
import { useFormatter } from '../../../components/i18n';
import AutocompleteField from '../../../components/AutocompleteField';
import ItemIcon from '../../../components/ItemIcon';

interface DraftContextFieldProps {
  onChange: (name: string, value: string) => void;
}

const draftContextFieldQuery = graphql`
    query DraftContextFieldQuery($search: String, $first: Int) {
        draftWorkspaces(search: $search, first: $first) {
            edges {
                node {
                    id
                    name
                }
            }
        }
    }
`;

const DraftContextField: FunctionComponent<DraftContextFieldProps> = ({
  onChange,
}) => {
  const { t_i18n } = useFormatter();

  const [drafts, setDrafts] = useState<Option[]>([]);
  const searchDrafts = (event: React.ChangeEvent<HTMLInputElement>) => {
    fetchQuery(draftContextFieldQuery, {
      search: (event && event.target && event.target.value) ?? '',
      first: 10,
    })
      .toPromise()
      .then((data) => {
        const newDrafts = (
          (data as DraftContextFieldQuery$data)?.draftWorkspaces?.edges ?? []
        ).map((n) => ({
          label: n.node.name,
          value: n.node.id,
        }));
        setDrafts(newDrafts);
      });
  };

  return (
    <Field
      component={AutocompleteField}
      name="draft_context"
      multiple={false}
      onChange={(name: string, value: Option) => onChange(name, value?.value ?? null)}
      isOptionEqualToValue={(option: Option, { value }: Option) => option.value === value}
      textfieldprops={{
        variant: 'standard',
        label: t_i18n('Drafts'),
        fullWidth: true,
        onFocus: searchDrafts,
      }}
      options={drafts}
      onInputChange={searchDrafts}
      fullWidth={true}
      renderOption={(
        props: React.HTMLAttributes<HTMLLIElement>,
        option: Option,
      ) => (
        <li {...props}>
          <div style={{
            color: option.color,
            paddingTop: 4,
            display: 'inline-block',
          }}
          >
            <ItemIcon type='draft_context' />
          </div>
          <div style={{
            display: 'inline-block',
            flexGrow: 1,
            marginLeft: 10,
          }}
          >
            {option.label}
          </div>
        </li>
      )}
    />
  );
};

export default DraftContextField;
