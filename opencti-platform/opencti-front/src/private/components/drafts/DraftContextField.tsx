import React, { FunctionComponent } from 'react';
import { Option } from '@components/common/form/ReferenceField';
import { Field } from 'formik';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { DraftContextFieldQuery } from '@components/drafts/__generated__/DraftContextFieldQuery.graphql';
import Loader, { LoaderVariant } from '../../../components/Loader';
import { useFormatter } from '../../../components/i18n';
import AutocompleteField from '../../../components/AutocompleteField';
import { fieldSpacingContainerStyle } from '../../../utils/field';
import ItemIcon from '../../../components/ItemIcon';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';

interface DraftContextFieldProps {
  onChange: (name: string, value: string) => void;
  queryRef: PreloadedQuery<DraftContextFieldQuery>;
}

const draftContextFieldQuery = graphql`
  query DraftContextFieldQuery {
    draftWorkspaces {
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
  queryRef,
}) => {
  const { t_i18n } = useFormatter();
  const { draftWorkspaces } = usePreloadedQuery<DraftContextFieldQuery>(
    draftContextFieldQuery,
    queryRef,
  );

  return (
    <Field
      component={AutocompleteField}
      name="workspace_context"
      multiple={false}
      onChange={(name: string, value: Option) => onChange(name, value?.value ?? null)}
      isOptionEqualToValue={(option: Option, { value }: Option) => option.value === value}
      textfieldprops={{
        variant: 'standard',
        label: t_i18n('Drafts'),
        fullWidth: true,
      }}
      options={(draftWorkspaces?.edges ?? []).map(({ node: { id, name } }) => ({
        value: id,
        label: name,
      }))}
      style={fieldSpacingContainerStyle}
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
            <ItemIcon type='workspace_context' />
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

const DraftField: FunctionComponent<Omit<DraftContextFieldProps, 'queryRef'>> = (props) => {
  const queryRef = useQueryLoading<DraftContextFieldQuery>(draftContextFieldQuery);
  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <DraftContextField {...props} queryRef={queryRef} />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement} />
  );
};

export default DraftField;
