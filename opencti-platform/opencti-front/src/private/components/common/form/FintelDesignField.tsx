import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React, { FunctionComponent } from 'react';
import { Field } from 'formik';
import { FintelDesignFieldQuery } from '@components/common/form/__generated__/FintelDesignFieldQuery.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { FieldOption } from '../../../../utils/field';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import AutocompleteField from '../../../../components/AutocompleteField';
import ItemIcon from '../../../../components/ItemIcon';

const fintelDesignFieldQuery = graphql`
  query FintelDesignFieldQuery {
    fintelDesigns {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;

interface FintelDesignFieldComponentProps {
  onChange?: (name: string, value: FieldOption) => void;
  onSubmit?: (name: string, value: FieldOption) => void;
  containerStyle?: Record<string, string | number>;
  helpertext?: string;
  queryRef: PreloadedQuery<FintelDesignFieldQuery>;
  label?: string;
}

const FintelDesignFieldComponent: FunctionComponent<FintelDesignFieldComponentProps> = ({
  containerStyle,
  onChange,
  onSubmit,
  helpertext,
  queryRef,
  label,
}) => {
  const { t_i18n } = useFormatter();
  const data = usePreloadedQuery(fintelDesignFieldQuery, queryRef);
  const fintelDesignOptions = data.fintelDesigns?.edges?.map(({ node }) => ({
    value: node?.id,
    label: node?.name,
  }));

  return (
    <div style={{ width: '100%' }}>
      <Field
        component={AutocompleteField}
        name="fintelDesigns"
        multiple
        textfieldprops={{
          variant: 'standard',
          label: t_i18n(label ?? 'Fintel designs'),
          helperText: helpertext,
        }}
        onChange={(name: string, value: FieldOption) => {
          if (onChange) onChange(name, value);
          if (onSubmit) onSubmit(name, value);
        }}
        style={containerStyle}
        noOptionsText={t_i18n('No available options')}
        options={fintelDesignOptions}
        renderOption={(
          props: React.HTMLAttributes<HTMLLIElement>,
          option: { label: string },
        ) => (
          <li {...props} style={{ display: 'flex', alignItems: 'center' }}>
            <ItemIcon type="Fintel-Design" />
            <div style={{ flexGrow: 1, marginLeft: 10 }}>{option.label}</div>
          </li>
        )}
        classes={{ clearIndicator: { display: 'none' } }}
      />
    </div>
  );
};

type FintelDesignFieldProps = Omit<FintelDesignFieldComponentProps, 'queryRef'>;

const FintelDesignField: FunctionComponent<FintelDesignFieldProps> = (props) => {
  const queryRef = useQueryLoading<FintelDesignFieldQuery>(fintelDesignFieldQuery);
  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <FintelDesignFieldComponent {...props} queryRef={queryRef} />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement} />
  );
};

export default FintelDesignField;
