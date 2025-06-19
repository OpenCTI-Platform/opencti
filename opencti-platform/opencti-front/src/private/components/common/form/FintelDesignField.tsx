import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React, { FunctionComponent } from 'react';
import { Field } from 'formik';
import { FintelDesignFieldQuery } from '@components/common/form/__generated__/FintelDesignFieldQuery.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import { useFormatter } from '../../../../components/i18n';
import AutocompleteField from '../../../../components/AutocompleteField';
import ItemIcon from '../../../../components/ItemIcon';
import Loader, { LoaderVariant } from '../../../../components/Loader';

const fintelDesignFieldQuery = graphql`
  query FintelDesignFieldQuery(
    $orderMode: OrderingMode,
    $orderBy: FintelDesignOrdering
    $filters: FilterGroup
  ) {
    fintelDesigns(
      orderMode: $orderMode
      orderBy: $orderBy
      filters: $filters
    ) {
      edges {
        node {
          id
          name
          file_id
          gradiantToColor
          gradiantFromColor
          textColor
        }
      }
    }
  }
`;

export interface FintelDesign {
  file_id: string | null | undefined,
  gradiantFromColor: string | null | undefined,
  gradiantToColor: string | null | undefined,
  textColor: string | null | undefined,
}

export type FintelDesignFieldOption = {
  label: string;
  value: FintelDesign
};

interface FintelDesignFieldComponentProps {
  label?: string
  name: string;
  style?: React.CSSProperties,
  helperText?: string;
  onChange?: (name: string, value: FieldOption[]) => void;
  required?: boolean
  queryRef: PreloadedQuery<FintelDesignFieldQuery>
}

const FintelDesignFieldComponent: FunctionComponent<FintelDesignFieldComponentProps> = ({
  label,
  name,
  style,
  helperText,
  onChange,
  required = false,
  queryRef,
}) => {
  const { t_i18n } = useFormatter();

  const data = usePreloadedQuery(fintelDesignFieldQuery, queryRef);
  const fintelDesigns = data.fintelDesigns?.edges?.map(({ node }) => ({ value: node, label: node?.name }));

  return (
    <div style={{ width: '100%' }}>
      <Field
        component={AutocompleteField}
        name={name}
        multiple={false}
        disabled={false}
        textfieldprops={{
          variant: 'standard',
          label: label ?? t_i18n('Fintel designs'),
          helperText,
        }}
        required={required}
        onChange={onChange}
        style={fieldSpacingContainerStyle ?? style}
        noOptionsText={t_i18n('No available options')}
        options={fintelDesigns}
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

const FintelDesignField = ({ ...props }: FintelDesignFieldProps) => {
  const queryRef = useQueryLoading<FintelDesignFieldQuery>(fintelDesignFieldQuery);
  const { name, label } = props;
  return queryRef ? (
    <React.Suspense fallback={
      <Field
        component={AutocompleteField}
        name={name}
        disabled={true}
        fullWidth={true}
        options={[]}
        renderOption={() => null}
        textfieldprops={{
          label,
        }}
      />
      }
    >
      <FintelDesignFieldComponent {...props} queryRef={queryRef} />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement} />
  );
};

export default FintelDesignField;
