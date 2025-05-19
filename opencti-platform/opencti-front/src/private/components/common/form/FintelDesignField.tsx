import { graphql } from 'react-relay';
import React, { FunctionComponent, useState } from 'react';
import { Field } from 'formik';
import { FintelDesignFieldQuery$data } from '@components/common/form/__generated__/FintelDesignFieldQuery.graphql';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import { useFormatter } from '../../../../components/i18n';
import AutocompleteField from '../../../../components/AutocompleteField';
import ItemIcon from '../../../../components/ItemIcon';
import { fetchQuery } from '../../../../relay/environment';

type FintelDesignFieldOption = {
  label: string,
  value: string,
};

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
          description
          url
          gradiantFromColor
          gradiantToColor
          textColor
        }
      }
    }
  }
`;

interface FintelDesignFieldComponentProps {
  label?: string
  name: string;
  style?: React.CSSProperties,
  helpertext?: string;
  onChange: (name: string, value: FieldOption[]) => void;
  required?: boolean
}

const FintelDesignField: FunctionComponent<FintelDesignFieldComponentProps> = ({
  label,
  name,
  style,
  helpertext,
  onChange,
  required = false,
}) => {
  const { t_i18n } = useFormatter();

  const [fintelDesign, setFintelDesign] = useState<FintelDesignFieldOption[]>([]);

  const searchFintelDesigns = () => {
    fetchQuery(fintelDesignFieldQuery, { orderBy: 'name', orderMode: 'asc' })
      .toPromise()
      .then((data) => {
        const fintelDesignData = (data as FintelDesignFieldQuery$data).fintelDesigns?.edges ?? [];
        const fintel = fintelDesignData.map((n) => {
          const fintelLabel = n?.node?.name ?? '';
          return {
            label: fintelLabel,
            value: n?.node?.id ?? '',
          };
        });
        setFintelDesign(fintel);
      });
  };

  return (
    <div style={{ width: '100%' }}>
      <Field
        component={AutocompleteField}
        name={name}
        multiple={false}
        disabled={false}
        textfieldprops={{
          variant: 'standard',
          label: label ?? t_i18n('Fintel Designs'),
          helperText: helpertext,
          onFocus: searchFintelDesigns,
        }}
        required={required}
        onChange={typeof onChange === 'function' ? onChange : null}
        style={fieldSpacingContainerStyle ?? style}
        noOptionsText={t_i18n('No available options')}
        options={fintelDesign}
        onInputChange={searchFintelDesigns}
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

export default FintelDesignField;
