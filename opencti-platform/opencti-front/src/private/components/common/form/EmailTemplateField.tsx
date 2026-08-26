import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React, { FunctionComponent } from 'react';
import { Field } from 'formik';
import { EmailTemplateFieldQuery } from '@components/common/form/__generated__/EmailTemplateFieldQuery.graphql';
import useEnterpriseEdition from 'src/utils/hooks/useEnterpriseEdition';
import EETooltip from '@components/common/entreprise_edition/EETooltip';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { useFormatter } from '../../../../components/i18n';
import ComboboxField, { asSingleValue } from '../../../../components/ComboboxField';
import ItemIcon from '../../../../components/ItemIcon';
import Loader, { LoaderVariant } from '../../../../components/Loader';

const emailTemplateFieldQuery = graphql`
  query EmailTemplateFieldQuery(
    $orderMode: OrderingMode,
    $orderBy: EmailTemplateOrdering
    $filters: FilterGroup
  ) {
    emailTemplates(
      orderMode: $orderMode
      orderBy: $orderBy
      filters: $filters
    ) {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;

export type EmailTemplate = {
  id: string;
  name: string;
};

export type EmailTemplateFieldOption = {
  label: string;
  value: EmailTemplate;
};

interface EmailTemplateFieldComponentProps {
  label?: string;
  name: string;
  style?: React.CSSProperties;
  helperText?: string;
  // Declared as an array, but this field is mounted multiple={false} and its one
  // caller passes Formik's setFieldValue, which accepts anything — so the array
  // never arrived. Typed as the field actually behaves.
  onChange?: (name: string, value: EmailTemplateFieldOption | null) => void;
  required?: boolean;
  queryRef: PreloadedQuery<EmailTemplateFieldQuery>;
}

const EmailTemplateFieldComponent: FunctionComponent<EmailTemplateFieldComponentProps> = ({
  label,
  name,
  style,
  helperText,
  onChange,
  required = false,
  queryRef,
}) => {
  const { t_i18n } = useFormatter();

  const data = usePreloadedQuery(emailTemplateFieldQuery, queryRef);
  const emailTemplates = data.emailTemplates?.edges?.map(({ node }) => ({ value: node, label: node?.name }));

  return (
    <div style={{ width: '100%' }}>
      <Field
        component={ComboboxField}
        // MUI hid its clear indicator here with display:none; the library defaults
        // clearable to true, so the affordance must be declined explicitly.
        clearable={false}
        name={name}
        multiple={false}
        disabled={false}
        label={label ?? t_i18n('Email templates')}
        helperText={helperText}
        required={required}
        onChange={asSingleValue(onChange)}
        style={fieldSpacingContainerStyle ?? style}
        noOptionsText={t_i18n('No available options')}
        options={emailTemplates}
        renderOption={(option: EmailTemplateFieldOption) => (
          <>
            <ItemIcon color="#afb505" type="EmailTemplate" />
            <div style={{ flexGrow: 1, marginLeft: 10 }}>{option.label}</div>
          </>
        )}
      />
    </div>
  );
};

const EmailTemplateFieldLoader = (props: EmailTemplateFieldProps) => {
  const queryRef = useQueryLoading<EmailTemplateFieldQuery>(emailTemplateFieldQuery);
  const { name, label } = props;

  return queryRef ? (
    <React.Suspense fallback={(
      <Field
        component={ComboboxField}
        name={name}
        disabled={true}
        options={[]}
        renderOption={() => null}
        label={label}
      />
    )}
    >
      <EmailTemplateFieldComponent {...props} queryRef={queryRef} />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement} />
  );
};

type EmailTemplateFieldProps = Omit<EmailTemplateFieldComponentProps, 'queryRef'>;
const EmailTemplateField = ({ ...props }: EmailTemplateFieldProps) => {
  const { t_i18n } = useFormatter();
  const isEnterpriseEdition = useEnterpriseEdition();
  const { name } = props;

  if (!isEnterpriseEdition) {
    return (
      <EETooltip title={t_i18n('Only available in EE')}>
        <Field
          component={ComboboxField}
          name={name}
          disabled={true}
          options={[]}
          style={fieldSpacingContainerStyle}
          renderOption={() => null}
          label={t_i18n('Email template')}
        />
      </EETooltip>
    );
  }

  return <EmailTemplateFieldLoader {...props} />;
};

export default EmailTemplateField;
