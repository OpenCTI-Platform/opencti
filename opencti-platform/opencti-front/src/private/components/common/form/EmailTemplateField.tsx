import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React, { FunctionComponent } from 'react';
import { Field } from 'formik';
import { EmailTemplateFieldQuery } from '@components/common/form/__generated__/EmailTemplateFieldQuery.graphql';
import useEnterpriseEdition from 'src/utils/hooks/useEnterpriseEdition';
import EETooltip from '@components/common/entreprise_edition/EETooltip';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import { useFormatter } from '../../../../components/i18n';
import AutocompleteField from '../../../../components/AutocompleteField';
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
  name: string
};

export type EmailTemplateFieldOption = {
  label: string;
  value: EmailTemplate
};

interface EmailTemplateFieldComponentProps {
  label?: string
  name: string;
  style?: React.CSSProperties,
  helperText?: string;
  onChange?: (name: string, value: FieldOption[]) => void;
  required?: boolean
  queryRef: PreloadedQuery<EmailTemplateFieldQuery>
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
        component={AutocompleteField}
        name={name}
        multiple={false}
        disabled={false}
        textfieldprops={{
          variant: 'standard',
          label: label ?? t_i18n('Email templates'),
          helperText,
        }}
        required={required}
        onChange={onChange}
        style={fieldSpacingContainerStyle ?? style}
        noOptionsText={t_i18n('No available options')}
        options={emailTemplates}
        renderOption={(
          props: React.HTMLAttributes<HTMLLIElement>,
          option: EmailTemplateFieldOption,
        ) => (
          <li {...props} key={option.value.id} style={{ display: 'flex', alignItems: 'center' }}>
            <ItemIcon color={'#afb505'} type='EmailTemplate' />
            <div style={{ flexGrow: 1, marginLeft: 10 }}>{option.label}</div>
          </li>
        )}
        classes={{ clearIndicator: { display: 'none' } }}
      />
    </div>
  );
};

type EmailTemplateFieldProps = Omit<EmailTemplateFieldComponentProps, 'queryRef'>;

const EmailTemplateField = ({ ...props }: EmailTemplateFieldProps) => {
  const { t_i18n } = useFormatter();
  const isEnterpriseEdition = useEnterpriseEdition();

  const queryRef = useQueryLoading<EmailTemplateFieldQuery>(emailTemplateFieldQuery);
  const { name, label } = props;

  if (!isEnterpriseEdition) {
    return (
      <>
        <EETooltip title={t_i18n('Only available in EE')}>
          <Field
            component={AutocompleteField}
            name={name}
            disabled={true}
            fullWidth={true}
            options={[]}
            style={fieldSpacingContainerStyle}
            renderOption={() => null}
            textfieldprops={{
              label: t_i18n('Email template'),
            }}
          />
        </EETooltip>
      </>
    );
  }

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
      <EmailTemplateFieldComponent {...props} queryRef={queryRef} />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement}/>
  );
};

export default EmailTemplateField;
