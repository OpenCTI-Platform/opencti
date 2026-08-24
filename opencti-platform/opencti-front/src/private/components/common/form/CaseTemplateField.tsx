import makeStyles from '@mui/styles/makeStyles';
import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import ComboboxField, { ComboboxFieldProps } from '../../../../components/ComboboxField';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { CaseTemplateFieldQuery } from './__generated__/CaseTemplateFieldQuery.graphql';
import Field, { FieldOption } from '../../../../utils/field';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
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

const caseTemplateFieldQuery = graphql`
  query CaseTemplateFieldQuery {
    caseTemplates {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;

interface CaseTemplateFieldComponentProps {
  onChange?: (name: string, value: FieldOption[]) => void;
  onSubmit?: (name: string, value: FieldOption[]) => void;
  containerStyle?: Record<string, string | number>;
  helpertext?: string;
  queryRef: PreloadedQuery<CaseTemplateFieldQuery>;
  label?: string;
  isDisabled?: boolean;
}

const CaseTemplateFieldComponent: FunctionComponent<CaseTemplateFieldComponentProps> = ({
  containerStyle,
  onChange,
  onSubmit,
  helpertext,
  queryRef,
  label,
  isDisabled,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();

  const data = usePreloadedQuery(caseTemplateFieldQuery, queryRef);
  const caseTemplates = (data.caseTemplates?.edges ?? []).map(({ node }) => ({
    value: node.id,
    label: node.name,
  }));

  return (
    <div style={{ width: '100%' }}>
      <Field<ComboboxFieldProps>
        component={ComboboxField}
        name="caseTemplates"
        multiple
        label={t_i18n(label ?? 'Default case templates')}
        helperText={helpertext}
        onChange={(name, value) => {
          const templates = (value ?? []) as FieldOption[];
          onChange?.(name, templates);
          onSubmit?.(name, templates);
        }}
        style={containerStyle}
        disabled={isDisabled}
        noOptionsText={t_i18n('No available options')}
        options={caseTemplates}
        renderOption={(option) => (
          <>
            <div className={classes.icon} style={{ color: option.color }}>
              <ItemIcon type="Case-Template" />
            </div>
            <div className={classes.text}>{option.label}</div>
          </>
        )}
      />
    </div>
  );
};

type CaseTemplateFieldProps = Omit<Omit<CaseTemplateFieldComponentProps, 'queryRef'>, 'reloadCaseTemplates'>;

const CaseTemplateField: FunctionComponent<CaseTemplateFieldProps> = (props) => {
  const queryRef = useQueryLoading<CaseTemplateFieldQuery>(caseTemplateFieldQuery);

  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <CaseTemplateFieldComponent {...props} queryRef={queryRef} />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement} />
  );
};

export default CaseTemplateField;
