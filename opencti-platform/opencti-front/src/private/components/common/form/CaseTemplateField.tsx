import makeStyles from '@mui/styles/makeStyles';
import { Field } from 'formik';
import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import AutocompleteField from '../../../../components/AutocompleteField';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { CaseTemplateFieldQuery } from './__generated__/CaseTemplateFieldQuery.graphql';
import { FieldOption } from '../../../../utils/field';

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
  onChange?: (name: string, value: FieldOption[]) => void
  onSubmit?: (name: string, value: FieldOption[]) => void
  containerStyle?: Record<string, string | number>
  helpertext?: string
  queryRef: PreloadedQuery<CaseTemplateFieldQuery>
  label?: string
  isDisabled?: boolean
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
  const caseTemplates = data.caseTemplates?.edges?.map(({ node }) => ({ value: node.id, label: node.name }));

  return (
    <div style={{ width: '100%' }}>
      <Field
        component={AutocompleteField}
        name="caseTemplates"
        multiple
        textfieldprops={{
          variant: 'standard',
          label: t_i18n(label ?? 'Default case templates'),
          helperText: helpertext,
        }}
        onChange={(name: string, value: FieldOption[]) => {
          onChange?.(name, value);
          onSubmit?.(name, value);
        }}
        style={containerStyle}
        disabled={isDisabled}
        noOptionsText={t_i18n('No available options')}
        options={caseTemplates}
        renderOption={(
          props: React.HTMLAttributes<HTMLLIElement>,
          option: { color: string; label: string },
        ) => (
          <li {...props}>
            <div className={classes.icon} style={{ color: option.color }}>
              <ItemIcon type="Case-Template" />
            </div>
            <div className={classes.text}>{option.label}</div>
          </li>
        )}
        classes={{ clearIndicator: classes.autoCompleteIndicator }}
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
