import { Field } from 'formik';
import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import AutocompleteField from '../../../../components/AutocompleteField';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { DashboardFieldQuery } from './__generated__/DashboardFieldQuery.graphql';
import { Option } from './ReferenceField';
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
}));

interface DashboardFieldProps {
  onChange: (name: string, value: string) => void;
  context:
  | readonly ({
    readonly focusOn: string | null;
    readonly name: string;
  } | null)[]
  | null;
  queryRef: PreloadedQuery<DashboardFieldQuery>;
}

const workspaceQuery = graphql`
  query DashboardFieldQuery {
    workspaces(filters: [{ key: type, values: ["Dashboard"] }]) {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;

const DashboardFieldComponent: FunctionComponent<DashboardFieldProps> = ({
  onChange,
  context,
  queryRef,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const { workspaces } = usePreloadedQuery<DashboardFieldQuery>(
    workspaceQuery,
    queryRef,
  );
  return (
    <Field
      component={AutocompleteField}
      name="default_dashboard"
      multiple={false}
      onChange={(name: string, value: Option) => onChange(name, value?.value ?? null)}
      isOptionEqualToValue={(option: Option, { value }: Option) => option.value === value}
      textfieldprops={{
        variant: 'standard',
        label: t('Default dashboard'),
        fullWidth: true,
        helperText: (
          <SubscriptionFocus context={context} fieldName="default_dashboard" />
        ),
      }}
      options={(workspaces?.edges ?? []).map(({ node: { id, name } }) => ({
        value: id,
        label: name,
        type: 'Dashboard',
      }))}
      style={fieldSpacingContainerStyle}
      renderOption={(
        props: React.HTMLAttributes<HTMLLIElement>,
        option: Option,
      ) => (
        <li {...props}>
          <div className={classes.icon} style={{ color: option.color }}>
            <ItemIcon type={option.type} />
          </div>
          <div className={classes.text}>{option.label}</div>
        </li>
      )}
    />
  );
};

const DashboardField: FunctionComponent<
Omit<DashboardFieldProps, 'queryRef'>
> = (props) => {
  const queryRef = useQueryLoading<DashboardFieldQuery>(workspaceQuery);
  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <DashboardFieldComponent {...props} queryRef={queryRef} />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement} />
  );
};

export default DashboardField;
