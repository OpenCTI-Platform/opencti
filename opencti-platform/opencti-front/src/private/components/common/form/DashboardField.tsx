import { Field } from 'formik';
import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import AutocompleteField from '../../../../components/AutocompleteField';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { DashboardFieldQuery } from './__generated__/DashboardFieldQuery.graphql';
import ItemIcon from '../../../../components/ItemIcon';
import { GenericContext } from '../model/GenericContextModel';

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
}));

interface DashboardFieldProps {
  onChange: (name: string, value: string) => void;
  context?: readonly (GenericContext | null)[] | null;
  queryRef: PreloadedQuery<DashboardFieldQuery>;
}

const workspaceQuery = graphql`
  query DashboardFieldQuery {
    workspaces(filters: { mode: and, filters: [{ key: "type", values: ["Dashboard"] }], filterGroups: [] }) {
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
  const { t_i18n } = useFormatter();
  const { workspaces } = usePreloadedQuery<DashboardFieldQuery>(
    workspaceQuery,
    queryRef,
  );
  return (
    <Field
      component={AutocompleteField}
      name="default_dashboard"
      multiple={false}
      onChange={(name: string, value: FieldOption) => onChange(name, value?.value ?? null)}
      isOptionEqualToValue={(option: FieldOption, { value }: FieldOption) => option.value === value}
      textfieldprops={{
        variant: 'standard',
        label: t_i18n('Default dashboard'),
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
        option: FieldOption,
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
