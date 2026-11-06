import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { styled } from '@mui/material/styles';
import ComboboxField, { ComboboxFieldProps } from '../../../../components/ComboboxField';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { SubscriptionFocus } from '../../../../components/Subscription';
import Field, { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { DashboardFieldQuery } from './__generated__/DashboardFieldQuery.graphql';
import ItemIcon from '../../../../components/ItemIcon';
import { GenericContext } from '../model/GenericContextModel';

const OptionIcon = styled('div')({
  paddingTop: 4,
  display: 'inline-block',
});

const OptionText = styled('div')({
  display: 'inline-block',
  flexGrow: 1,
  marginLeft: 10,
});

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
  const { t_i18n } = useFormatter();
  const { workspaces } = usePreloadedQuery<DashboardFieldQuery>(
    workspaceQuery,
    queryRef,
  );
  return (
    <Field<ComboboxFieldProps>
      component={ComboboxField}
      name="default_dashboard"
      multiple={false}
      onChange={(name, value) => onChange(name, (value as FieldOption | null)?.value ?? '')}
      isOptionEqualToValue={(option, { value }) => option.value === value}
      label={t_i18n('Default dashboard')}
      helperText={(
        <SubscriptionFocus context={context} fieldName="default_dashboard" />
      )}
      options={(workspaces?.edges ?? []).map(({ node: { id, name } }) => ({
        value: id,
        label: name,
        type: 'Dashboard',
      }))}
      style={fieldSpacingContainerStyle}
      renderOption={(option) => (
        <>
          <OptionIcon style={{ color: option.color }}>
            <ItemIcon type={option.type} />
          </OptionIcon>
          <OptionText>{option.label}</OptionText>
        </>
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
