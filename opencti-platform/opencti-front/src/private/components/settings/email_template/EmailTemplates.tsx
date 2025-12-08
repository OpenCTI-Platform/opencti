import React from 'react';
import AccessesMenu from '@components/settings/AccessesMenu';
import { graphql } from 'react-relay';
import EnterpriseEdition from '@components/common/entreprise_edition/EnterpriseEdition';
import EmailTemplateCreation from '@components/settings/email_template/EmailTemplateCreation';
import {
  EmailTemplatesLinesPaginationQuery,
  EmailTemplatesLinesPaginationQuery$variables,
} from '@components/settings/email_template/__generated__/EmailTemplatesLinesPaginationQuery.graphql';
import { EmailTemplatesLine_node$data } from '@components/settings/email_template/__generated__/EmailTemplatesLine_node.graphql';
import DataTable from '../../../../components/dataGrid/DataTable';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { DataTableProps } from '../../../../components/dataGrid/dataTableTypes';
import ItemIcon from '../../../../components/ItemIcon';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import Alert from '../../../../components/Alert';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import PageContainer from '../../../../components/PageContainer';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';

export const emailTemplatesQuery = graphql`
    query EmailTemplatesLinesPaginationQuery(
        $search: String
        $count: Int!
        $cursor: ID
        $orderBy: EmailTemplateOrdering
        $orderMode: OrderingMode
        $filters: FilterGroup
    ) {
        ...EmailTemplatesLines_data
        @arguments(
            search: $search
            count: $count
            cursor: $cursor
            orderBy: $orderBy
            orderMode: $orderMode
            filters: $filters
        )
    }
`;

export const emailTemplatesFragment = graphql`
    fragment EmailTemplatesLines_data on Query
    @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "EmailTemplateOrdering", defaultValue: name }
        orderMode: { type: "OrderingMode", defaultValue: desc }
        filters: { type: "FilterGroup" }
    ) @refetchable(queryName: "EmailTemplatesLinesRefetchQuery") {
        emailTemplates(
            search: $search
            first: $count
            after: $cursor
            orderBy: $orderBy
            orderMode: $orderMode
            filters: $filters
        ) @connection(key: "Pagination_emailTemplates") {
            edges {
                node {
                    ...EmailTemplatesLine_node
                }
            }
            pageInfo {
                endCursor
                hasNextPage
                globalCount
            }
        }
    }
`;

const emailTemplatesLineFragment = graphql`
    fragment EmailTemplatesLine_node on EmailTemplate {
      id
      entity_type
      name
      description
      email_object
      sender_email
      template_body
    }
`;

const LOCAL_STORAGE_KEY = 'view-email-templates';

const EmailTemplates = () => {
  const isEnterpriseEdition = useEnterpriseEdition();
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Email templates | Security | Settings'));

  const initialValues = {
    searchTerm: '',
    sortBy: 'name',
    orderAsc: true,
    openExports: false,
    filters: emptyFilterGroup,
  };

  const {
    viewStorage,
    paginationOptions,
    helpers: storageHelpers,
  } = usePaginationLocalStorage<EmailTemplatesLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );

  const { filters } = viewStorage;
  const contextFilters = useBuildEntityTypeBasedFilterContext('EmailTemplate', filters);

  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as EmailTemplatesLinesPaginationQuery$variables;

  const queryRef = useQueryLoading<EmailTemplatesLinesPaginationQuery>(
    emailTemplatesQuery,
    queryPaginationOptions,
  );

  const dataColumns: DataTableProps['dataColumns'] = {
    name: {
      id: 'name',
      label: 'Name',
      isSortable: true,
      percentWidth: 25,
    },
    description: {
      id: 'description',
      label: 'Description',
      percentWidth: 75,
      isSortable: false,
    },
  };

  const preloadedPaginationProps = {
    linesQuery: emailTemplatesQuery,
    linesFragment: emailTemplatesFragment,
    queryRef,
    nodePath: ['emailTemplates', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<EmailTemplatesLinesPaginationQuery>;

  return (
    <div data-testid="email-templates-page">
      <AccessesMenu/>
      <PageContainer withRightMenu>
        <Breadcrumbs elements={[{ label: t_i18n('Settings') }, { label: t_i18n('Security') }, { label: t_i18n('Email templates'), current: true }]} />
        {!isEnterpriseEdition ? (
          <EnterpriseEdition feature="Email templates" />
        ) : (
          <>
            <Alert
              style={{ marginBottom: '16px' }}
              content={t_i18n('These template emails are only used for one time email, not for notifications or dissemination.')}
            />
            {queryRef && (
            <DataTable
              dataColumns={dataColumns}
              resolvePath={(data) => data.emailTemplates?.edges?.map(({ node }: { node: EmailTemplatesLine_node$data }) => node)}
              storageKey={LOCAL_STORAGE_KEY}
              initialValues={initialValues}
              contextFilters={contextFilters}
              lineFragment={emailTemplatesLineFragment}
              disableLineSelection
              preloadedPaginationProps={preloadedPaginationProps}
              createButton={<EmailTemplateCreation paginationOptions={queryPaginationOptions} />}
              icon={() => <ItemIcon color={'#afb505'} type="EmailTemplate" />}
            />
            )}
          </>
        )}
      </PageContainer>
    </div>
  );
};

export default EmailTemplates;
