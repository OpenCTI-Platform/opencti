import React, { Suspense } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useParams } from 'react-router-dom';
import { EmailTemplateQuery } from '@components/settings/email_template/__generated__/EmailTemplateQuery.graphql';
import { EmailTemplateProvider } from '@components/settings/email_template/EmailTemplateContext';
import EmailTemplateHeader from '@components/settings/email_template/EmailTemplateHeader';
import EmailTemplateTabs from '@components/settings/email_template/EmailTemplateTabs';
import EmailTemplateContentEditor from '@components/settings/email_template/EmailTemplateContentEditor';
import EmailTemplatePreview from '@components/settings/email_template/EmailTemplatePreview';
import EmailTemplateAttributesSidebar, { EMAIL_TEMPLATE_SIDEBAR_WIDTH } from '@components/settings/email_template/EmailTemplateAttributesSidebar';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader from '../../../../components/Loader';

export const emailTemplateQuery = graphql`
    query EmailTemplateQuery($id: ID!) {
        disseminationList(id: $id) {
            id
            entity_type
            ...EmailTemplateHeader_template
        }
    }
`;

interface EmailTemplateProps {
  queryRef: PreloadedQuery<EmailTemplateQuery>
}

const EmailTemplateComponent = ({ queryRef }: EmailTemplateProps) => {
  const { disseminationList: email_template } = usePreloadedQuery(emailTemplateQuery, queryRef);
  if (!email_template) return <ErrorNotFound/>;

  return (
    <EmailTemplateProvider>
      <div style={{ marginRight: EMAIL_TEMPLATE_SIDEBAR_WIDTH }}>
        <EmailTemplateHeader
          data={email_template}
        />

        <EmailTemplateTabs data={email_template}>
          {({ index }) => (
            <>
              <div role="tabpanel" hidden={index !== 0}>
                <EmailTemplateContentEditor data={email_template} />
              </div>
              <div role="tabpanel" hidden={index !== 1}>
                <EmailTemplatePreview />
              </div>
            </>
          )}
        </EmailTemplateTabs>
      </div>

      <EmailTemplateAttributesSidebar />
    </EmailTemplateProvider>
  );
};

const EmailTemplate = () => {
  const { templateId, subTypeId } = useParams<{ templateId?: string, subTypeId?: string }>();
  if (!templateId || !subTypeId) return <ErrorNotFound/>;

  const templateRef = useQueryLoading<EmailTemplateQuery>(
    emailTemplateQuery,
    {
      id: templateId,
    },
  );

  return (
    <Suspense fallback={<Loader />}>
      {templateRef && <EmailTemplateComponent queryRef={templateRef} />}
    </Suspense>
  );
};

export default EmailTemplate;
