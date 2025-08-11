import React, { Suspense } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useParams } from 'react-router-dom';
import { EmailTemplateQuery } from '@components/settings/email_template/__generated__/EmailTemplateQuery.graphql';
import { EmailTemplateProvider } from '@components/settings/email_template/EmailTemplateContext';
import EmailTemplateHeader from '@components/settings/email_template/EmailTemplateHeader';
import EmailTemplateTabs from '@components/settings/email_template/EmailTemplateTabs';
import EmailTemplateContentEditor from '@components/settings/email_template/EmailTemplateContentEditor';
import EmailTemplateAttributesSidebar, { EMAIL_TEMPLATE_SIDEBAR_WIDTH } from '@components/settings/email_template/EmailTemplateAttributesSidebar';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader from '../../../../components/Loader';

export const emailTemplateQuery = graphql`
    query EmailTemplateQuery($id: ID!) {
        emailTemplate(id: $id) {
            id
            entity_type
            ...EmailTemplateTabs_template
            ...EmailTemplateHeader_template
            ...EmailTemplateContentEditor_template
        }
    }
`;

interface EmailTemplateProps {
  queryRef: PreloadedQuery<EmailTemplateQuery>
}

const EmailTemplateComponent = ({ queryRef }: EmailTemplateProps) => {
  const { emailTemplate } = usePreloadedQuery(emailTemplateQuery, queryRef);
  if (!emailTemplate) return <ErrorNotFound/>;

  return (
    <EmailTemplateProvider>
      <div style={{ marginRight: EMAIL_TEMPLATE_SIDEBAR_WIDTH }}>
        <EmailTemplateHeader
          data={emailTemplate}
        />

        <EmailTemplateTabs data={emailTemplate}>
          {({ index }) => (
            <>
              <div role="tabpanel" hidden={index !== 0}>
                <EmailTemplateContentEditor data={emailTemplate} />
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
  const { emailTemplateId } = useParams<{ emailTemplateId?: string }>();
  if (!emailTemplateId) return <ErrorNotFound/>;

  const templateRef = useQueryLoading<EmailTemplateQuery>(
    emailTemplateQuery,
    {
      id: emailTemplateId,
    },
  );

  return (
    <Suspense fallback={<Loader />}>
      {templateRef && <EmailTemplateComponent queryRef={templateRef} />}
    </Suspense>
  );
};

export default EmailTemplate;
