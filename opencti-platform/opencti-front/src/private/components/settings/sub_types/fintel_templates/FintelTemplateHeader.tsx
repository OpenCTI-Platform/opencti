import React from 'react';
import { useParams } from 'react-router-dom';
import { graphql, useFragment } from 'react-relay';
import { FintelTemplateHeader_template$key } from '@components/settings/sub_types/fintel_templates/__generated__/FintelTemplateHeader_template.graphql';
import Typography from '@mui/material/Typography';
import FintelTemplatePopover from '@components/settings/sub_types/fintel_templates/FintelTemplatePopover';
import Breadcrumbs from '../../../../../components/Breadcrumbs';
import { useFormatter } from '../../../../../components/i18n';
import ErrorNotFound from '../../../../../components/ErrorNotFound';

const headerFragment = graphql`
  fragment FintelTemplateHeader_template on FintelTemplate {
    id
    name
  }
`;

interface FintelTemplateHeaderProps {
  data: FintelTemplateHeader_template$key
}

const FintelTemplateHeader = ({ data }: FintelTemplateHeaderProps) => {
  const { t_i18n } = useFormatter();
  const { subTypeId } = useParams<{ subTypeId?: string }>();
  if (!subTypeId) return <ErrorNotFound />;

  const template = useFragment(headerFragment, data);

  const customizationLink = '/dashboard/settings/customization/entity_types';
  const breadcrumb = [
    { label: t_i18n('Settings') },
    { label: t_i18n('Customization') },
    { label: t_i18n('Entity types'), link: customizationLink },
    { label: subTypeId, link: `${customizationLink}/${subTypeId}` },
    { label: t_i18n('FINTEL Templates') },
    { label: template.name },
  ];

  return (
    <>
      <Breadcrumbs elements={breadcrumb} />

      <Typography variant="h1" gutterBottom={true}>
        {template.name}
      </Typography>
      <FintelTemplatePopover
        templateId={template.id}
        onUpdate={console.log}
      />
    </>
  );
};

export default FintelTemplateHeader;
