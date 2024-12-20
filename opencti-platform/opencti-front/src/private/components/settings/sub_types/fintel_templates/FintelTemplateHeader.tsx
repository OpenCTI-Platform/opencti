import React, { useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { graphql, useFragment } from 'react-relay';
import { FintelTemplateHeader_template$key } from '@components/settings/sub_types/fintel_templates/__generated__/FintelTemplateHeader_template.graphql';
import { Typography, Button } from '@mui/material';
import { useTheme } from '@mui/styles';
import FintelTemplateFormDrawer from '@components/settings/sub_types/fintel_templates/FintelTemplateFormDrawer';
import Breadcrumbs from '../../../../../components/Breadcrumbs';
import { useFormatter } from '../../../../../components/i18n';
import ErrorNotFound from '../../../../../components/ErrorNotFound';
import type { Theme } from '../../../../../components/Theme';

const headerFragment = graphql`
  fragment FintelTemplateHeader_template on FintelTemplate {
    id
    name
    description
    start_date
  }
`;

interface FintelTemplateHeaderProps {
  entitySettingId: string
  data: FintelTemplateHeader_template$key
}

const FintelTemplateHeader = ({ entitySettingId, data }: FintelTemplateHeaderProps) => {
  const theme = useTheme<Theme>();
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();
  const { subTypeId } = useParams<{ subTypeId?: string }>();

  const [isFormOpen, setFormOpen] = useState(false);

  const template = useFragment(headerFragment, data);

  if (!subTypeId) return <ErrorNotFound />;

  const customizationLink = '/dashboard/settings/customization/entity_types';
  const subTypeLink = `${customizationLink}/${subTypeId}`;
  const breadcrumb = [
    { label: t_i18n('Settings') },
    { label: t_i18n('Customization') },
    { label: t_i18n('Entity types'), link: customizationLink },
    { label: subTypeId, link: subTypeLink },
    { label: t_i18n('FINTEL Templates') },
    { label: template.name },
  ];

  return (
    <>
      <Breadcrumbs elements={breadcrumb} />

      <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1) }}>
        <Typography variant="h1" sx={{ marginBottom: 0.5, flex: 1 }}>
          {template.name}
        </Typography>

        <Button variant="outlined" onClick={() => setFormOpen(true)}>
          {t_i18n('Update')}
        </Button>
      </div>

      <FintelTemplateFormDrawer
        entitySettingId={entitySettingId}
        isOpen={isFormOpen}
        template={{
          id: template.id,
          name: template.name,
          description: template.description ?? null,
          published: !!template.start_date,
        }}
        onClose={() => setFormOpen(false)}
        onDeleteComplete={() => navigate(subTypeLink)}
      />
    </>
  );
};

export default FintelTemplateHeader;
