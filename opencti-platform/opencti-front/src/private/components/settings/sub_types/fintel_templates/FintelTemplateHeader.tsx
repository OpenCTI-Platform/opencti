import React, { useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { graphql, useFragment } from 'react-relay';
import { Typography } from '@mui/material';
import { useTheme } from '@mui/styles';
import Button from '@common/button/Button';
import FintelTemplatePopover from './FintelTemplatePopover';
import { FintelTemplateHeader_template$key } from './__generated__/FintelTemplateHeader_template.graphql';
import FintelTemplateFormDrawer from './FintelTemplateFormDrawer';
import useFintelTemplateEdit from './useFintelTemplateEdit';
import { useFintelTemplateContext } from './FintelTemplateContext';
import Breadcrumbs from '../../../../../components/Breadcrumbs';
import { useFormatter } from '../../../../../components/i18n';
import ErrorNotFound from '../../../../../components/ErrorNotFound';
import type { Theme } from '../../../../../components/Theme';
import ItemBoolean from '../../../../../components/ItemBoolean';

const headerFragment = graphql`
  fragment FintelTemplateHeader_template on FintelTemplate {
    id
    name
    description
    start_date
    template_content
  }
`;

interface FintelTemplateHeaderProps {
  entitySettingId: string;
  data: FintelTemplateHeader_template$key;
}

const FintelTemplateHeader = ({ entitySettingId, data }: FintelTemplateHeaderProps) => {
  const theme = useTheme<Theme>();
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();
  const { subTypeId } = useParams<{ subTypeId?: string }>();
  const [commitEditMutation, editOnGoing] = useFintelTemplateEdit();
  const { editorValue } = useFintelTemplateContext();

  const [isFormOpen, setFormOpen] = useState(false);

  const template = useFragment(headerFragment, data);

  if (!subTypeId) return <ErrorNotFound />;

  const customizationLink = '/dashboard/settings/customization/entity_types';
  const subTypeLink = `${customizationLink}/${subTypeId}`;
  const breadcrumb = [
    { label: t_i18n('Settings') },
    { label: t_i18n('Customization') },
    { label: t_i18n('Entity types'), link: customizationLink },
    { label: t_i18n(`entity_${subTypeId}`), link: subTypeLink },
    { label: t_i18n('FINTEL Templates') },
    { label: template.name },
  ];

  const onSubmit = () => {
    const input = { key: 'template_content', value: [editorValue] };
    commitEditMutation({
      variables: { id: template.id, input: [input] },
    });
  };

  return (
    <>
      <Breadcrumbs elements={breadcrumb} />

      <div style={{ display: 'flex', gap: theme.spacing(1) }}>
        <Typography variant="h1" sx={{ float: 'left' }}>
          {template.name}
        </Typography>

        <div
          style={{
            float: 'left',
            margin: '0 0 0 5px',
          }}
        >
          <ItemBoolean
            status={!!template.start_date}
            label={template.start_date ? t_i18n('Published') : t_i18n('Not published')}
          />
        </div>
        <div style={{ display: 'flex', alignItems: 'center', marginLeft: 'auto', gap: theme.spacing(1) }}>
          <FintelTemplatePopover
            onUpdate={() => setFormOpen(true)}
            entitySettingId={entitySettingId}
            templateId={template.id}
            inline={false}
            onDeleteComplete={() => navigate(subTypeLink)}
          />
          <Button
            onClick={onSubmit}
            style={{ marginLeft: 'auto' }}
            disabled={editorValue === template.template_content || editOnGoing}
          >
            {t_i18n('Save template')}
          </Button>
        </div>
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
      />
    </>
  );
};

export default FintelTemplateHeader;
