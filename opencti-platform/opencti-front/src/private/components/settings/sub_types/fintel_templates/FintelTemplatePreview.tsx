import React, { useEffect, useState } from 'react';
import { useTheme } from '@mui/styles';
import { graphql, useFragment } from 'react-relay';
import { FintelDesign } from '@components/common/form/FintelDesignField';
import { useFintelTemplateContext } from './FintelTemplateContext';
import type { Theme } from '../../../../../components/Theme';
import { useFormatter } from '../../../../../components/i18n';
import FintelTemplatePreviewForm, { FintelTemplatePreviewFormInputs } from './FintelTemplatePreviewForm';
import useFileFromTemplate from '../../../../../utils/outcome_template/engine/useFileFromTemplate';
import { htmlToPdfReport } from '../../../../../utils/htmlToPdf/htmlToPdf';
import PdfViewer from '../../../../../components/PdfViewer';
import { FintelTemplatePreview_template$key } from './__generated__/FintelTemplatePreview_template.graphql';
import Card from '../../../../../components/common/card/Card';

const previewFragment = graphql`
  fragment FintelTemplatePreview_template on FintelTemplate {
    fintel_template_widgets {
      variable_name
      widget {
        id
        type
        perspective
        dataSelection {
          instance_id
          filters
          dynamicFrom
          dynamicTo
          date_attribute
          number
          attribute
          isTo
          sort_by
          sort_mode
          number
          columns {
            label
            variableName
            attribute
            displayStyle
          }
        }
      }
    }
  }
`;

interface FintelTemplatePreviewProps {
  data: FintelTemplatePreview_template$key;
  isTabActive: boolean;
}

const FintelTemplatePreview = ({
  data,
  isTabActive,
}: FintelTemplatePreviewProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { buildFileFromTemplate } = useFileFromTemplate();
  const { editorValue } = useFintelTemplateContext();

  const [pdf, setPdf] = useState<File>();
  const [formValues, setFormValues] = useState<FintelTemplatePreviewFormInputs>();

  const { fintel_template_widgets } = useFragment<FintelTemplatePreview_template$key>(
    previewFragment,
    data,
  );

  const buildPreview = async (
    scoId: string,
    scoName: string,
    fintelDesign: FintelDesign | null | undefined,
    maxMarkings: string[],
    fileMarkings: string[],
  ) => {
    const template = {
      template_content: editorValue ?? '',
      name: 'Preview',
      id: 'preview',
      fintel_template_widgets,
      instance_filters: null,
    };
    const htmlTemplate = await buildFileFromTemplate(scoId, maxMarkings, undefined, template);
    const PDF = await htmlToPdfReport(scoName, htmlTemplate, 'Preview', fileMarkings, fintelDesign);
    PDF.getBlob((blob) => {
      const file = new File([blob], 'Preview.pdf', { type: blob.type });
      setPdf(file);
    });
  };

  useEffect(() => {
    const { fileMarkings, entity, contentMaxMarkings, fintelDesign } = formValues ?? {};
    if (!entity || !isTabActive) return;
    buildPreview(
      entity.value,
      entity.label,
      fintelDesign?.value ?? null,
      (contentMaxMarkings ?? []).map((m) => m.value),
      (fileMarkings ?? []).map((m) => m.label),
    );
  }, [formValues, editorValue, isTabActive]);

  return (
    <div style={{
      height: 'calc(100vh - 280px)',
      display: 'flex',
      gap: theme.spacing(3),
    }}
    >
      <div style={{ flex: 2, display: 'flex', flexDirection: 'column' }}>
        <Card title={t_i18n('Configuration')}>
          <FintelTemplatePreviewForm
            onChange={(values) => setFormValues(values)}
          />
        </Card>
      </div>

      <div style={{ flex: 5, display: 'flex', flexDirection: 'column' }}>
        <Card title={t_i18n('Preview')}>
          {pdf ? (
            <PdfViewer pdf={pdf} />
          ) : (
            <div style={{
              display: 'flex',
              height: '100%',
              alignItems: 'center',
              justifyContent: 'center',
            }}
            >
              {t_i18n('Please select an entity on the left form to preview the template')}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
};

export default FintelTemplatePreview;
