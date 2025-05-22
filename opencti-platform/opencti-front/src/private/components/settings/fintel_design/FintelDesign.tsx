import React, { FunctionComponent, useEffect, useState } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import { useParams } from 'react-router-dom';
import { FintelDesignQuery } from '@components/settings/fintel_design/__generated__/FintelDesignQuery.graphql';
import FintelDesignPopover from '@components/settings/fintel_design/FintelDesignPopover';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/styles';
import Paper from '@mui/material/Paper';
import { FintelDesign_fintelDesign$key } from '@components/settings/fintel_design/__generated__/FintelDesign_fintelDesign.graphql';
import CustomizationMenu from '@components/settings/CustomizationMenu';
import FintelDesignForm from '@components/settings/fintel_design/FintelDesignForm';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import PageContainer from '../../../../components/PageContainer';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { htmlToPdfReport } from '../../../../utils/htmlToPdf/htmlToPdf';
import useFileFromTemplate from '../../../../utils/outcome_template/engine/useFileFromTemplate';
import PdfViewer from '../../../../components/PdfViewer';

const fintelDesignQuery = graphql`
  query FintelDesignQuery($id: String!) {
    fintelDesign(id: $id) {
      ...FintelDesign_fintelDesign
      ...FintelDesignsLine_node
    }
  }
`;

const fintelDesignComponentFragment = graphql`
  fragment FintelDesign_fintelDesign on FintelDesign {
    id
    name
    description
    url
    gradiantFromColor
    gradiantToColor
    textColor
  }
`;

interface FintelDesignComponentProps {
  queryRef: PreloadedQuery<FintelDesignQuery>
}

export type FintelDesignFormValues = {
  name: string
  description?: string | null | undefined
  url?: string | null | undefined
  gradiantFromColor?: string | null | undefined
  gradiantToColor?: string | null | undefined
  textColor?: string | null | undefined
};

const FintelDesignComponent: FunctionComponent<FintelDesignComponentProps> = ({
  queryRef,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const queryResult = usePreloadedQuery(fintelDesignQuery, queryRef);
  const fintelDesign = useFragment<FintelDesign_fintelDesign$key>(
    fintelDesignComponentFragment,
    queryResult.fintelDesign,
  );
  if (!fintelDesign) return null;
  const [pdf, setPdf] = useState<File>();
  const { buildFileFromTemplate } = useFileFromTemplate();

  const [formValues, setFormValues] = useState<FintelDesignFormValues>();

  const buildPreview = async () => {
    const template = {
      template_content: '',
      name: 'Preview',
      id: 'preview',
      fintel_template_widgets: [],
      instance_filters: null,
    };
    const htmlTemplate = await buildFileFromTemplate('', [], undefined, template);
    const PDF = await htmlToPdfReport('', htmlTemplate, 'Preview', [], fintelDesign);
    PDF.getBlob((blob) => {
      const file = new File([blob], 'Preview.pdf', { type: blob.type });
      setPdf(file);
    });
  };
  useEffect(() => {
    buildPreview();
  }, [formValues]);

  return (
    <>
      <div style={{ display: 'flex', alignItems: 'center' }}>
        <Typography
          variant="h1"
          gutterBottom={true}
          style={{ marginRight: 10 }}
        >
          {fintelDesign.name}
        </Typography>
        <div style={{ marginTop: -6 }}>
          <FintelDesignPopover data={fintelDesign}/>
        </div>
      </div>
      <PageContainer withRightMenu>
        <CustomizationMenu />
        <Breadcrumbs
          noMargin
          elements={[
            { label: t_i18n('Settings') },
            { label: t_i18n('Customization') },
            { label: t_i18n('Fintel design'), link: '/dashboard/settings/customization/fintel_designs' },
            { label: `${fintelDesign.name}`, current: true },
          ]}
        />
        <Grid
          container={true}
          spacing={3}
          style={{ margin: 0, paddingRight: 20 }}
        >
          <Grid item xs={4} style={{ paddingLeft: 0 }}>
            <Typography variant="h4" gutterBottom={true}>
              {t_i18n('Configuration')}
            </Typography>
            <Paper
              style={{
                marginTop: theme.spacing(1),
                padding: '15px',
                borderRadius: 6,
              }}
              variant="outlined"
            >
              <FintelDesignForm
                fintelDesign={fintelDesign}
                onChange={(values) => setFormValues(values)}
              />
            </Paper>
          </Grid>
          <Grid item xs={8}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Preview')}
            </Typography>
            <Paper
              style={{
                marginTop: theme.spacing(1),
                padding: '15px',
                borderRadius: 6,
              }}
              variant="outlined"
            >
              {pdf && (
                <PdfViewer pdf={pdf} />
              )}
            </Paper>
          </Grid>
        </Grid>
      </PageContainer>
    </>
  );
};

const FintelDesign = () => {
  const { fintelDesignId }: { fintelDesignId?: string } = useParams();
  if (!fintelDesignId) return null;
  const queryRef = useQueryLoading<FintelDesignQuery>(
    fintelDesignQuery,
    { id: fintelDesignId },
  );
  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
      <FintelDesignComponent queryRef={queryRef} />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.container} />
  );
};

export default FintelDesign;
