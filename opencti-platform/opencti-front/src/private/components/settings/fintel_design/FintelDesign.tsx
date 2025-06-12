import React, { FunctionComponent, useEffect, useState } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import { useParams } from 'react-router-dom';
import { FintelDesignQuery } from '@components/settings/fintel_design/__generated__/FintelDesignQuery.graphql';
import Grid from '@mui/material/Grid2';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/styles';
import Paper from '@mui/material/Paper';
import { FintelDesign_fintelDesign$key } from '@components/settings/fintel_design/__generated__/FintelDesign_fintelDesign.graphql';
import CustomizationMenu from '@components/settings/CustomizationMenu';
import FintelDesignForm from '@components/settings/fintel_design/FintelDesignForm';
import FintelDesignEdition from '@components/settings/fintel_design/FintelDesignEdition';
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
      ...FintelDesignEditionOverview_fintelDesign
    }
  }
`;

const fintelDesignComponentFragment = graphql`
  fragment FintelDesign_fintelDesign on FintelDesign {
    id
    name
    description
    gradiantFromColor
    gradiantToColor
    textColor
    file_id
  }
`;

interface FintelDesignComponentProps {
  queryRef: PreloadedQuery<FintelDesignQuery>
}

const FintelDesignComponent: FunctionComponent<FintelDesignComponentProps> = ({
  queryRef,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [pdf, setPdf] = useState<File>();
  const { buildFileFromTemplate } = useFileFromTemplate();

  const queryResult = usePreloadedQuery(fintelDesignQuery, queryRef);
  const fintelDesign = useFragment<FintelDesign_fintelDesign$key>(
    fintelDesignComponentFragment,
    queryResult.fintelDesign,
  );
  if (!queryResult.fintelDesign || !fintelDesign) return null;

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
  }, [fintelDesign]);

  return (
    <>
      <PageContainer withRightMenu>
        <CustomizationMenu/>
        <Breadcrumbs
          elements={[
            { label: t_i18n('Settings') },
            { label: t_i18n('Customization') },
            { label: t_i18n('Fintel design'), link: '/dashboard/settings/customization/fintel_designs' },
            { label: `${fintelDesign.name}`, current: true },
          ]}
        />
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <Typography
            variant="h1"
            gutterBottom={true}
          >
            {fintelDesign.name}
          </Typography>
          <div>
            <FintelDesignEdition
              fintelDesignId={fintelDesign.id}
              overviewData={queryResult.fintelDesign}
            />
          </div>
        </div>
        <Grid
          container spacing={3}
          sx={{ marginTop: 2 }}
        >
          <Grid size={{ xs: 4 }}>
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
                onFileUploaded={buildPreview}
              />
            </Paper>
          </Grid>
          <Grid size={{ xs: 8 }} sx={{ height: 'calc(100vh - 250px)' }}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Preview')}
            </Typography>
            <Paper
              style={{
                marginTop: theme.spacing(1),
                padding: '15px',
                borderRadius: 6,
                height: '100%',
              }}
              variant="outlined"
            >
              {pdf && (
                <PdfViewer pdf={pdf}/>
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
    <React.Suspense fallback={<Loader variant={LoaderVariant.container}/>}>
      <FintelDesignComponent queryRef={queryRef} />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.container} />
  );
};

export default FintelDesign;
