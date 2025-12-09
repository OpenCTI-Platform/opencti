import React, { FunctionComponent, useEffect, useState } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import { useParams } from 'react-router-dom';
import { FintelDesignQuery } from '@components/settings/fintel_design/__generated__/FintelDesignQuery.graphql';
import Grid from '@mui/material/Grid2';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/styles';
import { FintelDesign_fintelDesign$key } from '@components/settings/fintel_design/__generated__/FintelDesign_fintelDesign.graphql';
import CustomizationMenu from '@components/settings/CustomizationMenu';
import FintelDesignForm from '@components/settings/fintel_design/FintelDesignForm';
import FintelDesignEdition from '@components/settings/fintel_design/FintelDesignEdition';
import { Box, styled } from '@mui/material';
import MenuItem from '@mui/material/MenuItem';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import PageContainer from '../../../../components/PageContainer';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { htmlToPdfReport } from '../../../../utils/htmlToPdf/htmlToPdf';
import useFileFromTemplate from '../../../../utils/outcome_template/engine/useFileFromTemplate';
import PdfViewer from '../../../../components/PdfViewer';
import PopoverMenu from '../../../../components/PopoverMenu';
import FintelDesignDeletion from './FintelDesignDeletion';
import useGranted, { KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import Card from '../../../../components/common/card/Card';

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
  queryRef: PreloadedQuery<FintelDesignQuery>;
}

const FintelDesignComponent: FunctionComponent<FintelDesignComponentProps> = ({
  queryRef,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const canDelete = useGranted([KNOWLEDGE_KNUPDATE_KNDELETE]);
  const [openDelete, setOpenDelete] = useState(false);

  const [pdf, setPdf] = useState<File>();
  const { buildFileFromTemplate } = useFileFromTemplate();

  const handleOpenDelete = () => setOpenDelete(true);
  const handleCloseDelete = () => setOpenDelete(false);

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

  const FintelDesignHeader = styled('div')({
    display: 'flex',
    justifyContent: 'space-between',
    marginBottom: 24,
  });

  return (
    <>
      <PageContainer withRightMenu>
        <CustomizationMenu />
        <Breadcrumbs
          elements={[
            { label: t_i18n('Settings') },
            { label: t_i18n('Customization') },
            { label: t_i18n('Fintel design'), link: '/dashboard/settings/customization/fintel_designs' },
            { label: `${fintelDesign.name}`, current: true },
          ]}
        />
        <FintelDesignHeader>
          <div>
            <Typography
              variant="h1"
              gutterBottom={true}
            >
              {fintelDesign.name}
            </Typography>
          </div>
          <div style={{ display: 'flex', alignItems: 'center' }}>
            <div style={{ display: 'flex' }}>
              <div style={{ marginRight: theme.spacing(0.5) }}>
                {canDelete && (
                  <PopoverMenu>
                    {({ closeMenu }) => (
                      <Box>
                        <MenuItem onClick={() => {
                          handleOpenDelete();
                          closeMenu();
                        }}
                        >
                          {t_i18n('Delete')}
                        </MenuItem>
                      </Box>
                    )}
                  </PopoverMenu>
                )}
              </div>
              <FintelDesignDeletion
                id={fintelDesign.id}
                isOpen={openDelete}
                handleClose={handleCloseDelete}
              />
              <FintelDesignEdition
                fintelDesignId={fintelDesign.id}
                overviewData={queryResult.fintelDesign}
              />
            </div>
          </div>
        </FintelDesignHeader>
        <Grid
          container
          spacing={3}
        >
          <Grid size={{ xs: 4 }}>
            <Card title={t_i18n('Configuration')}>
              <FintelDesignForm
                fintelDesign={fintelDesign}
                onFileUploaded={buildPreview}
              />
            </Card>
          </Grid>
          <Grid size={{ xs: 8 }} sx={{ height: 'calc(100vh - 250px)' }}>
            <Card title={t_i18n('Preview')}>
              {pdf && (
                <PdfViewer pdf={pdf} />
              )}
            </Card>
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
