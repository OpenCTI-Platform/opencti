import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import FintelDesignPopover from '@components/settings/fintel_design/FintelDesignPopover';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/styles';
import Paper from '@mui/material/Paper';
import { useParams } from 'react-router-dom';
import { FintelDesign_fintelDesign$key } from '@components/settings/fintel_design/__generated__/FintelDesign_fintelDesign.graphql';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import PageContainer from '../../../../components/PageContainer';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { FintelDesignQuery } from './__generated__/FintelDesignQuery.graphql';
import CustomizationMenu from "@components/settings/CustomizationMenu";
import Breadcrumbs from "../../../../components/Breadcrumbs";

const fintelDesignQuery = graphql`
  query FintelDesignQuery($id: String!) {
    fintelDesign(id: $id) {
      id
      name
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
  console.log('fintalDesign', fintelDesign);
  if (!fintelDesign) return null;

  return (
    <>
      <div>
        <Typography
          variant="h1"
          gutterBottom={true}
          style={{ float: 'left', marginRight: 10 }}
        >
          {fintelDesign.name}
        </Typography>
        <div style={{
          float: 'left',
          marginTop: -6,
        }}
        >
          <FintelDesignPopover data={fintelDesign}/>
        </div>
      </div>
      <div className="clearfix"/>
      <PageContainer withRightMenu>
        <CustomizationMenu />
        <Breadcrumbs
          noMargin
          elements={[
            { label: t_i18n('Settings') },
            { label: t_i18n('Customization') },
            { label: t_i18n('Fintel Designs'), link: '/dashboard/settings/customization/fintel_designs' },
            { label: `${fintelDesign.name}`, current: true },
          ]}
        />
        <Grid
          container={true}
          spacing={3}
          style={{ margin: 0, paddingRight: 20 }}
        >
          <Grid item xs={6} style={{ paddingLeft: 0 }}>
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
              <Grid item xs={12}>
                <Typography variant="h3" gutterBottom={true}>
                  {t_i18n('Logo')}
                </Typography>
              </Grid>
              <Grid item xs={12}>
                <Typography variant="h3" gutterBottom={true} style={{ marginTop: 20 }}>
                  {t_i18n('Gradiant color')}
                </Typography>
              </Grid>
              <Grid item xs={12}>
                <Typography variant="h3" gutterBottom={true} style={{ marginTop: 20 }}>
                  {t_i18n('Cover page text color')}
                </Typography>
              </Grid>
            </Paper>
          </Grid>
          <Grid item xs={6}>
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
              <div>coucou</div>
            </Paper>
          </Grid>
        </Grid>
      </PageContainer>
    </>
  );
};

const FintelDesign = () => {
  const { fintelDesignId } = useParams() as { fintelDesignId: string };
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
