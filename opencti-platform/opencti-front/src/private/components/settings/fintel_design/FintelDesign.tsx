import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import FintelDesignPopover from '@components/settings/fintel_design/FintelDesignPopover';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/styles';
import Paper from '@mui/material/Paper';
import { FintelDesign_fintelDesign$key } from './__generated__/FintelDesign_fintelDesign.graphql';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import PageContainer from '../../../../components/PageContainer';

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
  fintelDesignData: FintelDesign_fintelDesign$key;
}

const FintelDesign: FunctionComponent<FintelDesignComponentProps> = ({
  fintelDesignData,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const fintelDesign = useFragment<FintelDesign_fintelDesign$key>(
    fintelDesignComponentFragment,
    fintelDesignData,
  );

  console.log('fintelDesign', fintelDesign);

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
                <Typography variant="h3" gutterBottom={true}>
                  {t_i18n('Gradiant color')}
                </Typography>
              </Grid>
              <Grid item xs={12}>
                <Typography variant="h3" gutterBottom={true}>
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

export default FintelDesign;
