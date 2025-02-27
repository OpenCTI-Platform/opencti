import React from 'react';
import { makeStyles } from '@mui/styles';
import { Chip, Grid, Paper, Typography } from '@mui/material';
import AddThreatActorIndividualDemographic from '@components/threats/threat_actors_individual/AddThreatActorIndividualDemographic';
import { useFormatter } from '../../../../components/i18n';
import { ThreatActorIndividual_ThreatActorIndividual$data } from './__generated__/ThreatActorIndividual_ThreatActorIndividual.graphql';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';
import type { Theme } from '../../../../components/Theme';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import CardLabel from '../../../../components/CardLabel';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  paper: {
    marginTop: theme.spacing(1),
    padding: '15px',
    borderRadius: 4,
  },
}));

interface ThreatActorIndividualDemographicsCountryRelationships {
  country_of_residence: Array<string>;
  citizenship: Array<string>;
  nationality: Array<string>;
  place_of_birth: string | undefined;
  ethnicity: string | undefined;
}

interface ThreatActorIndividualDemographicsProps {
  threatActorIndividual: ThreatActorIndividual_ThreatActorIndividual$data;
}

const ThreatActorIndividualDemographics = ({
  threatActorIndividual,
}: ThreatActorIndividualDemographicsProps) => {
  const classes = useStyles();
  const { t_i18n, fsd } = useFormatter();
  const countryRelationship: ThreatActorIndividualDemographicsCountryRelationships = {
    country_of_residence: [],
    citizenship: [],
    nationality: [],
    place_of_birth: threatActorIndividual.bornIn?.name,
    ethnicity: threatActorIndividual.ethnicity?.name,
  };
  const edges = threatActorIndividual.stixCoreRelationships?.edges ?? [];
  for (const { node } of edges) {
    const { relationship_type } = node ?? {};
    const name = node?.to?.name;
    if (name) {
      switch (relationship_type) {
        case 'resides-in':
          countryRelationship.country_of_residence.push(name);
          break;
        case 'citizen-of':
          countryRelationship.citizenship.push(name);
          break;
        case 'national-of':
          countryRelationship.nationality.push(name);
          break;
        default:
      }
    }
  }
  return (
    <>
      <Typography variant="h4" gutterBottom={true}>
        {t_i18n('Demographic Information')}
      </Typography>
      <Paper classes={{ root: classes.paper }} className={'paper-for-grid'} variant="outlined">
        <Grid container={true} spacing={3}>
          <Grid item xs={4}>
            <CardLabel action={(
              <Security
                needs={[KNOWLEDGE_KNUPDATE]}
              >
                <AddThreatActorIndividualDemographic
                  threatActorIndividual={threatActorIndividual}
                  relType='resides-in'
                  title={t_i18n('Add country of residence')}
                />
              </Security>
            )}
            >
              {t_i18n('Country of Residence')}
            </CardLabel>
            <div id="country_of_residence_list">
              <FieldOrEmpty source={countryRelationship.country_of_residence}>
                {countryRelationship.country_of_residence.map(
                  (place: string, index: number) => (
                    <Chip
                      key={index}
                      label={t_i18n(place)}
                      style={{ margin: 1 }}
                    />
                  ),
                )}
              </FieldOrEmpty>
            </div>
          </Grid>
          <Grid item xs={4}>
            <CardLabel action={(
              <Security
                needs={[KNOWLEDGE_KNUPDATE]}
              >
                <AddThreatActorIndividualDemographic
                  threatActorIndividual={threatActorIndividual}
                  relType='citizen-of'
                  title={'Add citizenship'}
                />
              </Security>
            )}
            >
              {t_i18n('Citizenship')}
            </CardLabel>
            <div id="citizenship_list">
              <FieldOrEmpty source={countryRelationship.citizenship}>
                {countryRelationship.citizenship.map(
                  (place: string, index: number) => (
                    <Chip
                      key={index}
                      label={t_i18n(place)}
                      style={{ margin: 1 }}
                    />
                  ),
                )}
              </FieldOrEmpty>
            </div>
          </Grid>
          <Grid item xs={4}>
            <CardLabel >
              {t_i18n('Place of Birth')}
            </CardLabel>
            <div id="place_of_birth">
              {t_i18n(countryRelationship.place_of_birth ?? '-')}
            </div>
          </Grid>
          <Grid item xs={4}>
            <CardLabel >
              {t_i18n('Date of Birth')}
            </CardLabel>
            <div id="date_of_birth">
              {threatActorIndividual.date_of_birth
                ? fsd(threatActorIndividual.date_of_birth)
                : '-'}
            </div>
          </Grid>
          <Grid item xs={4}>
            <CardLabel action={(
              <Security needs={[KNOWLEDGE_KNUPDATE]}>
                <AddThreatActorIndividualDemographic
                  threatActorIndividual={threatActorIndividual}
                  relType='national-of'
                  title={t_i18n('Add nationality')}
                />
              </Security>
            )}
            >
              {t_i18n('Nationality')}
            </CardLabel>
            <div id="nationality">
              <FieldOrEmpty source={countryRelationship.nationality}>
                {countryRelationship.nationality.map(
                  (place: string, index: number) => (
                    <Chip
                      key={index}
                      label={t_i18n(place)}
                      style={{ margin: 1 }}
                    />
                  ),
                )}
              </FieldOrEmpty>
            </div>
          </Grid>
          <Grid item xs={4}>
            <CardLabel >
              {t_i18n('Ethnicity')}
            </CardLabel>
            <div id="ethnicity">{t_i18n(countryRelationship.ethnicity ?? '-')}</div>
          </Grid>
          <Grid item xs={4}>
            <CardLabel >
              {t_i18n('Gender')}
            </CardLabel>
            <FieldOrEmpty source={threatActorIndividual.gender}>
              <ItemOpenVocab
                type="gender-ov"
                value={threatActorIndividual.gender}
                small
              />
            </FieldOrEmpty>
          </Grid>
          <Grid item xs={4}>
            <CardLabel >
              {t_i18n('Marital Status')}
            </CardLabel>
            <FieldOrEmpty source={threatActorIndividual.marital_status}>
              <ItemOpenVocab
                type="marital-status-ov"
                value={threatActorIndividual.marital_status}
                small
              />
            </FieldOrEmpty>
          </Grid>
          <Grid item xs={4}>
            <CardLabel >
              {t_i18n('Job Title')}
            </CardLabel>
            <FieldOrEmpty source={threatActorIndividual.job_title}>
              <div id="job_title">{threatActorIndividual.job_title}</div>
            </FieldOrEmpty>
          </Grid>
        </Grid>
      </Paper>
    </>
  );
};

export default ThreatActorIndividualDemographics;
