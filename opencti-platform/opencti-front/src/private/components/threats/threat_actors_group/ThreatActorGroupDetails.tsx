import React from 'react';
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
import CustomFieldValuesDisplay from '@components/common/custom_fields/CustomFieldValuesDisplay';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { useFormatter } from '../../../../components/i18n';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import ImageCarousel, { ImagesData } from '../../../../components/ImageCarousel';
import ItemScore from '../../../../components/ItemScore';
import ThreatActorGroupLocation from './ThreatActorGroupLocation';
import Card from '@common/card/Card';
import Label from '../../../../components/common/label/Label';
import Tag from '../../../../components/common/tag/Tag';
import TextList from '../../../../components/common/text/TextList';
import { Stack } from '@mui/material';
import { ThreatActorGroupDetails_ThreatActorGroup$key } from './__generated__/ThreatActorGroupDetails_ThreatActorGroup.graphql';

const threatActorGroupDetailsFragment = graphql`
  fragment ThreatActorGroupDetails_ThreatActorGroup on ThreatActorGroup {
    id
    entity_type
    customFieldValues {
      ...CustomFieldValuesDisplay_values @relay(mask: false)
    }
    first_seen
    last_seen
    description
    threat_actor_types
    sophistication
    resource_level
    x_opencti_score
    primary_motivation
    secondary_motivations
    goals
    roles
    images: importFiles(prefixMimeType: "image/") {
      edges {
        node {
          id
          name
          metaData {
            mimetype
            order
            inCarousel
            description
          }
        }
      }
    }
    ...ThreatActorGroupLocations_locations
  }
`;

interface ThreatActorGroupDetailsProps {
  threatActorGroup: ThreatActorGroupDetails_ThreatActorGroup$key;
}

const ThreatActorGroupDetails = ({ threatActorGroup: threatActorGroupKey }: ThreatActorGroupDetailsProps) => {
  const { t_i18n, fldt } = useFormatter();
  const threatActorGroup = useFragment(threatActorGroupDetailsFragment, threatActorGroupKey);
  const hasImages = (threatActorGroup.images?.edges ?? []).some((n) => n?.node?.metaData?.inCarousel);

  return (
    <Card title={t_i18n('Details')}>
      <Grid container={true} spacing={2}>
        {hasImages && (
          <Grid size={4}>
            <ImageCarousel data={{ images: threatActorGroup.images }} />
          </Grid>
        )}
        <Grid size={hasImages ? 8 : 12}>
          <Label>
            {t_i18n('Description')}
          </Label>
          <ExpandableMarkdown
            source={threatActorGroup.description}
            limit={hasImages ? 400 : 600}
          />
        </Grid>
        <Grid size={4}>
          <Label>
            {t_i18n('Threat actor types')}
          </Label>
          <FieldOrEmpty source={threatActorGroup.threat_actor_types}>
            <Stack
              direction="row"
              sx={{
                flexWrap: 'wrap',
                gap: 1,
              }}
            >
              {threatActorGroup.threat_actor_types?.map((threatActorGroupType) => (
                <Tag
                  key={threatActorGroupType}
                  label={threatActorGroupType}
                />
              ))}
            </Stack>
          </FieldOrEmpty>
        </Grid>
        <Grid size={4}>
          <ThreatActorGroupLocation threatActorGroup={threatActorGroup} />
        </Grid>
        <Grid size={4}>
          <Label>
            {t_i18n('First seen')}
          </Label>
          {fldt(threatActorGroup.first_seen)}
          <Label
            sx={{ marginTop: 2 }}
          >
            {t_i18n('Last seen')}
          </Label>
          {fldt(threatActorGroup.last_seen)}
        </Grid>
      </Grid>
      <Grid container={true} spacing={2}>
        <Grid size={4}>
          <Label
            sx={{ marginTop: 2 }}
          >
            {t_i18n('Sophistication')}
          </Label>
          <FieldOrEmpty source={threatActorGroup.sophistication}>
            <ItemOpenVocab
              type="threat-actor-group-sophistication-ov"
              value={threatActorGroup.sophistication}
            />
          </FieldOrEmpty>
        </Grid>
        <Grid size={4}>
          <Label
            sx={{ marginTop: 2 }}
          >
            {t_i18n('Resource level')}
          </Label>
          <FieldOrEmpty source={threatActorGroup.resource_level}>
            <ItemOpenVocab
              type="attack-resource-level-ov"
              value={threatActorGroup.resource_level}
            />
          </FieldOrEmpty>
        </Grid>
        <Grid size={4}>
          <Label
            sx={{ marginTop: 2 }}
          >
            {t_i18n('Primary motivation')}
          </Label>
          <FieldOrEmpty source={threatActorGroup.primary_motivation}>
            <ItemOpenVocab
              type="attack-motivation-ov"
              value={threatActorGroup.primary_motivation}
            />
          </FieldOrEmpty>
        </Grid>
        <Grid size={4}>
          <Label>
            {t_i18n('Roles')}
          </Label>
          <TextList
            list={threatActorGroup.roles}
          />
        </Grid>
        <Grid size={4}>
          <Label>
            {t_i18n('Score')}
          </Label>
          <ItemScore score={threatActorGroup.x_opencti_score} />
        </Grid>
        <Grid size={4}>
          <Label>
            {t_i18n('Goals')}
          </Label>
          <TextList
            list={threatActorGroup.goals}
          />
        </Grid>
        <Grid size={4}>
          <Label>
            {t_i18n('Secondary motivations')}
          </Label>
          <TextList
            list={threatActorGroup.secondary_motivations}
          />
        </Grid>
        <CustomFieldValuesDisplay entityType={threatActorGroup.entity_type} values={threatActorGroup.customFieldValues ?? []} />
      </Grid>
    </Card>
  );
};

export default ThreatActorGroupDetails;
