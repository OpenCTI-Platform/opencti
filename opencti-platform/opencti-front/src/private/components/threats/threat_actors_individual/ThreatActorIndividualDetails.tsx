import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { useFormatter } from '../../../../components/i18n';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';
import {
  ThreatActorIndividualDetails_ThreatActorIndividual$data,
  ThreatActorIndividualDetails_ThreatActorIndividual$key,
} from './__generated__/ThreatActorIndividualDetails_ThreatActorIndividual.graphql';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import ImageCarousel, { ImagesData } from '../../../../components/ImageCarousel';
import ThreatActorIndividualLocation from './ThreatActorIndividualLocation';
import ThreatActorIndividualDetailsChips from './ThreatActorIndividualDetailsChips';
import Card from '../../../../components/common/card/Card';
import Label from '../../../../components/common/label/Label';
import Tag from '@common/tag/Tag';
import TextList from '../../../../components/TextList';

const ThreatActorIndividualDetailsFragment = graphql`
  fragment ThreatActorIndividualDetails_ThreatActorIndividual on ThreatActorIndividual
  {
    id
    first_seen
    last_seen
    description
    threat_actor_types
    sophistication
    resource_level
    personal_motivations
    primary_motivation
    secondary_motivations
    goals
    roles
    stixCoreRelationships {
      edges {
        node {
          id
          relationship_type
          to {
            ... on Individual {
              id
              name
            }
            ... on Persona {
              id
              observable_value
              persona_type
            }
          }
        }
      }
    }
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
    ...ThreatActorIndividualLocations_locations
  }
`;

interface ThreatActorIndividualDetailsProps {
  threatActorIndividualData: ThreatActorIndividualDetails_ThreatActorIndividual$key;
}

const ThreatActorIndividualDetails: FunctionComponent<
  ThreatActorIndividualDetailsProps
> = ({ threatActorIndividualData }) => {
  const { t_i18n, fldt } = useFormatter();
  const data: ThreatActorIndividualDetails_ThreatActorIndividual$data = useFragment(
    ThreatActorIndividualDetailsFragment,
    threatActorIndividualData,
  );

  const imagesCarousel: { images: ImagesData } = {
    images: {
      edges: (data.images?.edges ?? []).filter((n) => n?.node?.metaData?.inCarousel),
    } as ImagesData,
  };
  const hasImages = imagesCarousel.images?.edges ? imagesCarousel.images.edges.length > 0 : false;

  return (
    <Card title={t_i18n('Details')}>
      <Grid container={true} spacing={2}>
        <Grid item xs={hasImages ? 7 : 6}>
          <Grid container={true} spacing={2}>
            {hasImages && (
              <Grid item xs={4}>
                <ImageCarousel data={imagesCarousel} />
              </Grid>
            )}
            <Grid item xs={hasImages ? 8 : 12}>
              <Label>
                {t_i18n('Threat actor types')}
              </Label>
              <FieldOrEmpty source={data.threat_actor_types}>
                {data.threat_actor_types?.map((threatActorIndividualType) => threatActorIndividualType && (
                  <Tag
                    key={threatActorIndividualType}
                    label={threatActorIndividualType}
                  />
                ))}
              </FieldOrEmpty>
              <Label
                sx={{ marginTop: 2 }}
              >
                {t_i18n('Description')}
              </Label>
              <ExpandableMarkdown
                source={data.description}
                limit={hasImages ? 400 : 600}
              />
            </Grid>
          </Grid>
        </Grid>
        <Grid item xs={hasImages ? 5 : 6}>
          <ThreatActorIndividualDetailsChips
            data={data}
            relType="known-as"
          />
          <ThreatActorIndividualDetailsChips
            data={data}
            relType="impersonates"
          />
          <ThreatActorIndividualLocation threatActorIndividual={data} />
          <Label sx={{ marginTop: '20px' }}>
            {t_i18n('First seen')}
          </Label>
          {fldt(data.first_seen)}
          <Label sx={{ marginTop: '20px' }}>
            {t_i18n('Last seen')}
          </Label>
          {fldt(data.last_seen)}
        </Grid>
      </Grid>
      <Grid container={true} spacing={2}>
        <Grid item xs={4}>
          <Label>
            {t_i18n('Sophistication')}
          </Label>
          <FieldOrEmpty source={data.sophistication}>
            <ItemOpenVocab
              type="threat-actor-individual-sophistication-ov"
              value={data.sophistication}
              small
            />
          </FieldOrEmpty>
        </Grid>
        <Grid item xs={4}>
          <Label>
            {t_i18n('Resource level')}
          </Label>
          <FieldOrEmpty source={data.resource_level}>
            <ItemOpenVocab
              type="attack-resource-level-ov"
              value={data.resource_level}
              small
            />
          </FieldOrEmpty>
        </Grid>
        <Grid item xs={4}>
          <Label>
            {t_i18n('Primary motivation')}
          </Label>
          <FieldOrEmpty source={data.primary_motivation}>
            <ItemOpenVocab
              type="attack-motivation-ov"
              value={data.primary_motivation}
              small
            />
          </FieldOrEmpty>
        </Grid>
        <Grid item xs={4}>
          <Label>
            {t_i18n('Roles')}
          </Label>
          <TextList
            list={data.roles}
          />
        </Grid>
        <Grid item xs={4}>
          <Label>
            {t_i18n('Goals')}
          </Label>
          <TextList
            list={data.goals}
          />
        </Grid>
        <Grid item xs={4}>
          <Label>
            {t_i18n('Secondary motivations')}
          </Label>
          <TextList
            list={data.secondary_motivations}
          />
        </Grid>
        <Grid item xs={4}>
          <Label>
            {t_i18n('Personal motivations')}
          </Label>
          <TextList
            list={data.personal_motivations}
          />
        </Grid>
      </Grid>
    </Card>
  );
};

export default ThreatActorIndividualDetails;
