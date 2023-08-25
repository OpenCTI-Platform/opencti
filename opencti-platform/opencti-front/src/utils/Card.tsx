import Tooltip from '@mui/material/Tooltip';
import React from 'react';
import { APP_BASE_PATH } from '../relay/environment';

export interface ImageEdges {
  edges: ReadonlyArray<{
    node: {
      id: string,
      name: string,
      metaData: {
        inCarousel: boolean | null;
        description: string | null;
      } | null
    }
  } | null> | null
}

export interface toEdgesLocated {
  edges: ReadonlyArray<{ node: { to: { x_opencti_aliases?: ReadonlyArray<string | null> | null; name: string } | null } }>;
}

export const getAvatarImage = (images: ImageEdges | null | undefined) => {
  const imagesList = images?.edges ?? [];
  const inCarouselImages = imagesList ? imagesList.filter((n) => n?.node?.metaData?.inCarousel === true) : [];
  return (inCarouselImages.length > 0 ? inCarouselImages[0]?.node : null);
};

export const renderCardTitle = (entity: { countryFlag?: toEdgesLocated | null | undefined; name: string; }) => {
  if ((entity.countryFlag?.edges ?? []).length > 0) {
    const country = entity.countryFlag?.edges[0]?.node?.to;
    const flag = country?.x_opencti_aliases
      ? country.x_opencti_aliases.find((a) => a?.length === 2) : null;
    if (flag && country) {
      return (
        <div style={{ display: 'inline-flex' }}>
          <div style={{ paddingTop: 2 }}>
            <Tooltip title={country.name}>
            <img
              style={{ width: 20 }}
              src={`${APP_BASE_PATH}/static/flags/4x3/${flag.toLowerCase()}.svg`}
              alt={country.name}
            />
            </Tooltip>
          </div>
          <div style={{ marginLeft: 10 }}>
            {entity.name}
          </div>
        </div>
      );
    }
  }
  return entity.name;
};
