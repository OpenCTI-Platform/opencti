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

export const getAvatarImage = (images: ImageEdges | null | undefined) => {
  const imagesList = images?.edges ?? [];
  const inCarouselImages = imagesList ? imagesList.filter((n) => n?.node?.metaData?.inCarousel === true) : [];
  return (inCarouselImages.length > 0 ? inCarouselImages[0]?.node : null);
};
