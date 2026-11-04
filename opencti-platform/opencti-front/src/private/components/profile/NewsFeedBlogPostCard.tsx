import { Card, CardContent, CardFooter, CardHeader, CardSubtitle, CardTitle, Text } from '@filigran/design-system';
import { Box } from '@mui/material';
import React, { FunctionComponent, useState } from 'react';
import { useFormatter } from '../../../components/i18n';
import { useXTMHubResourceLink } from '../../../utils/hooks/useXTMHubResourceLink';
import NewsFeedTags from './NewsFeedTags';
import { getNewsFeedMetadataValue, parseNewsFeedAuthorNames, parseNewsFeedReadMinutes } from '../../../utils/NewsFeed';
import { toSafeHttpUrl } from '../../../utils/url';

export interface NewsFeedBlogPostData {
  id: string;
  title: string;
  tags: readonly (string | null | undefined)[];
  metadata: readonly ({ readonly key: string; readonly value: string | null | undefined } | null | undefined)[];
  creation_date: string;
}

interface NewsFeedBlogPostCardProps {
  item: NewsFeedBlogPostData;
}

// Blog titles can be long: the design system truncates the card title on one line, here it is
// entirely displayed instead, in a smaller size so it stays compact.
const titleSx = {
  '& .truncate': {
    overflow: 'visible',
    whiteSpace: 'normal',
    textOverflow: 'clip',
    overflowWrap: 'anywhere',
    fontSize: 'var(--text-title-xs)',
    lineHeight: 'var(--leading-title-xs)',
    fontWeight: 'var(--font-weight-title-xs)',
  },
};

const NewsFeedBlogPostCard: FunctionComponent<NewsFeedBlogPostCardProps> = ({ item }) => {
  const { t_i18n, fsd } = useFormatter();
  // The url of the image that failed to load: a corrected url sent later by the Hub gets a new chance.
  const [brokenImageUrl, setBrokenImageUrl] = useState<string | null>(null);

  // Every metadata but the url path is optional, and comes from an external source: nothing is trusted.
  const href = useXTMHubResourceLink(getNewsFeedMetadataValue(item.metadata, 'url_path'));
  const imageUrl = toSafeHttpUrl(getNewsFeedMetadataValue(item.metadata, 'image_url') ?? null);
  const isImageBroken = imageUrl !== null && imageUrl === brokenImageUrl;
  const imageAlt = getNewsFeedMetadataValue(item.metadata, 'image_alt') ?? '';
  const description = getNewsFeedMetadataValue(item.metadata, 'description');
  const authors = parseNewsFeedAuthorNames(getNewsFeedMetadataValue(item.metadata, 'author_names'));
  const readMinutes = parseNewsFeedReadMinutes(getNewsFeedMetadataValue(item.metadata, 'read_minutes'));
  const tags = item.tags.filter((tag): tag is string => !!tag);

  const hasSubtitle = authors.length > 0 || readMinutes !== undefined;

  return (
    <Card
      padding={0}
      gap={0}
      // clips the image to the rounded corners of the card
      style={{ overflow: 'hidden' }}
      // The article is on the Filigran blog: it opens in a new tab, never in the platform.
      onClick={href ? () => window.open(href, '_blank', 'noopener,noreferrer') : undefined}
    >
      {imageUrl && !isImageBroken && (
        <img
          src={imageUrl}
          alt={imageAlt}
          loading="lazy"
          onError={() => setBrokenImageUrl(imageUrl)}
          style={{ display: 'block', width: '100%', height: 150, objectFit: 'cover' }}
        />
      )}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 16, padding: 24 }}>
        <CardHeader>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, minWidth: 0, flex: 1 }}>
            <Box sx={titleSx}>
              <CardTitle as="h3">{item.title}</CardTitle>
            </Box>
            {hasSubtitle && (
              // the read time sticks to the right of the card, the authors take the remaining space
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, minWidth: 0 }}>
                <div style={{ minWidth: 0, flex: 1 }}>
                  {authors.length > 0 && <CardSubtitle>{authors.join(', ')}</CardSubtitle>}
                </div>
                {readMinutes !== undefined && (
                  <Text variant="content-compact" className="text-default-secondary" style={{ whiteSpace: 'nowrap' }}>
                    {t_i18n('{count} min read', { values: { count: readMinutes } })}
                  </Text>
                )}
              </div>
            )}
          </div>
        </CardHeader>
        {description && <CardContent>{description}</CardContent>}
        <CardFooter>
          {/* the tags that do not fit are hidden behind a "+N" tag, with a tooltip */}
          <div style={{ flex: 1, minWidth: 0 }}>
            <NewsFeedTags tags={tags} />
          </div>
          <time dateTime={item.creation_date} style={{ whiteSpace: 'nowrap' }}>{fsd(item.creation_date)}</time>
        </CardFooter>
      </div>
    </Card>
  );
};

export default NewsFeedBlogPostCard;
