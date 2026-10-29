import { Card, CardContent, CardFooter, CardHeader, CardSubtitle, CardTitle } from '@filigran/design-system';
import React, { FunctionComponent, useState } from 'react';
import Tag from '../../../components/common/tag/Tag';
import { useFormatter } from '../../../components/i18n';
import { useXTMHubResourceLink } from '../../../utils/hooks/useXTMHubResourceLink';
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

const NewsFeedBlogPostCard: FunctionComponent<NewsFeedBlogPostCardProps> = ({ item }) => {
  const { t_i18n, fsd } = useFormatter();
  const [isImageBroken, setIsImageBroken] = useState(false);

  // Every metadata but the url path is optional, and comes from an external source: nothing is trusted.
  const href = useXTMHubResourceLink(getNewsFeedMetadataValue(item.metadata, 'url_path'));
  const imageUrl = toSafeHttpUrl(getNewsFeedMetadataValue(item.metadata, 'image_url') ?? null);
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
      // The article is on the Filigran blog: it opens in a new tab, never in the platform.
      onClick={href ? () => window.open(href, '_blank', 'noopener,noreferrer') : undefined}
    >
      {imageUrl && !isImageBroken && (
        <img
          src={imageUrl}
          alt={imageAlt}
          loading="lazy"
          onError={() => setIsImageBroken(true)}
          style={{ display: 'block', width: '100%', height: 150, objectFit: 'cover' }}
        />
      )}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 16, padding: 24 }}>
        <CardHeader>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, minWidth: 0, flex: 1 }}>
            <CardTitle as="h3">{item.title}</CardTitle>
            {hasSubtitle && (
              <CardSubtitle
                endAdornment={readMinutes !== undefined
                  ? <span style={{ whiteSpace: 'nowrap' }}>{t_i18n('{count} min read', { values: { count: readMinutes } })}</span>
                  : undefined}
              >
                {authors.join(', ')}
              </CardSubtitle>
            )}
          </div>
        </CardHeader>
        {description && <CardContent>{description}</CardContent>}
        <CardFooter>
          <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 8 }}>
            {tags.map((tag) => <Tag key={tag} label={tag} />)}
          </div>
          <time dateTime={item.creation_date} style={{ whiteSpace: 'nowrap' }}>{fsd(item.creation_date)}</time>
        </CardFooter>
      </div>
    </Card>
  );
};

export default NewsFeedBlogPostCard;
