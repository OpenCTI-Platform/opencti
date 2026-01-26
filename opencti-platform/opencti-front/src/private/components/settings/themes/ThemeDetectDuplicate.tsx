import React, { FunctionComponent, useEffect, useState } from 'react';
import { graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import { fetchQuery } from '../../../../relay/environment';
import { ThemeDetectDuplicateQuery$data } from './__generated__/ThemeDetectDuplicateQuery.graphql';

const themesQuery = graphql`
  query ThemeDetectDuplicateQuery($filters: FilterGroup) {
    themes(filters: $filters) {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;

interface ThemeDetectDuplicateProps {
  themeName: string;
  themeId?: string;
}

const ThemeDetectDuplicate: FunctionComponent<ThemeDetectDuplicateProps> = ({
  themeName,
  themeId,
}) => {
  const { t_i18n } = useFormatter();
  const [duplicateCount, setDuplicateCount] = useState<number>(0);

  useEffect(() => {
    const fetchDuplicates = async () => {
      if (themeName.length < 2) {
        setDuplicateCount(0);
        return;
      }

      try {
        const data = await fetchQuery(themesQuery, {
          filters: {
            mode: 'and',
            filters: [{
              key: 'name',
              values: [themeName],
              operator: 'search',
            }],
            filterGroups: [],
          },
        }).toPromise();

        const result = data as ThemeDetectDuplicateQuery$data;
        const themes = result.themes?.edges ?? [];

        const duplicates = themes
          .filter((theme) => theme?.node.id !== themeId)
          .map((theme) => theme?.node.name)
          .filter(Boolean);

        setDuplicateCount(duplicates.length);
      } catch (_error) {
        // console.error('Failed to fetch duplicate themes:', error);
        setDuplicateCount(0);
      }
    };

    fetchDuplicates();
  }, [themeName, themeId]);

  const renderMessage = () => {
    if (duplicateCount === 0) {
      return t_i18n('No potential duplicate entities has been found.');
    }

    if (duplicateCount === 1) {
      return `1 ${t_i18n('potential duplicate entity')} ${t_i18n('has been found.')}`;
    }

    return `${duplicateCount} ${t_i18n('potential duplicate entities')} ${t_i18n('have been found.')}`;
  };

  return <span>{renderMessage()}</span>;
};

export default ThemeDetectDuplicate;
