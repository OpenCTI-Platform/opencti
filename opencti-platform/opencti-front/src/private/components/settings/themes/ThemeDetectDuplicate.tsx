import React, { FunctionComponent, useEffect, useState } from 'react';
import { graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import { fetchQuery } from '../../../../relay/environment';
import { ThemeDetectDuplicateQuery$data } from './__generated__/ThemeDetectDuplicateQuery.graphql';

const themesQuery = graphql`
  query ThemeDetectDuplicateQuery(
    $search: String
  ) {
    themes(search: $search) {
      edges {
        node {
          name
        }
      }
    }
  }
`;

interface ThemeDetectDuplicateProps {
  themeName: string;
}

const ThemeDetectDuplicate: FunctionComponent<ThemeDetectDuplicateProps> = ({
  themeName,
}) => {
  const { t_i18n } = useFormatter();
  const [potentialDuplicates, setPotentialDuplicates] = useState<string[]>([]);

  useEffect(() => {
    if (themeName.length >= 2) {
      fetchQuery(themesQuery, { search: themeName })
        .toPromise()
        .then((data) => {
          const themes = (data as ThemeDetectDuplicateQuery$data).themes?.edges ?? [];
          const themeNames = themes
            .filter((theme) => !!theme)
            .map((theme) => theme?.node.name);
          setPotentialDuplicates(themeNames);
        });
    }
  }, [themeName]);

  if (potentialDuplicates.length > 1) {
    return (
      <span>
        {potentialDuplicates.length} {t_i18n('potential duplicate entities')}
        {' '}
        {t_i18n('have been found.')}
      </span>
    );
  } if (potentialDuplicates.length === 1) {
    return (
      <span>
        1 {t_i18n('potential duplicate entity')}
        {' '}
        {t_i18n('has been found.')}
      </span>
    );
  }
  return (
    <span>{t_i18n('No potential duplicate entities has been found.')}</span>
  );
};

export default ThemeDetectDuplicate;
