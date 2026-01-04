import { useState, useEffect } from 'react';

export interface Post {
  id: string;
  title: string;
  category?: string;
  createdAt: string;
  [key: string]: any; // Allow additional fields for different tab types
}

export interface PostsData {
  data: Post[];
  total: number;
  loading: boolean;
  error: string | null;
}

interface UsePostsDataParams {
  tab: number;
  page: number;
  perPage: number;
  filters?: string[];
  searchText?: string;
}

// Tab definitions
const TAB_NAMES = [
  'telegram',      // 0: Telegram Recents
  'exploid',       // 1: Exploid Posts
  'russian-market', // 2: Russian Market Items
  'intelx-leaks',  // 3: IntelX Leaks
  'intelx-items',  // 4: IntelX Items
];

export const usePostsData = ({
  tab,
  page,
  perPage,
  filters = [],
  searchText = '',
}: UsePostsDataParams): PostsData => {
  const [data, setData] = useState<Post[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchData = async () => {
      // API endpoint - using the same endpoint as resaa-dwm-panel
      const apiUrl = (window as any).RESSA_DWM_API_URL 
        || (window as any).PUBLIC_VITE_API_URL 
        || 'http://172.16.40.15:3400';
      const endpoint = `${apiUrl}/graphql`;

      try {
        setLoading(true);
        setError(null);

        const tabName = TAB_NAMES[tab];
        if (!tabName) {
          setData([]);
          setTotal(0);
          setLoading(false);
          return;
        }

        // Build filters array
        let allFilters = [...filters];
        if (searchText) {
          // Add search filter based on tab type
          allFilters.push(`title:${searchText}:contains`);
        }

        // Determine which query to use based on tab
        let query = '';
        let variables: any = {
          page,
          perPage,
        };

        switch (tab) {
          case 0: // Telegram Recents
            query = `
              query GetTelegramMessages($filters: [String], $page: Int, $perPage: Int) {
                getTelegramMessages(page: $page, perPage: $perPage, filters: $filters) {
                  total
                  data {
                    id
                    messageId
                    message
                    date
                    channel {
                      id
                      title
                      username
                    }
                  }
                }
              }
            `;
            variables.filters = allFilters;
            break;

          case 1: // Exploit Posts
            query = `
              query GetExploitPosts($filters: Object, $page: Int, $perPage: Int) {
                getExploitPosts(page: $page, perPage: $perPage, filters: $filters) {
                  total
                  data {
                    id
                    title
                    categoryId
                    createdAt
                    createdDate
                  }
                }
              }
            `;
            // For Exploit Posts, filters should be an object, not array
            variables.filters = allFilters.length > 0 ? Object.fromEntries(allFilters.map(f => f.split(':'))) : {};
            break;

          case 2: // Russian Market Items
            query = `
              query GetRussianItems($filters: [String], $page: Int, $perPage: Int) {
                getRussianItems(page: $page, perPage: $perPage, filters: $filters) {
                  total
                  data {
                    id
                    stealer
                    vendor
                    price
                    date
                    created_at
                  }
                }
              }
            `;
            break;

          case 3: // IntelX Leaks
            query = `
              query GetIntelxItems($filters: [String], $page: Int, $perPage: Int, $leak: Boolean) {
                getIntelxItems(page: $page, perPage: $perPage, filters: $filters, leak: $leak) {
                  total
                  data {
                    id
                    created_at
                    updated_at
                    date
                    added
                    user
                    password
                    domain
                    passwordtype
                    bucket
                    sourceshort
                    sourcelong
                    systemid
                  }
                }
              }
            `;
            variables.filters = allFilters;
            variables.leak = true;
            break;

          case 4: // IntelX Items
            query = `
              query GetIntelxItems($filters: [String], $page: Int, $perPage: Int, $leak: Boolean) {
                getIntelxItems(page: $page, perPage: $perPage, filters: $filters, leak: $leak) {
                  total
                  data {
                    id
                    domain
                    created_at
                    updated_at
                    item {
                      owner
                      systemid
                      storageid
                      instore
                      size
                      accesslevel
                      type
                      media
                      date
                      added
                      name
                      description
                      xscore
                      simhash
                      bucket
                      keyvalues
                      tags
                      relations
                    }
                  }
                }
              }
            `;
            variables.filters = allFilters;
            variables.leak = false;
            break;

          default:
            setData([]);
            setTotal(0);
            setLoading(false);
            return;
        }

        const response = await fetch(endpoint, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            query,
            variables,
          }),
        });

        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }

        const result = await response.json();

        if (result.errors) {
          throw new Error(result.errors[0]?.message || 'GraphQL error');
        }

        // Extract data based on query type
        let responseData: Post[] = [];
        let responseTotal = 0;

        if (tab === 0) {
          // Telegram Messages
          const telegramData = result.data?.getTelegramMessages;
          if (telegramData) {
            responseTotal = telegramData.total || 0;
            responseData = (telegramData.data || []).map((msg: any) => ({
              ...msg,
              id: msg.id?.toString() || '',
            }));
          }
        } else if (tab === 1) {
          // Exploit Posts
          const exploitData = result.data?.getExploitPosts;
          if (exploitData) {
            responseTotal = exploitData.total || 0;
            responseData = (exploitData.data || []).map((item: any) => ({
              ...item,
              id: item.id?.toString() || '',
            }));
          }
        } else if (tab === 2) {
          // Russian Market Items
          const russianData = result.data?.getRussianItems;
          if (russianData) {
            responseTotal = russianData.total || 0;
            responseData = (russianData.data || []).map((item: any) => ({
              ...item,
              id: item.id?.toString() || '',
            }));
          }
        } else if (tab === 3 || tab === 4) {
          // IntelX Items/Leaks
          const intelxData = result.data?.getIntelxItems;
          if (intelxData) {
            responseTotal = intelxData.total || 0;
            responseData = (intelxData.data || []).map((item: any) => ({
              ...item,
              id: item.id?.toString() || '',
            }));
          }
        }

        setData(responseData);
        setTotal(responseTotal);
      } catch (err) {
        const errorMessage = err instanceof Error ? err.message : 'Failed to fetch data';
        setError(errorMessage);
        console.error('Error fetching Posts data:', err);
        console.error('Endpoint used:', endpoint);
        // Set empty data on error
        setData([]);
        setTotal(0);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [tab, page, perPage, JSON.stringify(filters), searchText]);

  return { data, total, loading, error };
};
