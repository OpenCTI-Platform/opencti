import { useState, useEffect } from 'react';

export interface RessaDWMData {
  stats: {
    allNewLeaks: { value: number; change: number };
    darkWeb: { value: number; change: number };
    web: { value: number; change: number };
    telegram: { value: number; change: number };
  };
  monitoredSources: { label: string; value: number; color: string }[];
  topLeaks: { name: string; value: number }[];
  topDamageable: { name: string; value: number }[];
  vulnerabilityTrends: { name: string; data: number[]; color: string }[];
  dataLeakTrends: { name: string; data: number[]; color: string }[];
}

export const useRessaDWMData = () => {
  const [data, setData] = useState<RessaDWMData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchData = async () => {
      // API endpoint - using the same endpoint as resaa-dwm-panel
      // The endpoint can be configured via window config, otherwise uses the default
      const apiUrl = (window as any).RESSA_DWM_API_URL 
        || (window as any).PUBLIC_VITE_API_URL 
        || 'http://172.16.40.15:3400';
      const endpoint = `${apiUrl}/graphql`;
      
      try {
        setLoading(true);
        setError(null);
        
        // Calculate date range for last 12 months
        const to = new Date();
        const from = new Date();
        from.setMonth(from.getMonth() - 12);
        
        // GraphQL query for dashboard data
        const dashboardQuery = `
          query GetDashboardData($from: Date, $to: Date) {
            getDashboardData {
              resourcesUnderControl
              allResourcesCount
              allWebResourcesCount
              allDarkWebResourcesCount
              allTelegramResourcesCount
              allResourcesByDate(from: $from, to: $to)
            }
          }
        `;

        // GraphQL query for Top Leaks (Telegram channels)
        const topLeaksQuery = `
          query GetTelegramChannels {
            getTelegramChannels {
              id
              title
              username
              avatarUrl
              lastMessage {
                date
              }
            }
          }
        `;

        // Fetch dashboard data
        const dashboardResponse = await fetch(endpoint, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            query: dashboardQuery,
            variables: {
              from: from.toISOString().split('T')[0],
              to: to.toISOString().split('T')[0],
            },
          }),
        });

        if (!dashboardResponse.ok) {
          throw new Error(`HTTP error! status: ${dashboardResponse.status}`);
        }

        const dashboardResult = await dashboardResponse.json();
        
        if (dashboardResult.errors) {
          throw new Error(dashboardResult.errors[0]?.message || 'GraphQL error');
        }

        // Debug: Log the API response
        console.log('Dashboard API Response:', dashboardResult);
        console.log('Dashboard Data:', dashboardResult.data?.getDashboardData);

        // Fetch Top Leaks (Telegram channels)
        let topLeaksData: { name: string; value: number }[] = [];
        try {
          const topLeaksResponse = await fetch(endpoint, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              query: topLeaksQuery,
            }),
          });

          if (topLeaksResponse.ok) {
            const topLeaksResult = await topLeaksResponse.json();
            if (topLeaksResult.data?.getTelegramChannels) {
              // Get message counts for each channel to determine top leaks
              const channels = topLeaksResult.data.getTelegramChannels;
              
              // Fetch message counts for each channel
              const channelCounts = await Promise.all(
                channels.slice(0, 10).map(async (channel: any) => {
                  try {
                    const messagesQuery = `
                      query GetTelegramMessages($filters: [String]) {
                        getTelegramMessages(page: 1, perPage: 1, filters: $filters) {
                          total
                        }
                      }
                    `;
                    
                    const messagesResponse = await fetch(endpoint, {
                      method: 'POST',
                      headers: {
                        'Content-Type': 'application/json',
                      },
                      body: JSON.stringify({
                        query: messagesQuery,
                        variables: {
                          filters: [`channelId:${channel.id}:=`],
                        },
                      }),
                    });

                    if (messagesResponse.ok) {
                      const messagesResult = await messagesResponse.json();
                      return {
                        name: channel.title || channel.username || 'Unknown',
                        value: messagesResult.data?.getTelegramMessages?.total || 0,
                      };
                    }
                    return null;
                  } catch {
                    return null;
                  }
                })
              );

              topLeaksData = channelCounts
                .filter((item): item is { name: string; value: number } => item !== null)
                .sort((a, b) => b.value - a.value)
                .slice(0, 5);
            }
          }
        } catch (err) {
          console.warn('Failed to fetch Top Leaks:', err);
          // Continue with empty array if Top Leaks fetch fails
        }

        // Fetch Top Damageable (domains with most leaks from Intelx)
        let topDamageableData: { name: string; value: number }[] = [];
        try {
          const topDamageableQuery = `
            query GetIntelxItems($filters: [String], $page: Int, $perPage: Int, $leak: Boolean) {
              getIntelxItems(page: $page, perPage: $perPage, filters: $filters, leak: $leak) {
                total
                data {
                  domain
                }
              }
            }
          `;

          // Fetch leaks with pagination to get all domains
          const damageableResponse = await fetch(endpoint, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              query: topDamageableQuery,
              variables: {
                leak: true,
                page: 1,
                perPage: 100, // Get more items to analyze domains
                filters: [],
              },
            }),
          });

          if (damageableResponse.ok) {
            const damageableResult = await damageableResponse.json();
            if (damageableResult.data?.getIntelxItems?.data) {
              const leaks = damageableResult.data.getIntelxItems.data;
              
              // Group by domain and count
              const domainCounts: { [key: string]: number } = {};
              leaks.forEach((leak: any) => {
                if (leak.domain) {
                  // Extract base domain (remove www, http, etc.)
                  const domain = leak.domain
                    .replace(/^https?:\/\//, '')
                    .replace(/^www\./, '')
                    .split('/')[0]
                    .toLowerCase();
                  
                  if (domain) {
                    domainCounts[domain] = (domainCounts[domain] || 0) + 1;
                  }
                }
              });

              // Convert to array and sort
              topDamageableData = Object.entries(domainCounts)
                .map(([name, value]) => ({ name, value }))
                .sort((a, b) => b.value - a.value)
                .slice(0, 5);
            }
          }
        } catch (err) {
          console.warn('Failed to fetch Top Damageable:', err);
          // Continue with empty array if Top Damageable fetch fails
        }

        // Transform the GraphQL response to match our data structure
        const dashboardData = dashboardResult.data?.getDashboardData;
        if (dashboardData) {
          // Parse resourcesUnderControl (assuming it's a JSON string or object)
          let resourcesUnderControl: any = {};
          try {
            resourcesUnderControl = typeof dashboardData.resourcesUnderControl === 'string'
              ? JSON.parse(dashboardData.resourcesUnderControl)
              : dashboardData.resourcesUnderControl || {};
          } catch {
            resourcesUnderControl = {};
          }

          // Parse allResourcesByDate (assuming it's an array of data points)
          const resourcesByDate = dashboardData.allResourcesByDate || [];
          
          // Debug: Log the resourcesByDate structure
          console.log('Resources by Date from API:', resourcesByDate);
          console.log('First item structure:', resourcesByDate[0]);
          
          // Extract trend data by source from allResourcesByDate
          // The structure can be: 
          // - Array of objects: [{ date, 'dark-web': count, telegram: count, website: count, forum: count }, ...]
          // - Object with source keys: { 'dark-web': [counts], telegram: [counts], website: [counts] }
          const extractTrendData = (sourceKey: string, color: string) => {
            if (!Array.isArray(resourcesByDate) || resourcesByDate.length === 0) {
              // Check if it's an object with arrays
              if (typeof resourcesByDate === 'object' && resourcesByDate !== null && !Array.isArray(resourcesByDate)) {
                const sourceData = (resourcesByDate as any)[sourceKey] || (resourcesByDate as any)[`${sourceKey}Count`];
                if (Array.isArray(sourceData)) {
                  return {
                    name: sourceKey === 'dark-web' ? 'Dark Web' : sourceKey === 'website' ? 'Web' : sourceKey.charAt(0).toUpperCase() + sourceKey.slice(1),
                    data: sourceData,
                    color,
                  };
                }
              }
              return {
                name: sourceKey === 'dark-web' ? 'Dark Web' : sourceKey === 'website' ? 'Web' : sourceKey.charAt(0).toUpperCase() + sourceKey.slice(1),
                data: [],
                color,
              };
            }

            // If it's an array of objects, extract the source key from each item
            const data = resourcesByDate.map((item: any) => {
              // Try different possible key formats
              return item[sourceKey] 
                || item[`${sourceKey}Count`]
                || item[sourceKey.replace('-', '_')]
                || item[sourceKey.replace('-', '')]
                || 0;
            });

            return {
              name: sourceKey === 'dark-web' ? 'Dark Web' : sourceKey === 'website' ? 'Web' : sourceKey.charAt(0).toUpperCase() + sourceKey.slice(1),
              data,
              color,
            };
          };

          // Build monitored sources from resourcesUnderControl
          const monitoredSourcesMap: { [key: string]: { label: string; color: string } } = {
            'website': { label: 'Web', color: '#1565c0' },
            'forum': { label: 'Forums', color: '#64b5f6' },
            'telegram': { label: 'Telegram', color: '#42a5f5' },
            'dark-web': { label: 'Dark Web', color: '#0d47a1' },
            'social-media': { label: 'Social Media', color: '#42a5f5' },
            'deep-web': { label: 'Deep Web', color: '#90caf9' },
            'chat-apps': { label: 'Chat Apps', color: '#42a5f5' },
            'email': { label: 'Email', color: '#0d47a1' },
            'gaming-platforms': { label: 'Gaming Platforms', color: '#42a5f5' },
            'file-sharing': { label: 'File Sharing', color: '#90caf9' },
          };

          const monitoredSources = Object.entries(resourcesUnderControl)
            .filter(([key]) => monitoredSourcesMap[key])
            .map(([key, value]) => ({
              label: monitoredSourcesMap[key].label,
              value: typeof value === 'number' ? value : 0,
              color: monitoredSourcesMap[key].color,
            }))
            .filter(item => item.value > 0);

          // Calculate changes based on historical data from allResourcesByDate
          // Compare current period with previous period
          const calculateChange = (currentValue: number, sourceKey?: string) => {
            if (!Array.isArray(resourcesByDate) || resourcesByDate.length < 2) {
              // If we don't have enough historical data, return 0
              return 0;
            }

            try {
              // Get the last two data points
              const recent = resourcesByDate[resourcesByDate.length - 1];
              const previous = resourcesByDate[resourcesByDate.length - 2];
              
              let recentValue = 0;
              let previousValue = 0;

              if (sourceKey) {
                // For specific source, get the value from the data point
                recentValue = recent[sourceKey] || recent[`${sourceKey}Count`] || 0;
                previousValue = previous[sourceKey] || previous[`${sourceKey}Count`] || 0;
              } else {
                // For total, sum all sources
                const sources = ['dark-web', 'telegram', 'website', 'forum'];
                recentValue = sources.reduce((sum, key) => sum + (recent[key] || recent[`${key}Count`] || 0), 0);
                previousValue = sources.reduce((sum, key) => sum + (previous[key] || previous[`${key}Count`] || 0), 0);
              }

              if (previousValue === 0) {
                return recentValue > 0 ? 100 : 0;
              }

              const change = ((recentValue - previousValue) / previousValue) * 100;
              return Math.round(change);
            } catch {
              return 0;
            }
          };

          // Debug: Log the values we're using
          console.log('Stats values from API:', {
            allResourcesCount: dashboardData.allResourcesCount,
            allDarkWebResourcesCount: dashboardData.allDarkWebResourcesCount,
            allWebResourcesCount: dashboardData.allWebResourcesCount,
            allTelegramResourcesCount: dashboardData.allTelegramResourcesCount,
          });

          const transformedData: RessaDWMData = {
            stats: {
              allNewLeaks: {
                value: dashboardData.allResourcesCount || 0,
                change: calculateChange(dashboardData.allResourcesCount || 0),
              },
              darkWeb: {
                value: dashboardData.allDarkWebResourcesCount || 0,
                change: calculateChange(dashboardData.allDarkWebResourcesCount || 0, 'dark-web'),
              },
              web: {
                value: dashboardData.allWebResourcesCount || 0,
                change: calculateChange(dashboardData.allWebResourcesCount || 0, 'website'),
              },
              telegram: {
                value: dashboardData.allTelegramResourcesCount || 0,
                change: calculateChange(dashboardData.allTelegramResourcesCount || 0, 'telegram'),
              },
            },
            monitoredSources: monitoredSources.length > 0 
              ? monitoredSources 
              : [
                  { label: 'Web', value: dashboardData.allWebResourcesCount || 0, color: '#1565c0' },
                  { label: 'Dark Web', value: dashboardData.allDarkWebResourcesCount || 0, color: '#0d47a1' },
                  { label: 'Telegram', value: dashboardData.allTelegramResourcesCount || 0, color: '#42a5f5' },
                ],
            topLeaks: topLeaksData.length > 0 ? topLeaksData : [
              // Fallback data if API doesn't return Top Leaks
              { name: 'IRLeaks', value: 150 },
              { name: 'bakhtak', value: 120 },
              { name: 'We Red Evils Original', value: 100 },
              { name: 'OnHex', value: 60 },
              { name: 'CVE Notify', value: 35 },
            ],
            topDamageable: topDamageableData.length > 0 ? topDamageableData : [
              // Fallback data if API doesn't return Top Damageable
              { name: 'Tapsi.ir', value: 109 },
              { name: 'Snapp.ir', value: 85 },
              { name: 'Varzesh3.com', value: 78 },
              { name: 'Irancell.com', value: 66 },
              { name: 'mci.ir', value: 47 },
            ],
            vulnerabilityTrends: (() => {
              const trends = [
                extractTrendData('dark-web', '#64b5f6'),
                extractTrendData('telegram', '#42a5f5'),
                extractTrendData('website', '#1565c0'),
              ];
              console.log('Vulnerability Trends extracted:', trends);
              return trends.filter(item => item.data.length > 0);
            })(),
            dataLeakTrends: [
              extractTrendData('dark-web', '#64b5f6'),
              extractTrendData('telegram', '#42a5f5'),
              extractTrendData('website', '#1565c0'),
            ].filter(item => item.data.length > 0),
          };
          
          setData(transformedData);
        }
      } catch (err) {
        const errorMessage = err instanceof Error ? err.message : 'Failed to fetch data';
        setError(errorMessage);
        console.error('Error fetching Ressa DWM data:', err);
        console.error('Endpoint used:', endpoint);
        // Don't throw - let the component render with default data
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  return { data, loading, error };
};

