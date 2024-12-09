import { describe, it } from 'vitest';
import axios, { type AxiosRequestConfig } from 'axios';
import { getHttpClient, type GetHttpClient } from '../src/utils/http-client';

axios.interceptors.request.use((request) => {
  console.log('******🐠🐠 Starting Request', JSON.stringify(request, null, 2));
  return request;
});

describe('HTTP Get', () => {
  type Getter = (uri: string) => Promise<object>;

  const userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
  const ingestionURL = 'https://www.redpacketsecurity.com/feed/';

  /*
  https://dailydarkweb.net/feed/
  https://cybersecurity.att.com/site/blog-all-rss

  https://www.securityweek.com/feed/
  */

  const rssHttpGetter = (): Getter => {
    const httpClientOptions: GetHttpClient = {
      responseType: 'text',
      headers: {
        accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'accept-encoding': 'identity',
        'accept-language': 'fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7',
        'cache-control': 'max-age=0',
        'if-modified-since': 'Wed, 04 Dec 2024 18:49:00 GMT',
        'if-none-match': 'W/"54c78a500afa9073204546d19a8ab4c5"',
        priority: 'u=0, i',
        'sec-ch-ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'none',
        'sec-fetch-user': '?1',
        'upgrade-insecure-requests': '1',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
        Pragma: 'no-cache'
      }
    };

    const httpClientOptionsShort: GetHttpClient = {
      responseType: 'text',
      headers: {
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
      }
    };

    const httpClient = getHttpClient(httpClientOptionsShort);
    return async (uri: string) => {
      const { data } = await httpClient.get(uri);
      return data;
    };
  };

  const rssHttpGetterV2 = (): Getter => {
    return async (uri: string) => {
      const options: AxiosRequestConfig = {
        method: 'GET',
        url: uri,
        headers: {
          accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
          'accept-encoding': 'identity',
          'accept-language': 'fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7',
          'cache-control': 'max-age=0',
          'if-modified-since': 'Wed, 04 Dec 2024 18:49:00 GMT',
          'if-none-match': 'W/"54c78a500afa9073204546d19a8ab4c5"',
          priority: 'u=0, i',
          'sec-ch-ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
          'sec-ch-ua-mobile': '?0',
          'sec-ch-ua-platform': '"Windows"',
          'sec-fetch-dest': 'document',
          'sec-fetch-mode': 'navigate',
          'sec-fetch-site': 'none',
          'sec-fetch-user': '?1',
          'upgrade-insecure-requests': '1',
          'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
          Pragma: 'no-cache'
        }
      };
      const { data } = await axios.request(options);
      return data;
    };
  };

  it('HTTP Get current implementation', async () => {
    try {
      const httpGet = rssHttpGetter();
      const data = await httpGet(ingestionURL);
      console.log('CURRENT data', data);
    } catch (e) {
      console.log('CURRENT error', e);
    }
  });

  it('HTTP Get custom implementation', async () => {
    try {
      const httpGet = rssHttpGetterV2();
      const data = await httpGet(ingestionURL);
      console.log('NEW data', data);
    } catch (e) {
      console.log('NEW error', e);
    }
  });

  it('HTTP Get fetch implementation', async () => {
    try {
      await fetch(ingestionURL)
        .then((response) => response.text())
        .then((data) => console.log(data));
    } catch (e) {
      console.log('NEW error', e);
    }
  });
});
