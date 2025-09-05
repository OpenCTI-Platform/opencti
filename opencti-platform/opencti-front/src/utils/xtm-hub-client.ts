import { RootSettings$data } from '../private/__generated__/RootSettings.graphql';

interface FetchDocumentParams {
  settings: RootSettings$data
  serviceInstanceId: string
  fileId: string
  userPlatformToken: string
}

const XtmHubClient = {
  fetchDocument: async ({ settings, serviceInstanceId, fileId, userPlatformToken }: FetchDocumentParams): Promise<File> => {
    const response = await fetch(
      `${settings.platform_xtmhub_url}/document/get/${serviceInstanceId}/${fileId}`,
      {
        method: 'GET',
        credentials: 'omit',
        headers: {
          'XTM-Hub-User-Platform-Token': userPlatformToken,
          'XTM-Hub-Platform-Id': settings.id,
          'XTM-Hub-Platform-Token': settings.xtm_hub_token ?? '',
        },
      },
    );

    const blob = await response.blob();
    return new File([blob], 'downloaded.json', {
      type: 'application/json',
    });
  },
};

export default XtmHubClient;
