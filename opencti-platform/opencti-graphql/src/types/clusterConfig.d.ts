export type ClusterConfig = {
  platform_id: string;
  // Not set by the nodes of a previous version
  api_enabled?: boolean;
  managers: {
    id: string;
    enable: boolean;
    running: boolean;
  }[];
};
