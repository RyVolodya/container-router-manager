export type NetworkEndpoint = {
  id: string;
  name: string;
  endpointId: string;
  macAddress: string;
  ipv4Address: string;
  ipv6Address: string;
};

export type DockerNetwork = {
  id: string;
  name: string;
  driver: string;
  scope: string;
  internal: boolean;
  attachable: boolean;
  ingress: boolean;
  ipv4Enabled: boolean;
  ipv6Enabled: boolean;
  subnets: Array<{ subnet: string | null; gateway: string | null; ipRange: string | null }>;
  containers: NetworkEndpoint[];
};

export type DockerContainer = {
  id: string;
  name: string;
  image: string;
  state: string;
  status: string;
  ports: Array<{
    containerPort: string;
    protocol: string;
    port: number;
    published: Array<{
      hostIp: string;
      hostPort: number;
    }>;
  }>;
  networks: Array<{
    networkName: string;
    networkId: string | null;
    ipv4Address: string | null;
    ipv4PrefixLen: number | null;
    gateway: string | null;
    ipv6Address: string | null;
    macAddress: string | null;
  }>;
};

export type Topology = {
  generatedAt: string;
  networkCount: number;
  containerCount: number;
  runningContainerCount: number;
  networks: DockerNetwork[];
  containers: DockerContainer[];
};


export type FirewallRule = {
  id: string;
  sourceNetworkId: string;
  destinationNetworkId: string;
  family?:4|6|"both";
  protocol: "all" | "tcp" | "udp" | "icmp" | "icmpv6";
  destinationPort?: number | null;
  action: "ACCEPT" | "DROP" | "REJECT";
  enabled: boolean;
  description?: string;
};

export type HostInputRule={
  id:string;family?:4|6|"both";interfaceName:string;localAddress?:string|null;protocol:"all"|"tcp"|"udp"|"icmp"|"icmpv6";
  destinationPort?:number|null;sourceCidr:string;action:"ACCEPT"|"DROP"|"REJECT";enabled:boolean;description?:string;
};

export type AccessSelectorType="custom"|"docker-network"|"container"|"wireguard";
export type AccessSelector={type:AccessSelectorType;refId?:string|null;value?:string|null;label?:string|null};
export type ContainerAccessRule={
  id:string;
  family:4|6|"both";
  source:AccessSelector;
  destination:AccessSelector;
  protocol:"all"|"tcp"|"udp"|"icmp"|"icmpv6";
  destinationPort?:number|null;
  action:"ACCEPT"|"DROP"|"REJECT";
  enabled:boolean;
  description?:string;
};

export type FirewallStatus = {
  engine:string;managedChain:string;
  config:{enabled:boolean;rules:FirewallRule[];publishedPortRules:Array<{id:string;family?:4|6;containerId:string;containerName:string;protocol:"tcp"|"udp";publishedPort:number;hostIp:string;containerPort:number;sourceCidr:string;destinationCidr?:string;action:"ACCEPT"|"DROP"|"REJECT";enabled:boolean;description?:string}>;hostInputRules:HostInputRule[];accessRules:ContainerAccessRule[];updatedAt:string};
  applied:{enabled:boolean;rules:FirewallRule[];publishedPortRules:Array<{id:string;family?:4|6;containerId:string;containerName:string;protocol:"tcp"|"udp";publishedPort:number;hostIp:string;containerPort:number;sourceCidr:string;destinationCidr?:string;action:"ACCEPT"|"DROP"|"REJECT";enabled:boolean;description?:string}>;hostInputRules:HostInputRule[];accessRules:ContainerAccessRule[];updatedAt:string};
  pendingChanges:boolean;lastAppliedAt:string|null;
  networkRefs:Array<{id:string;name:string;subnets:string[]}>;
  containerRefs:Array<{id:string;name:string;addresses:Array<{family:4|6;address:string;networkName:string}>}>;
  wireguardRefs:Array<{id:string;interfaceName:string;name:string;cidr:string;family:4|6;kind:"tunnel"|"peer"|"remote"}>;
  accessCounters:Record<string,{packets:number;bytes:number}>;
  ruleCounters:Record<string,{packets:number;bytes:number}>;
  publishedPortRefs:Array<{containerId:string;containerName:string;protocol:"tcp"|"udp";publishedPort:number;hostIp:string;containerPort:number}>;
  hostInterfaces:Array<{name:string;addresses:string[]}>;
  defaultWanInterface:string|null;
  hostPortRefs:Array<{protocol:"tcp"|"udp";listenAddress:string;port:number}>;
  runtime:{chainPresent:boolean;jumpPresent:boolean;installedRules:string[];inputChainPresent:boolean;inputJumpPresent:boolean;installedInputRules:string[];error:string|null};
};


export type NetworkStatsResponse = {
  generatedAt: string;
  containers: Array<{ id:string; name:string; readAt:string; rxBytes:number; txBytes:number; rxPackets:number; txPackets:number; networks:Array<{name:string;rxBytes:number;txBytes:number;rxPackets:number;txPackets:number}> }>;
};


export type ManagedRoute={id:string;family:4|6;destination:string;gateway?:string|null;dev?:string|null;metric?:number|null;enabled:boolean};
export type RoutingStatus={ipForward:boolean;ipForward6:boolean;routes:any[];routes4:any[];routes6:any[];addresses:any[];links:any[];managedRoutes:ManagedRoute[]};
export type WireGuardPeerRuntime={
  endpoint:string|null;
  remoteIp:string|null;
  remotePort:number|null;
  latestHandshake:number;
  latestHandshakeAt:string|null;
  handshakeAgeSeconds:number|null;
  rxBytes:number;
  txBytes:number;
  status:"active"|"idle"|"never";
};

export type WireGuardAccessPolicy={
  enabled:boolean;
  dockerCidrs:string[];
  lanCidrs:string[];
  internet:boolean;
  nat:boolean;
  wanInterface?:string;
  internet6?:boolean;
  nat66?:boolean;
  wanInterface6?:string;
};
export type WireGuardStatus={defaultWanInterface:string|null;defaultWanInterface6:string|null;hostInterfaces:string[];interfaces:Array<{
  name:string;
  address:string;
  ipv6Address:string|null;
  addresses:string[];
  listenPort:number;
  mtu:number;
  publicKey:string;
  accessPolicy:WireGuardAccessPolicy;
  peers:Array<{
    id:string;
    name:string;
    mode:"remote-access"|"site-to-site";
    enabled:boolean;
    publicKey:string;
    serverAllowedIps:string[];
    clientAllowedIps:string[];
    clientAddress?:string;
    clientIpv6Address?:string;
    remoteNetworks:string[];
    endpoint?:string;
    endpointHost?:string;
    endpointPort?:number;
    dns?:string;
    persistentKeepalive:number;
    runtime:WireGuardPeerRuntime;
  }>
}>};
