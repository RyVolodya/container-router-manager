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
  labels?: Record<string,string>;
  options?: Record<string,string>;
  parent?: string | null;
  vlanId?: number | null;
  managedVlanInterface?: string | null;
};

export type DockerContainer = {
  id: string;
  name: string;
  image: string;
  labels?: Record<string,string>;
  compose?: {project:string;service:string;containerNumber:string|null}|null;
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
  sourceNetworkName?: string | null;
  destinationNetworkName?: string | null;
  family?:4|6|"both";
  protocol: "all" | "tcp" | "udp" | "icmp" | "icmpv6";
  destinationPort?: number | null;
  action: "ACCEPT" | "DROP" | "REJECT";
  enabled: boolean;
  description?: string;
};

export type HostInputRule={
  id:string;family?:4|6|"both";interfaceName:string;localAddress?:string|null;protocol:"all"|"tcp"|"udp"|"icmp"|"icmpv6";
  destinationPort?:number|null;sourceCidr:string;sourceNegate?:boolean;action:"ACCEPT"|"DROP"|"REJECT";enabled:boolean;description?:string;
};

export type AccessSelectorType="custom"|"docker-network"|"container"|"wireguard";
export type AccessSelector={
  type:AccessSelectorType;
  refId?:string|null;
  refName?:string|null;
  value?:string|null;
  label?:string|null;
  composeProject?:string|null;
  composeService?:string|null;
  composeContainerNumber?:string|null;
};
export type ContainerAccessRule={
  id:string;
  family:4|6|"both";
  source:AccessSelector;
  sourceNegate?:boolean;
  destination:AccessSelector;
  protocol:"all"|"tcp"|"udp"|"icmp"|"icmpv6";
  destinationPort?:number|null;
  action:"ACCEPT"|"DROP"|"REJECT";
  enabled:boolean;
  description?:string;
  managedByNatRuleId?:string|null;
};

export type HostFirewallRule={
  id:string;family:4|6;chain:string;position:number;packets:number;bytes:number;protocol:string;
  source:string;destination:string;inInterface:string|null;outInterface:string|null;
  sourcePort:string|null;destinationPort:string|null;target:string;state:string|null;comment:string|null;
  owner:"DRM"|"Docker"|"System-External";raw:string;
};

export type FirewallStatus = {
  engine:string;managedChain:string;
  config:{enabled:boolean;rules:FirewallRule[];publishedPortRules:Array<{id:string;family?:4|6;containerId:string;containerName:string;protocol:"tcp"|"udp";publishedPort:number;hostIp:string;containerPort:number;interfaceName?:string;sourceCidr:string;sourceNegate?:boolean;destinationCidr?:string;action:"ACCEPT"|"DROP"|"REJECT";enabled:boolean;description?:string}>;hostInputRules:HostInputRule[];accessRules:ContainerAccessRule[];updatedAt:string};
  applied:{enabled:boolean;rules:FirewallRule[];publishedPortRules:Array<{id:string;family?:4|6;containerId:string;containerName:string;protocol:"tcp"|"udp";publishedPort:number;hostIp:string;containerPort:number;interfaceName?:string;sourceCidr:string;sourceNegate?:boolean;destinationCidr?:string;action:"ACCEPT"|"DROP"|"REJECT";enabled:boolean;description?:string}>;hostInputRules:HostInputRule[];accessRules:ContainerAccessRule[];updatedAt:string};
  pendingChanges:boolean;lastAppliedAt:string|null;
  networkRefs:Array<{id:string;name:string;refName?:string;subnets:string[]}>;
  containerRefs:Array<{
    id:string;
    name:string;
    refName?:string;
    composeProject?:string|null;
    composeService?:string|null;
    composeContainerNumber?:string|null;
    addresses:Array<{family:4|6;address:string;networkName:string}>
  }>;
  wireguardRefs:Array<{id:string;interfaceName:string;name:string;cidr:string;family:4|6;kind:"tunnel"|"peer"|"remote"}>;
  accessCounters:Record<string,{packets:number;bytes:number}>;
  accessRuleResolution:Record<string,{
    source:string[];
    destination:string[];
    resolved:boolean;
    message:string;
  }>;
  dynamicFirewall?:{lastRefreshAt:string|null;lastError:string|null;intervalMs:number};
  ruleCounters:Record<string,{packets:number;bytes:number}>;
  allFirewallRules:HostFirewallRule[];
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


export type ManagedRoute={id:string;family:4|6;destination:string;gateway?:string|null;dev?:string|null;metric?:number|null;table?:number|null;enabled:boolean};
export type RoutingStatus={ipForward:boolean;ipForward6:boolean;routes:any[];routes4:any[];routes6:any[];addresses:any[];links:any[];managedRoutes:ManagedRoute[]};
export type ManagedVrf={id:string;name:string;table:number;interfaces:string[];enabled:boolean;description:string;createdAt:string;updatedAt:string};
export type VrfStatus={tableRange:{min:number;max:number};config:{vrfs:ManagedVrf[];updatedAt:string};runtime:Array<{name:string;table:number;state:string;interfaces:string[]}>};
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

export type NatSourceSelector={
  type:"custom"|"docker-network"|"container"|"wireguard";
  refId?:string|null;refName?:string|null;value?:string|null;label?:string|null;
  composeProject?:string|null;composeService?:string|null;composeContainerNumber?:string|null;
};
export type NatContainerDestination={kind:"container";refId:string;refName?:string|null;label?:string|null;composeProject?:string|null;composeService?:string|null;composeContainerNumber?:string|null;networkName?:string|null};
export type NatIpDestination={kind:"ip";ip:string};
export type NatOutboundRule={id:string;type:"masquerade"|"snat";enabled:boolean;description:string;createdAt:string;updatedAt:string;source:NatSourceSelector;outInterface:string;toSourceIp:string|null;policyRoute:boolean;routeTable:number};
export type NatDnatRule={id:string;type:"dnat";enabled:boolean;description:string;createdAt:string;updatedAt:string;inInterface:string;externalIp:string;protocol:"tcp"|"udp";externalPort:number;sourceCidr:string;destination:NatContainerDestination|NatIpDestination;internalPort:number;createFirewallRule:boolean};
export type NatRule=NatOutboundRule|NatDnatRule;
export type HostNatRule={
  id:string;chain:string;position:number;packets:number;bytes:number;protocol:string;
  source:string;destination:string;inInterface:string|null;outInterface:string|null;
  target:string;sourcePort:string|null;destinationPort:string|null;
  toDestination:string|null;toSource:string|null;owner:"DRM"|"Docker"|"System-External";raw:string;
};
export type NatStatus={
  config:{rules:NatRule[];updatedAt:string};
  runtime:Record<string,{resolved:boolean;message:string;source:string[];destination:string[]}>;
  hostInterfaces:Array<{name:string;state:string;addresses:string[];ips:string[]}>;
  defaultWanInterface:string|null;
  defaultRoutes:any[];
  networkRefs:Array<{id:string;name:string;subnets:string[]}>;
  containerRefs:Array<{id:string;name:string;composeProject?:string|null;composeService?:string|null;composeContainerNumber?:string|null;networks:Array<{networkName:string;ipv4Address:string|null}>}>;
  dynamic:{lastRefreshAt:string|null;lastError:string|null;intervalMs:number};
  engine:{preChain:string;postChain:string;preChainPresent:boolean;postChainPresent:boolean};
  allNatRules:HostNatRule[];
};

export type ManagedHostInterfaceConfig={name:string;mode:"dhcp"|"static";address:string|null;gateway:string|null;metric:number|null;addDefaultRoute:boolean;vlan:{parent:string;vlanId:number}|null;enabled:boolean;createdAt:string;updatedAt:string};
export type HostInterfaceRuntime={name:string;index:number;kind:string;state:string;up:boolean;mac:string|null;mtu:number|null;ipv4:string[];defaultRoutes:any[];vlanId:number|null;parent:string|null;managedVlan:boolean;managedConfig:ManagedHostInterfaceConfig|null};
export type PendingHostInterfaceChange={token:string;interfaceName:string;previousManaged:ManagedHostInterfaceConfig|null;desired:ManagedHostInterfaceConfig;expiresAt:string;createdAt:string};
export type HostInterfaceManagementStatus={interfaces:HostInterfaceRuntime[];managed:ManagedHostInterfaceConfig[];pending:PendingHostInterfaceChange|null;rollbackMs:number;generatedAt:string};
