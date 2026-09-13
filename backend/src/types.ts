export interface DockerIPAMConfig {
  Subnet?: string;
  Gateway?: string;
  IPRange?: string;
}

export interface DockerNetworkContainer {
  Name: string;
  EndpointID: string;
  MacAddress: string;
  IPv4Address: string;
  IPv6Address: string;
}

export interface DockerNetwork {
  Name: string;
  Id: string;
  Scope: string;
  Driver: string;
  EnableIPv4?: boolean;
  EnableIPv6?: boolean;
  Internal: boolean;
  Attachable: boolean;
  Ingress: boolean;
  IPAM: {
    Driver: string;
    Config?: DockerIPAMConfig[];
  };
  Containers?: Record<string, DockerNetworkContainer>;
  Labels?: Record<string, string>;
  Options?: Record<string, string>;
}

export interface DockerContainerSummary {
  Id: string;
  Labels?: Record<string, string>;
  Names: string[];
  Image: string;
  State: string;
  Status: string;
  NetworkSettings?: {
    Networks?: Record<string, {
      NetworkID?: string;
      EndpointID?: string;
      Gateway?: string;
      IPAddress?: string;
      IPPrefixLen?: number;
      GlobalIPv6Address?: string;
      MacAddress?: string;
    }>;
  };
}


export interface DockerContainerInspect {
  Id: string;
  Config?: {
    ExposedPorts?: Record<string, Record<string, never>>;
    Labels?: Record<string, string>;
  };
  NetworkSettings?: {
    Ports?: Record<
      string,
      Array<{
        HostIp: string;
        HostPort: string;
      }> | null
    >;
  };
}


export type FirewallAction = "ACCEPT" | "DROP" | "REJECT";
export type FirewallProtocol = "all" | "tcp" | "udp" | "icmp" | "icmpv6";
export type FirewallFamily = 4 | 6 | "both";

export interface FirewallRule {
  id: string;
  family?: FirewallFamily;
  sourceNetworkId: string;
  destinationNetworkId: string;
  sourceNetworkName?: string | null;
  destinationNetworkName?: string | null;
  protocol: FirewallProtocol;
  destinationPort?: number | null;
  action: FirewallAction;
  enabled: boolean;
  description?: string;
}


export type AccessSelectorType = "custom" | "docker-network" | "container" | "wireguard";

export interface AccessSelector {
  type: AccessSelectorType;
  refId?: string | null;
  refName?: string | null;
  value?: string | null;
  label?: string | null;
  composeProject?: string | null;
  composeService?: string | null;
  composeContainerNumber?: string | null;
}

export interface ContainerAccessRule {
  id: string;
  family: FirewallFamily;
  source: AccessSelector;
  sourceNegate?: boolean;
  destination: AccessSelector;
  protocol: FirewallProtocol;
  destinationPort?: number | null;
  action: FirewallAction;
  enabled: boolean;
  description?: string;
  managedByNatRuleId?: string | null;
}

export interface FirewallConfig {
  enabled: boolean;
  rules: FirewallRule[];
  publishedPortRules: PublishedPortFirewallRule[];
  hostInputRules: HostInputFirewallRule[];
  accessRules: ContainerAccessRule[];
  updatedAt: string;
}

export interface FirewallNetworkRef {
  id: string;
  name: string;
  subnets: string[];
}


export interface PublishedPortFirewallRule {
  id: string;
  family?: 4 | 6;
  containerId: string;
  containerName: string;
  protocol: "tcp" | "udp";
  publishedPort: number;
  hostIp: string;
  containerPort: number;
  interfaceName?: string;
  sourceCidr: string;
  sourceNegate?: boolean;
  destinationCidr?: string;
  action: FirewallAction;
  enabled: boolean;
  description?: string;
}

export interface PublishedPortRef {
  containerId: string;
  containerName: string;
  protocol: "tcp" | "udp";
  publishedPort: number;
  hostIp: string;
  containerPort: number;
}


export interface HostInputFirewallRule {
  id: string;
  family?: FirewallFamily;
  interfaceName: string;
  localAddress?: string | null;
  protocol: FirewallProtocol;
  destinationPort?: number | null;
  sourceCidr: string;
  sourceNegate?: boolean;
  action: FirewallAction;
  enabled: boolean;
  description?: string;
}

export interface HostPortRef {
  protocol: "tcp" | "udp";
  listenAddress: string;
  port: number;
}
