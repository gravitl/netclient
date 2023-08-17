import { PeerConfig } from "../../src/models/Peer";

export namespace config {
	
	export class Config {
	    id: number[];
	    verbosity: number;
	    firewallinuse: string;
	    version: string;
	    ipforwarding: boolean;
	    daemoninstalled: boolean;
	    autoupdate: boolean;
	    hostpass: string;
	    name: string;
	    os: string;
	    interface: string;
	    debug: boolean;
	    listenport: number;
	    public_listen_port: number;
	    proxy_listen_port: number;
	    mtu: number;
	    publickey: number[];
	    macaddress: number[];
	    traffickeypublic: number[];
	    nodes: string[];
	    isrelayed: boolean;
	    relayed_by: string;
	    isrelay: boolean;
	    relay_hosts: string[];
	    interfaces: models.Iface[];
	    defaultinterface: string;
	    endpointip: number[];
	    proxy_enabled: boolean;
	    proxy_enabled_updated: boolean;
	    isdocker: boolean;
	    isk8s: boolean;
	    isstatic: boolean;
	    isdefault: boolean;
	    nat_type?: string;
	    // Go type: netip
	    turn_endpoint?: any;
	    privatekey: number[];
	    traffickeyprivate: number[];
	    peers: {[key: string]: PeerConfig[]};
	
	    static createFrom(source: any = {}) {
	        return new Config(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.verbosity = source["verbosity"];
	        this.firewallinuse = source["firewallinuse"];
	        this.version = source["version"];
	        this.ipforwarding = source["ipforwarding"];
	        this.daemoninstalled = source["daemoninstalled"];
	        this.autoupdate = source["autoupdate"];
	        this.hostpass = source["hostpass"];
	        this.name = source["name"];
	        this.os = source["os"];
	        this.interface = source["interface"];
	        this.debug = source["debug"];
	        this.listenport = source["listenport"];
	        this.public_listen_port = source["public_listen_port"];
	        this.proxy_listen_port = source["proxy_listen_port"];
	        this.mtu = source["mtu"];
	        this.publickey = source["publickey"];
	        this.macaddress = source["macaddress"];
	        this.traffickeypublic = source["traffickeypublic"];
	        this.nodes = source["nodes"];
	        this.isrelayed = source["isrelayed"];
	        this.relayed_by = source["relayed_by"];
	        this.isrelay = source["isrelay"];
	        this.relay_hosts = source["relay_hosts"];
	        this.interfaces = this.convertValues(source["interfaces"], models.Iface);
	        this.defaultinterface = source["defaultinterface"];
	        this.endpointip = source["endpointip"];
	        this.proxy_enabled = source["proxy_enabled"];
	        this.proxy_enabled_updated = source["proxy_enabled_updated"];
	        this.isdocker = source["isdocker"];
	        this.isk8s = source["isk8s"];
	        this.isstatic = source["isstatic"];
	        this.isdefault = source["isdefault"];
	        this.nat_type = source["nat_type"];
	        this.turn_endpoint = this.convertValues(source["turn_endpoint"], null);
	        this.privatekey = source["privatekey"];
	        this.traffickeyprivate = source["traffickeyprivate"];
	        this.peers = source["peers"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Node {
	    id: number[];
	    hostid: number[];
	    network: string;
	    // Go type: net
	    networkrange: any;
	    // Go type: net
	    networkrange6: any;
	    server: string;
	    connected: boolean;
	    // Go type: net
	    address: any;
	    // Go type: net
	    address6: any;
	    action: string;
	    // Go type: net
	    localaddress: any;
	    isegressgateway: boolean;
	    egressgatewayranges: string[];
	    isingressgateway: boolean;
	    dnson: boolean;
	    persistentkeepalive: number;
	
	    static createFrom(source: any = {}) {
	        return new Node(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.hostid = source["hostid"];
	        this.network = source["network"];
	        this.networkrange = this.convertValues(source["networkrange"], null);
	        this.networkrange6 = this.convertValues(source["networkrange6"], null);
	        this.server = source["server"];
	        this.connected = source["connected"];
	        this.address = this.convertValues(source["address"], null);
	        this.address6 = this.convertValues(source["address6"], null);
	        this.action = source["action"];
	        this.localaddress = this.convertValues(source["localaddress"], null);
	        this.isegressgateway = source["isegressgateway"];
	        this.egressgatewayranges = source["egressgatewayranges"];
	        this.isingressgateway = source["isingressgateway"];
	        this.dnson = source["dnson"];
	        this.persistentkeepalive = source["persistentkeepalive"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Server {
	    name: string;
	    mqid: number[];
	    nodes: {[key: string]: boolean};
	    accesskey: string;
	
	    static createFrom(source: any = {}) {
	        return new Server(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.mqid = source["mqid"];
	        this.nodes = source["nodes"];
	        this.accesskey = source["accesskey"];
	    }
	}

}

export namespace main {
	
	export class NcConfig {
	    id: number[];
	    verbosity: number;
	    firewallinuse: string;
	    version: string;
	    ipforwarding: boolean;
	    daemoninstalled: boolean;
	    autoupdate: boolean;
	    hostpass: string;
	    name: string;
	    os: string;
	    interface: string;
	    debug: boolean;
	    listenport: number;
	    public_listen_port: number;
	    proxy_listen_port: number;
	    mtu: number;
	    publickey: number[];
	    macaddress: number[];
	    traffickeypublic: number[];
	    nodes: string[];
	    isrelayed: boolean;
	    relayed_by: string;
	    isrelay: boolean;
	    relay_hosts: string[];
	    interfaces: models.Iface[];
	    defaultinterface: string;
	    endpointip: number[];
	    proxy_enabled: boolean;
	    proxy_enabled_updated: boolean;
	    isdocker: boolean;
	    isk8s: boolean;
	    isstatic: boolean;
	    isdefault: boolean;
	    nat_type?: string;
	    // Go type: netip
	    turn_endpoint?: any;
	    privatekey: number[];
	    traffickeyprivate: number[];
	    peers: {[key: string]: PeerConfig[]};
	    macaddressstr: string;
	
	    static createFrom(source: any = {}) {
	        return new NcConfig(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.verbosity = source["verbosity"];
	        this.firewallinuse = source["firewallinuse"];
	        this.version = source["version"];
	        this.ipforwarding = source["ipforwarding"];
	        this.daemoninstalled = source["daemoninstalled"];
	        this.autoupdate = source["autoupdate"];
	        this.hostpass = source["hostpass"];
	        this.name = source["name"];
	        this.os = source["os"];
	        this.interface = source["interface"];
	        this.debug = source["debug"];
	        this.listenport = source["listenport"];
	        this.public_listen_port = source["public_listen_port"];
	        this.proxy_listen_port = source["proxy_listen_port"];
	        this.mtu = source["mtu"];
	        this.publickey = source["publickey"];
	        this.macaddress = source["macaddress"];
	        this.traffickeypublic = source["traffickeypublic"];
	        this.nodes = source["nodes"];
	        this.isrelayed = source["isrelayed"];
	        this.relayed_by = source["relayed_by"];
	        this.isrelay = source["isrelay"];
	        this.relay_hosts = source["relay_hosts"];
	        this.interfaces = this.convertValues(source["interfaces"], models.Iface);
	        this.defaultinterface = source["defaultinterface"];
	        this.endpointip = source["endpointip"];
	        this.proxy_enabled = source["proxy_enabled"];
	        this.proxy_enabled_updated = source["proxy_enabled_updated"];
	        this.isdocker = source["isdocker"];
	        this.isk8s = source["isk8s"];
	        this.isstatic = source["isstatic"];
	        this.isdefault = source["isdefault"];
	        this.nat_type = source["nat_type"];
	        this.turn_endpoint = this.convertValues(source["turn_endpoint"], null);
	        this.privatekey = source["privatekey"];
	        this.traffickeyprivate = source["traffickeyprivate"];
	        this.peers = source["peers"];
	        this.macaddressstr = source["macaddressstr"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Network {
	    node?: config.Node;
	    server?: config.Server;
	
	    static createFrom(source: any = {}) {
	        return new Network(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.node = this.convertValues(source["node"], config.Node);
	        this.server = this.convertValues(source["server"], config.Server);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class SsoJoinResDto {
	    authendpoint: string;
	
	    static createFrom(source: any = {}) {
	        return new SsoJoinResDto(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.authendpoint = source["authendpoint"];
	    }
	}

}

export namespace models {

	export class Iface {
		name: string;
		// Go type: net.IPNet
	    address: any;
	    addressString: string;
	
	    static createFrom(source: any = {}) {
	        return new Iface(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.address = source["address"];
	        this.addressString = source["addressString"];
	    }
	}

}