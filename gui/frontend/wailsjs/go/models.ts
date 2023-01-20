export namespace config {
	
	export class Config {
	    verbosity: number;
	    firewallinuse: string;
	    version: string;
	    ipforwarding: boolean;
	    daemoninstalled: boolean;
	    hostid: string;
	    hostpass: string;
	    name: string;
	    os: string;
	    debug: boolean;
	    nodepassword: string;
	    listenport: number;
	    // Go type: net.IPNet
	    localaddress: any;
	    // Go type: net.IPNet
	    localrange: any;
	    locallistenport: number;
	    mtu: number;
	    privatekey: number[];
	    publickey: number[];
	    macaddress: number[];
	    traffickeyprivate: number[];
	    traffickeypublic: number[];
	    // Go type: net.UDPAddr
	    internetgateway: any;
	
	    static createFrom(source: any = {}) {
	        return new Config(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.verbosity = source["verbosity"];
	        this.firewallinuse = source["firewallinuse"];
	        this.version = source["version"];
	        this.ipforwarding = source["ipforwarding"];
	        this.daemoninstalled = source["daemoninstalled"];
	        this.hostid = source["hostid"];
	        this.hostpass = source["hostpass"];
	        this.name = source["name"];
	        this.os = source["os"];
	        this.debug = source["debug"];
	        this.nodepassword = source["nodepassword"];
	        this.listenport = source["listenport"];
	        this.localaddress = this.convertValues(source["localaddress"], null);
	        this.localrange = this.convertValues(source["localrange"], null);
	        this.locallistenport = source["locallistenport"];
	        this.mtu = source["mtu"];
	        this.privatekey = source["privatekey"];
	        this.publickey = source["publickey"];
	        this.macaddress = source["macaddress"];
	        this.traffickeyprivate = source["traffickeyprivate"];
	        this.traffickeypublic = source["traffickeypublic"];
	        this.internetgateway = this.convertValues(source["internetgateway"], null);
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
	    id: string;
	    hostid: string;
	    network: string;
	    networkrange: any; // Go type: net.IPNet
	    networkrange6: any; // Go type: net.IPNet
	    internetgateway?: any; // Go type: net.UDPAddr
	    server: string;
	    connected: boolean;
	    address: any; // Go type: net.IPNet
	    address6: any; // Go type: net.IPNet
	    postup: string;
	    postdown: string;
	    action: string;
	    islocal: boolean;
	    isegressgateway: boolean;
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
	        this.internetgateway = this.convertValues(source["internetgateway"], null);
	        this.server = source["server"];
	        this.connected = source["connected"];
	        this.address = this.convertValues(source["address"], null);
	        this.address6 = this.convertValues(source["address6"], null);
	        this.postup = source["postup"];
	        this.postdown = source["postdown"];
	        this.action = source["action"];
	        this.islocal = source["islocal"];
	        this.isegressgateway = source["isegressgateway"];
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
	    verson: string;
	    api: string;
	    corednsaddress: string;
	    broker: string;
	    mqport: string;
	    mqid: string;
	    password: string;
	    dnsmode: boolean;
	    isee: boolean;
	    nodes: {[key: string]: boolean};
	    traffickey: number[];
	    accesskey: string;
	
	    static createFrom(source: any = {}) {
	        return new Server(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.verson = source["verson"];
	        this.api = source["api"];
	        this.corednsaddress = source["corednsaddress"];
	        this.broker = source["broker"];
	        this.mqport = source["mqport"];
	        this.mqid = source["mqid"];
	        this.password = source["password"];
	        this.dnsmode = source["dnsmode"];
	        this.isee = source["isee"];
	        this.nodes = source["nodes"];
	        this.traffickey = source["traffickey"];
	        this.accesskey = source["accesskey"];
	    }
	}

}

export namespace main {
	
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

}

export namespace models {
	
	export class AccessToken {
	    apiconnstring: string;
	    network: string;
	    key: string;
	    localrange: string;
	
	    static createFrom(source: any = {}) {
	        return new AccessToken(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.apiconnstring = source["apiconnstring"];
	        this.network = source["network"];
	        this.key = source["key"];
	        this.localrange = source["localrange"];
	    }
	}

}

