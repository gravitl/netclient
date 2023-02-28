export namespace config {
  export class NcConfig {
    id: string;
    verbosity: number;
    firewallinuse: string;
    version: string;
    ipforwarding: boolean;
    daemoninstalled: boolean;
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
    macaddress: string;
    traffickeypublic: number[];
    internetgateway: any;

    nodes: string[];
    isrelayed: boolean;
    relayed_by: string;
    isrelay: boolean;
    relay_hosts: string[];
    interfaces: any[];
    defautlinterface: string;
    endpointip: any;
    proxy_enabled: boolean;
    isdocker: boolean;
    isk8s: boolean;
    isstatic: boolean;
    isdefault: boolean;
		macaddressstr: string;

    static createFrom(source: any = {}) {
      return new NcConfig(source);
    }

    constructor(source: any = {}) {
      if ("string" === typeof source) source = JSON.parse(source);
      this.id = source["verbosity"];
      this.verbosity = source["verbosity"];
      this.firewallinuse = source["firewallinuse"];
      this.version = source["version"];
      this.ipforwarding = source["ipforwarding"];
      this.daemoninstalled = source["daemoninstalled"];
      this.hostpass = source["hostpass"];
      this.name = source["name"];
      this.os = source["os"];
      this.debug = source["debug"];
      this.listenport = source["listenport"];
      this.mtu = source["mtu"];
      this.publickey = source["publickey"];
      this.macaddress = source["macaddress"];
      this.traffickeypublic = source["traffickeypublic"];
      this.internetgateway = this.convertValues(
        source["internetgateway"],
        null
      );
      this.interface = source["interface"];
      this.public_listen_port = source["public_listen_port"];
      this.proxy_listen_port = source["proxy_listen_port"];
      this.nodes = source["nodes"];
      this.isrelayed = source["isrelayed"];
      this.relayed_by = source["relayed_by"];
      this.isrelay = source["isrelay"];
      this.relay_hosts = source["relay_hosts"];
      this.interfaces = source["interfaces"];
      this.defautlinterface = source["defautlinterface"];
      this.endpointip = this.convertValues(source["endpointip"], null);
      this.proxy_enabled = source["proxy_enabled"];
      this.isdocker = source["isdocker"];
      this.isk8s = source["isk8s"];
      this.isstatic = source["isstatic"];
      this.isdefault = source["isdefault"];
      this.macaddressstr = source["macaddressstr"];
    }

    convertValues(a: any, classs: any, asMap: boolean = false): any {
      if (!a) {
        return a;
      }
      if (a.slice) {
        return (a as any[]).map((elem) => this.convertValues(elem, classs));
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
      if ("string" === typeof source) source = JSON.parse(source);
      this.id = source["id"];
      this.hostid = source["hostid"];
      this.network = source["network"];
      this.networkrange = this.convertValues(source["networkrange"], null);
      this.networkrange6 = this.convertValues(source["networkrange6"], null);
      this.internetgateway = this.convertValues(
        source["internetgateway"],
        null
      );
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
        return (a as any[]).map((elem) => this.convertValues(elem, classs));
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
    nodes: { [key: string]: boolean };
    traffickey: number[];
    accesskey: string;

    static createFrom(source: any = {}) {
      return new Server(source);
    }

    constructor(source: any = {}) {
      if ("string" === typeof source) source = JSON.parse(source);
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
      if ("string" === typeof source) source = JSON.parse(source);
      this.node = this.convertValues(source["node"], config.Node);
      this.server = this.convertValues(source["server"], config.Server);
    }

    convertValues(a: any, classs: any, asMap: boolean = false): any {
      if (!a) {
        return a;
      }
      if (a.slice) {
        return (a as any[]).map((elem) => this.convertValues(elem, classs));
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
      if ("string" === typeof source) source = JSON.parse(source);
      this.apiconnstring = source["apiconnstring"];
      this.network = source["network"];
      this.key = source["key"];
      this.localrange = source["localrange"];
    }
  }
}
