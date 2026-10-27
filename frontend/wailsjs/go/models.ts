export class IdentityInfo {
    enrolled: boolean;
    team: string;
    deviceName: string;
    deviceId: string;
    ipv4: string;
    ipv6: string;
    endpoint: string;

    static createFrom(source: any = {}) {
        return new IdentityInfo(source);
    }

    constructor(source: any = {}) {
        if ('string' === typeof source) source = JSON.parse(source);
        this.enrolled = source["enrolled"];
        this.team = source["team"];
        this.deviceName = source["deviceName"];
        this.deviceId = source["deviceId"];
        this.ipv4 = source["ipv4"];
        this.ipv6 = source["ipv6"];
        this.endpoint = source["endpoint"];
    }
}

export namespace app {
	
	export class Conflict {
	    org: string;
	    local: string;
	
	    static createFrom(source: any = {}) {
	        return new Conflict(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.org = source["org"];
	        this.local = source["local"];
	    }
	}
	export class EnrollRequest {
	    team: string;
	    token: string;
	    deviceName: string;
	    acceptTos: boolean;
	
	    static createFrom(source: any = {}) {
	        return new EnrollRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.team = source["team"];
	        this.token = source["token"];
	        this.deviceName = source["deviceName"];
	        this.acceptTos = source["acceptTos"];
	    }
	}
	export class Status {
	    enrolled: boolean;
	    team: string;
	    deviceName: string;
	    deviceId: string;
	    ipv4: string;
	    ipv6: string;
	    endpoint: string;
	    state: string;
	    iface: string;
	    lastError: string;
	
	    static createFrom(source: any = {}) {
	        return new Status(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.enrolled = source["enrolled"];
	        this.team = source["team"];
	        this.deviceName = source["deviceName"];
	        this.deviceId = source["deviceId"];
	        this.ipv4 = source["ipv4"];
	        this.ipv6 = source["ipv6"];
	        this.endpoint = source["endpoint"];
	        this.state = source["state"];
	        this.iface = source["iface"];
	        this.lastError = source["lastError"];
	    }
	}
	export class EnrollResult {
	    error?: string;
	    status: Status;
	
	    static createFrom(source: any = {}) {
	        return new EnrollResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.error = source["error"];
	        this.status = this.convertValues(source["status"], Status);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
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
	export class Entry {
	    value: string;
	    kind: string;
	    description?: string;
	
	    static createFrom(source: any = {}) {
	        return new Entry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.value = source["value"];
	        this.kind = source["kind"];
	        this.description = source["description"];
	    }
	}
	export class SplitView {
	    mode: string;
	    modeSource: string;
	    remoteAvailable: boolean;
	    remoteError?: string;
	    remoteNote?: string;
	    orgEntries: Entry[];
	    localEntries: Entry[];
	    conflicts: Conflict[];
	    localMode: string;
	    connected: boolean;
	    warnings?: string[];
	
	    static createFrom(source: any = {}) {
	        return new SplitView(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.mode = source["mode"];
	        this.modeSource = source["modeSource"];
	        this.remoteAvailable = source["remoteAvailable"];
	        this.remoteError = source["remoteError"];
	        this.remoteNote = source["remoteNote"];
	        this.orgEntries = this.convertValues(source["orgEntries"], Entry);
	        this.localEntries = this.convertValues(source["localEntries"], Entry);
	        this.conflicts = this.convertValues(source["conflicts"], Conflict);
	        this.localMode = source["localMode"];
	        this.connected = source["connected"];
	        this.warnings = source["warnings"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
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

