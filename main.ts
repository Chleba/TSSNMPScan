// SNMP Scanner typescript/RXJS BE test
// SNMP Scanner class that may have multiple instances for different CIDR ranges
// This class is having a buffer with variable size where handling 
// IP's snmp sessions is stored.
// Created snmp session with specific IP will try to connect to SNMP where first 
// will get it's hostname, then it will try to get it's interfaces table.
// Those informations (ip, hostname & interfaces) will be written into a 
// console as result for that specific IP address.
// IF hostname OR interfaces is not present BUT IP address will react to snmp,
// then the IP address will be put into a console as well.
// After all required information is recieved from IP, session will be closed and
// that session is removed from active sessions buffer where next IP address will start processing.  

import { Observable, Subscriber, from } from 'rxjs';
import { map, catchError } from 'rxjs/operators';
import IPCIDR from 'ip-cidr';

// -- node-snmp unfortunately don't have TS dev types yet :(
const snmp = require ("net-snmp"); 

interface IOIDs {
	hostname: string;
	interfaces: string;
};

class SNMPCIDRScanner {
	
	private _port: number;
  private _timeout: number;
	private _bufferSize: number;
	private _communityStr: string;

	IPTotal: number;
	CIDR?: string;
	IPList: string[];
	IPBuffer: string[];
	IPFound: string[];
	oids: IOIDs;
	subscriber: Subscriber<any>;

	constructor(
		port?: number, 
		bufferSize?: number, 
		timeout?: number, 
		communityStr?: string
	) {
		this._communityStr = communityStr ?? 'public';
		this._port = port ?? 161;
    this._timeout = timeout ?? 2000;
		this._bufferSize = bufferSize ?? 25;

		this.CIDR = undefined;
		this.IPBuffer = [];
		this.oids = {
			hostname: '1.3.6.1.2.1.1.5.0',
			interfaces: '1.3.6.1.2.1.2.2',
		};
		this.IPTotal = 0;
		this.IPFound = [];
		this.IPList = [];
	}

	public get port(): number { return this._port; }
	public get timeout(): number { return this._timeout; }
	public get bufferSize(): number { return this._bufferSize; }
	public get communityStr(): string { return this._communityStr; }

	scan(CIDR: string): Observable<string> {
		this.IPFound = [];
		return new Observable((sub: Subscriber<any>) => {
			this.subscriber = sub;
			if (!IPCIDR.isValidCIDR(CIDR)) {
				this.subscriber.error('Invalid CIDR');
				this.subscriber.complete();
			}
			this.CIDR = CIDR;
			this.getIPList();
			this.startScan();
		});
	}

	getIPList() {
		const ipcidr = new IPCIDR(this.CIDR);
		const iplist = ipcidr.toArray();
		// -- get number of IP addresses to scan
		this.IPTotal = iplist.length;
		// -- add array into a instance variable
		this.IPList = iplist;
	}

	getSNMPHostname(session: any): Observable<string> {
		return new Observable((sub: Subscriber<any>) => {
			session.get([this.oids.hostname], (err: any, varbinds: any) => {
				if (err) {
					// console.log(err, 'hostname err');
					sub.error(err);
				} else {
					const hostname = `${varbinds[0].value}`
					sub.next(hostname);
					sub.complete();
				}
			});
		});
	}

	getSNMPInterfaces(session: any): Observable<string[]> {
		return new Observable((sub: Subscriber<any>) => {
			session.table(this.oids.interfaces, (err: any, table: any) => {
				if (err) {
					// console.log(err, 'if err');
					sub.error(err);
				} else {
					const ifs: string[] = [];
					for(let tk in table){
						const ifName = `${table[tk][2]}`;
						ifs.push(ifName);
					}
					sub.next(ifs);
					sub.complete();
				}
			});
		});
	}

	hostScanComplete(info: any) {
		from(this.getSNMPInterfaces(info.session)).pipe(
			map((ifs: string[]) => ({
				...info,
				ifs,
			})),
			catchError(() => {
				// -- ERROR while getting IF TABLE but we already have IP's hostname -> show
				const { ip, hostname, session } = info;
				const ipInfoStr = `${ip}; ${hostname};`;
				this.saveIPInfo(ipInfoStr);
				this.nextIP(session);
				return [];
			})
		).subscribe(this.IFScanComplete.bind(this));
	}

	IFScanComplete(info: any) {
		const { ip, hostname, ifs, session } = info;
		let ipInfoStr = `${ip}; ${hostname};`;
		ifs.forEach((intf, index) => {
			ipInfoStr += ` ${intf}`;
			if (index !== ifs.length -1) {
				ipInfoStr += ',';
			}
		})
		// -- write found info into a array
		this.saveIPInfo(ipInfoStr);
		// -- session is done -> close
		this.nextIP(session);
	}

	saveIPInfo(ipInfo: string) {
		this.IPFound.push(ipInfo);
	}

	nextIP(session: any) {
		// -- remove session from buffer
		this.IPBuffer.splice(this.IPBuffer.findIndex((ipb:any) => ipb === session), 1);
		// -- close session
		session.close();
		// -- scan another IP from list and put it into a buffer
		this.scanIP()
		// -- show progress of scanning IPs
		this.showProgress();
	}

	scanIP() {
		if (this.IPBuffer.length < this.bufferSize) {
			const ip = this.IPList.pop();
			if (ip) {
				const session = snmp.createSession(ip, this.communityStr, {
					timeout: this.timeout,
					port: this.port,
				});
				this.IPBuffer.push(session);

				from(this.getSNMPHostname(session)).pipe(
					map((hostname: string) => ({
						session,
						ip,
						hostname
					})),
					catchError((err: any) => {
						// -- SNMP founded but access denied -> show IP
						if (err.code === 'EACCES') {
							this.saveIPInfo(`${ip}`);
						}
						this.nextIP(session);
						return [];
					})
				).subscribe(this.hostScanComplete.bind(this));
			} else {
				if (!this.IPBuffer.length) {
					// -- end of scanning
					this.showFoundIPs();
				}
			}
		}
	}

	startScan() {
		for(let i=0; i<this.bufferSize; i++) {
			this.scanIP();
		}
	}

	showProgress(end?: boolean) {
		const ipLeft = this.IPTotal - (this.IPList.length + this.IPBuffer.length);
		const ipLeftPercent = ((ipLeft / this.IPTotal) * 100).toFixed(2);
		const endLine = end ? '\n' : '\r';
		this.subscriber.next(`Scanned IP Addresses: ${ipLeft} / ${this.IPTotal} (${ipLeftPercent}%)${endLine}`);
		// process.stdout.write(`Scanned IP Addresses: ${ipLeft} / ${this.IPTotal} (${ipLeftPercent}%)${endLine}`);
	}

	showFoundIPs() {
		this.showProgress(true);

		this.subscriber.next('\n');
		this.subscriber.next('------------------------------------------\n');
		this.subscriber.next(`Found SNMP IPs for CIDR - ${this.CIDR}:\n`);
		this.subscriber.next('------------------------------------------\n');
		for(const [index, ipInfo] of this.IPFound.entries()) {
			this.subscriber.next(`${index + 1}: ${ipInfo}\n`);
		}

		this.subscriber.complete();
	}
}

// -- main process
const main = () => {
	const scanner = new SNMPCIDRScanner();
	console.log('Please enter CIDR you want to scan:');
	process.stdin.on('data', (data: string) => {
		const cidrAddress = `${data}`.trim();
		scanner.scan(cidrAddress).subscribe({
			next: (line: string) => { process.stdout.write(line); },
			complete: () => console.log('Please enter CIDR you want to scan:'),
			error: (err: string) => console.log(err),
		});
	});
}

main();
