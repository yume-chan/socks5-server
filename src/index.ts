import net from 'net';
import { EventEmitter, once } from 'events';

import * as ipaddr from 'ipaddr.js';
import { Duplex } from 'stream';

export enum Socks5ConnectionState {
    Handshake,
    Authentication,
    WaitCommand,
    Relay,
}

export enum Socks5AuthenticateMethod {
    None = 0x00,
    Gssapi = 0x01,
    UsernamePassword = 0x02
}

export enum Socks5Command {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssociate = 0x03,
}

export enum Socks5CommandResponse {
    Success = 0x00,
    GeneralError = 0x01,
    Forbidden = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    TtlExpired = 0x06,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
}

export enum Socks5AddressType {
    Ipv4 = 0x01,
    DomainName = 0x03,
    Ipv6 = 0x04,
}

class BufferReader {
    private _buffer: Buffer;

    private _offset: number = 0;

    constructor(buffer: Buffer) {
        this._buffer = buffer;
    }

    public readUint8(): number {
        const result = this._buffer.readUInt8(this._offset);
        this._offset += 1;
        return result;
    }

    public readUint16BE(): number {
        const result = this._buffer.readUInt16BE(this._offset);
        this._offset += 2;
        return result;
    }

    public readString(length: number): string {
        const end = this._offset + length;
        const result = this._buffer.toString('utf8', this._offset, end);
        this._offset = end;
        return result;
    }

    public readBuffer(length: number): Buffer {
        const end = this._offset + length;
        const result = this._buffer.slice(this._offset, end);
        this._offset = end;
        return result;
    }
}

export interface Socks5CommandHandler {
    process(data: Buffer): Promise<void>;

    read(): void;

    end(): Promise<void>;
}

export interface Socks5CommandHandlerConstructor {
    constructor(emitter: EventEmitter, address: string, port: number): Socks5CommandHandler;
}

export class Socks5ConnectCommandHandler implements Socks5CommandHandler {
    private _connection: Socks5ServerConnection;

    private _address: string;
    public get address(): string { return this._address; }

    private _port: number;
    public get port(): number { return this._port; }

    private _socket: net.Socket;

    constructor(connection: Socks5ServerConnection, address: string, port: number) {
        this._connection = connection;

        this._address = address;
        this._port = port;

        this._socket = net.connect(port, address);
        this._socket.on('connect', () => {
            const localAddress = ipaddr.process(this._socket.localAddress).toByteArray();
            const localPort = this._socket.localPort;

            const response = Buffer.alloc(6 + localAddress.length);
            response.writeUInt8(Socks5Version, 0);
            response.writeUInt8(Socks5CommandResponse.Success, 1);
            response.writeUInt8(localAddress.length === 4 ? Socks5AddressType.Ipv4 : Socks5AddressType.Ipv6, 3);
            response.set(localAddress, 4);
            response.writeUInt16BE(localPort, 4 + localAddress.length);
            this._connection.push(response);

            this.read();
        });
        this._socket.on('error', () => {
            if (this._socket.connecting) {
                const response = Buffer.alloc(6 + 4);
                response.writeUInt8(Socks5Version, 0);
                response.writeUInt8(Socks5CommandResponse.Success, 1);
                response.writeUInt8(Socks5AddressType.Ipv4, 3);
                this._connection.push(response);
            } else {
                this._connection.push(null);
                this._connection.end();
            }
        });
    }

    process(data: Buffer): Promise<void> {
        return new Promise<void>((resolve, reject) => {
            this._socket.write(data, (err) => {
                if (err) {
                    reject(err);
                } else {
                    resolve();
                }
            });
        });
    }

    async read() {
        while (this._connection.readableLength < this._connection.readableHighWaterMark) {
            if (this._socket.readableLength === 0) {
                await once(this._socket, 'readable');
            }
            this._connection.push(this._socket.read());
        }
    }

    async end(): Promise<void> {
        this._socket.end();
        await once(this._socket, 'close');
    }
}

export class Socks5Address {
    public readonly type: Socks5AddressType;
    public readonly buffer: Buffer;

    constructor(address: string) {
        try {
            const parsed = ipaddr.process(address);
            this.type = parsed.kind() === "ipv4" ? Socks5AddressType.Ipv4 : Socks5AddressType.Ipv6;
            this.buffer = Buffer.from(parsed.toByteArray());
        } catch (e) {
            let content = Buffer.from(address, 'utf8');
            let result = Buffer.alloc(content.length + 1);
            result.writeUInt8(content.length, 0);
            result.set(content, 1);
            this.type = Socks5AddressType.DomainName;
            this.buffer = result;
        }
    }
}

export const Socks5Version = 0x05;

/**
 * @see https://tools.ietf.org/html/rfc1928
 */
export default class Socks5ServerConnection extends Duplex {
    private _state: Socks5ConnectionState = Socks5ConnectionState.Handshake;
    public get state(): Socks5ConnectionState { return this._state; }

    private _handler: Socks5CommandHandler | undefined;
    public get handler(): Socks5CommandHandler | undefined { return this._handler; }

    private checkVersion(data: BufferReader): boolean {
        if (data.readUint8() !== Socks5Version) {
            this.push(null);
            this.end();
            return false;
        }

        return true;
    }

    private async process(data: Buffer): Promise<void> {
        const reader = new BufferReader(data);

        switch (this._state) {
            case Socks5ConnectionState.Handshake:
                if (!this.checkVersion(reader)) {
                    return;
                }

                const response = Buffer.alloc(2);
                response.writeUInt8(0x5, 0);

                const length = reader.readUint8();
                for (let i = 0; i < length; i++) {
                    const method: Socks5AuthenticateMethod = reader.readUint8();
                    if (method === Socks5AuthenticateMethod.None) {
                        response.writeUInt8(method, 1);
                        this._state = Socks5ConnectionState.WaitCommand;
                        this.push(response);
                        return;
                    }
                }

                response.writeUInt8(0xFF, 1);
                this.push(response);
                break;
            case Socks5ConnectionState.WaitCommand:
                if (!this.checkVersion(reader)) {
                    return;
                }

                const command: Socks5Command = reader.readUint8();

                // reserved
                reader.readUint8();

                const addressType: Socks5AddressType = reader.readUint8();

                let address: string;
                switch (addressType) {
                    case Socks5AddressType.Ipv4:
                        address = ipaddr.fromByteArray(Array.from(reader.readBuffer(4))).toString();
                        break;
                    case Socks5AddressType.DomainName:
                        const length = reader.readUint8();
                        address = reader.readString(length);
                        break;
                    case Socks5AddressType.Ipv6:
                        address = ipaddr.fromByteArray(Array.from(reader.readBuffer(16))).toString();
                        break;
                    default:
                        const response = Buffer.alloc(10);
                        response.writeUInt8(Socks5Version, 0);
                        response.writeUInt8(Socks5CommandResponse.AddressTypeNotSupported, 1);
                        response.writeUInt8(Socks5AddressType.Ipv4, 3);
                        this.push(response);
                        return;
                }

                const port = reader.readUint16BE();

                switch (command) {
                    case Socks5Command.Connect:
                        this._handler = new Socks5ConnectCommandHandler(this, address, port);
                        this._state = Socks5ConnectionState.Relay;
                        break;
                    case Socks5Command.Bind:
                    case Socks5Command.UdpAssociate:
                    default:
                        const response = Buffer.alloc(10);
                        response.writeUInt8(Socks5Version, 0);
                        response.writeUInt8(Socks5CommandResponse.CommandNotSupported, 1);
                        response.writeUInt8(Socks5AddressType.Ipv4, 3);
                        this.push(response);
                        return;
                }
                break;
            case Socks5ConnectionState.Relay:
                await this._handler!.process(data);
                break;
        }
    }

    public _read() {
        if (this._handler) {
            this._handler.read();
        }
    }

    public async _write(chunk: Buffer, encoding: string, callback: (err?: Error) => void): Promise<void> {
        try {
            await this.process(chunk);
            callback();
        } catch (e) {
            callback(e);
        }
    }

    public async _final(callback: (err: Error | null) => void): Promise<void> {
        if (this._handler) {
            await this._handler.end();
        }

        callback(null);
        this.destroy();
    }

    public _destroy(err: Error | null, callback: (err: Error | null) => void) {
        this.emit('close');
        callback(err);
    }
}
