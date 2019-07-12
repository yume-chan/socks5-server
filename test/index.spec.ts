import * as net from 'net';

import Socks5ServerConnection, {
    Socks5Address,
    Socks5AuthenticateMethod,
    Socks5Command,
    Socks5CommandResponse,
    Socks5ConnectionState,
    Socks5Version,
} from '../src';

function runSteps(authenticateMethods: Socks5AuthenticateMethod[], done: () => void, ...steps: ((connection: Socks5ServerConnection, response: Buffer) => void)[]): void {
    const connection = new Socks5ServerConnection();
    expect(connection).toHaveProperty('state', Socks5ConnectionState.Handshake);

    let index = 0;
    connection.on('data', (response) => {
        steps[index](connection, response);
        index += 1;
        if (index === steps.length) {
            done();
        }
    });

    let request = Buffer.alloc(2 + authenticateMethods.length);
    // VER - 0x05
    request.writeUInt8(Socks5Version, 0);
    // NMETHODS
    request.writeUInt8(authenticateMethods.length, 1);
    let offset = 2;
    for (const method of authenticateMethods) {
        // METHODS
        request.writeUInt8(method, offset);
        offset += 1;
    }

    connection.process(request);
}

describe('socks5-server', () => {
    const port = 9033;
    let echo!: net.Server;

    beforeAll(() => {
        echo = net.createServer(client => {
            client.on('data', (data) => {
                client.write(data);
            });
        });
        echo.listen(port);
    });

    afterAll(() => {
        echo.close();
    });

    it('version should be 5', () => {
        expect(Socks5Version).toBe(5);
    });

    it('should handle handshake', (done) => {
        runSteps(
            [Socks5AuthenticateMethod.None],
            done,
            (connection, response) => {
                expect(connection).toHaveProperty('state', Socks5ConnectionState.WaitCommand);
                expect(response).toEqual(Buffer.from([Socks5Version, Socks5AuthenticateMethod.None]));
            },
        );
    });

    it('should reject connection with wrong version', (done) => {
        const connection = new Socks5ServerConnection();

        connection.on('close', done);

        let request = Buffer.alloc(1);
        // VER - 0x04
        request.writeUInt8(Socks5Version - 1, 0);

        connection.process(request);
    });

    it('should select NONE authentication', (done) => {
        runSteps(
            [Socks5AuthenticateMethod.None, Socks5AuthenticateMethod.UsernamePassword],
            done,
            (connection, response) => {
                expect(connection).toHaveProperty('state', Socks5ConnectionState.WaitCommand);
                expect(response).toEqual(Buffer.from([Socks5Version, Socks5AuthenticateMethod.None]));
            },
        );
    });

    it('should handle CONNECT command', (done) => {
        runSteps(
            [Socks5AuthenticateMethod.None, Socks5AuthenticateMethod.UsernamePassword],
            done,
            (connection) => {
                const address = new Socks5Address('127.0.0.1');
                let request = Buffer.alloc(6 + address.buffer.length);
                // VER - 0x05
                request.writeInt8(Socks5Version, 0);
                // CMD - CONNECT X'01'
                request.writeInt8(Socks5Command.Connect, 1);
                // ATYP
                request.writeInt8(address.type, 3);
                // DST.ADDR
                request.set(address.buffer, 4);
                // DST.PORT
                request.writeUInt16BE(port, 4 + address.buffer.length);

                connection.process(request);
            },
            (connection, response) => {
                expect(connection).toHaveProperty('state', Socks5ConnectionState.Relay);

                // VER - 0x05
                expect(response.readUInt8(0)).toBe(Socks5Version);
                // REP - X'00' succeeded
                expect(response.readUInt8(1)).toBe(Socks5CommandResponse.Success);

                connection.close();
            },
        );
    });

    it('should relay in CONNECT mode', (done) => {
        const message = Buffer.from('hello, world!', 'utf8');

        runSteps(
            [Socks5AuthenticateMethod.None, Socks5AuthenticateMethod.UsernamePassword],
            done,
            (connection) => {
                const address = new Socks5Address('127.0.0.1');
                let request = Buffer.alloc(6 + address.buffer.length);
                // VER - 0x05
                request.writeInt8(Socks5Version, 0);
                // CMD - CONNECT X'01'
                request.writeInt8(Socks5Command.Connect, 1);
                // ATYP
                request.writeInt8(address.type, 3);
                // DST.ADDR
                request.set(address.buffer, 4);
                // DST.PORT
                request.writeUInt16BE(port, 4 + address.buffer.length);

                connection.process(request);
            },
            (connection, response) => {
                connection.process(message);
            },
            (connection, response) => {
                expect(response).toEqual(message);

                connection.close();
            },
        );
    });
});
