# SOCKS5 Server

[![travis-ci](https://travis-ci.org/yume-chan/socks5-server.svg?branch=master)](https://travis-ci.org/yume-chan/socks5-server)
[![Greenkeeper badge](https://badges.greenkeeper.io/yume-chan/socks5-server.svg)](https://greenkeeper.io/)

An SOCKS5 server implementation that doesn't tie to specific transportation

- [SOCKS5 Server](#SOCKS5-Server)
  - [Limitation](#Limitation)
  - [API](#API)
    - [Usage](#Usage)
  - [Development](#Development)
    - [Install dependencies:](#Install-dependencies)
    - [Testing](#Testing)
    - [Coverage](#Coverage)
  - [License](#License)

## Limitation

* Only support NONE authentication.
* Only support CONNECT command

## API

``` ts
export default class Socks5ServerConnection extends Duplex {
    write(data: Buffer): void;

    end(): void;

    on(event: 'data', listener: (data: Buffer) => void): void;
    on(event: 'close', listener: () => void): void;
}
```

### Usage

1. Create `Socks5ServerConnection` instance for each new client connection
2. Feed data from client into `process` function
3. Feed data from `data` event to client
4. Invoke `end` when client closes connection
5. Close client connection when `close` event fire

## Development

This project uses [pnpm](https://pnpm.js.org/) ([GitHub](https://github.com/pnpm/pnpm)) to manage dependency packages.

### Install dependencies:

``` shell
pnpm i
```

You may also use `npm`, but the lockfile may become out of sync.

### Testing

``` shell
npm test
```

### Coverage

``` shell
npm run coverage
```

## License

MIT
