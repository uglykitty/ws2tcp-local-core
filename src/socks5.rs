use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{Context, Result, bail};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

const SOCKS5_VERSION: u8 = 0x05;
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const AUTH_NO_AUTH: u8 = 0x00;
const AUTH_NO_ACCEPTABLE: u8 = 0xFF;

/// A SOCKS5 CONNECT reply reporting success, with an all-zero BND.ADDR/BND.PORT.
/// Clients are expected to use the tunnel itself rather than the bound address.
pub(crate) const SUCCESS_REPLY: [u8; 10] =
    [SOCKS5_VERSION, 0x00, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0];
/// A SOCKS5 CONNECT reply reporting a general server failure (REP 0x01).
pub(crate) const GENERAL_FAILURE_REPLY: [u8; 10] =
    [SOCKS5_VERSION, 0x01, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0];

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Socks5Request {
    pub(crate) authority: String,
}

/// What a client asked for after the SOCKS5 handshake.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Socks5Command {
    /// A CONNECT request for a single TCP-like stream to `authority`.
    Connect(Socks5Request),
    /// A UDP ASSOCIATE request. The caller replies with the local relay socket
    /// it will read/write SOCKS5 UDP datagrams on; the destination for each
    /// datagram is carried in the datagram itself, not in this request.
    UdpAssociate,
}

/// Reads a SOCKS5 no-authentication handshake followed by a request.
/// `socks5h` semantics fall out naturally: a domain-name (ATYP 0x03) target is
/// forwarded to the caller as a hostname rather than resolved locally here.
pub(crate) async fn read_socks5_request(client: &mut TcpStream) -> Result<Socks5Command> {
    negotiate_auth(client).await?;
    read_command(client).await
}

async fn negotiate_auth(client: &mut TcpStream) -> Result<()> {
    let mut header = [0_u8; 2];
    client
        .read_exact(&mut header)
        .await
        .context("read SOCKS5 greeting failed")?;
    let [version, method_count] = header;
    if version != SOCKS5_VERSION {
        bail!("unsupported SOCKS version {version} in greeting");
    }

    let mut methods = vec![0_u8; method_count as usize];
    client
        .read_exact(&mut methods)
        .await
        .context("read SOCKS5 auth methods failed")?;

    if !methods.contains(&AUTH_NO_AUTH) {
        client
            .write_all(&[SOCKS5_VERSION, AUTH_NO_ACCEPTABLE])
            .await
            .context("write SOCKS5 method rejection failed")?;
        bail!(
            "client did not offer a supported SOCKS5 auth method; only no-authentication is supported"
        );
    }

    client
        .write_all(&[SOCKS5_VERSION, AUTH_NO_AUTH])
        .await
        .context("write SOCKS5 method selection failed")
}

async fn read_command(client: &mut TcpStream) -> Result<Socks5Command> {
    let mut header = [0_u8; 4];
    client
        .read_exact(&mut header)
        .await
        .context("read SOCKS5 request header failed")?;
    let [version, cmd, _reserved, address_type] = header;
    if version != SOCKS5_VERSION {
        bail!("unsupported SOCKS version {version} in request");
    }
    if cmd != CMD_CONNECT && cmd != CMD_UDP_ASSOCIATE {
        bail!("unsupported SOCKS5 command {cmd}; only CONNECT and UDP ASSOCIATE are supported");
    }

    let host = read_address(client, address_type).await?;
    let mut port = [0_u8; 2];
    client
        .read_exact(&mut port)
        .await
        .context("read SOCKS5 port failed")?;

    if cmd == CMD_UDP_ASSOCIATE {
        // DST.ADDR/DST.PORT here are the address the client intends to send from, which
        // most clients leave as 0.0.0.0:0; the real per-datagram destination travels in
        // each UDP packet instead, so it is not needed here.
        return Ok(Socks5Command::UdpAssociate);
    }

    Ok(Socks5Command::Connect(Socks5Request {
        authority: format!("{host}:{}", u16::from_be_bytes(port)),
    }))
}

/// Builds a SOCKS5 UDP ASSOCIATE success reply carrying the local relay socket the client
/// should send its UDP datagrams to (and receive replies from).
pub(crate) fn udp_associate_reply(bound: SocketAddr) -> Vec<u8> {
    let mut reply = vec![SOCKS5_VERSION, 0x00, 0x00];
    match bound {
        SocketAddr::V4(addr) => {
            reply.push(ATYP_IPV4);
            reply.extend_from_slice(&addr.ip().octets());
        }
        SocketAddr::V6(addr) => {
            reply.push(ATYP_IPV6);
            reply.extend_from_slice(&addr.ip().octets());
        }
    }
    reply.extend_from_slice(&bound.port().to_be_bytes());
    reply
}

/// Parses a SOCKS5 UDP request datagram (RFC 1928 §7): `RSV(2) FRAG(1) ATYP DST.ADDR
/// DST.PORT DATA`. Returns the destination host, port, and the payload slice. Fragmented
/// datagrams (FRAG != 0) are not supported, since real clients essentially never send them.
pub(crate) fn parse_udp_datagram(data: &[u8]) -> Result<(String, u16, &[u8])> {
    if data.len() < 4 {
        bail!("SOCKS5 UDP datagram shorter than its header");
    }
    if data[2] != 0x00 {
        bail!("SOCKS5 UDP datagram fragmentation is not supported");
    }
    let address_type = data[3];
    let mut offset = 4_usize;

    let host = match address_type {
        ATYP_IPV4 => {
            let end = offset + 4;
            let octets: [u8; 4] = data
                .get(offset..end)
                .context("SOCKS5 UDP datagram truncated in IPv4 address")?
                .try_into()
                .expect("slice of length 4");
            offset = end;
            Ipv4Addr::from(octets).to_string()
        }
        ATYP_DOMAIN => {
            let length = *data
                .get(offset)
                .context("SOCKS5 UDP datagram truncated before domain length")?
                as usize;
            offset += 1;
            let end = offset + length;
            let domain = data
                .get(offset..end)
                .context("SOCKS5 UDP datagram truncated in domain name")?;
            offset = end;
            String::from_utf8(domain.to_vec())
                .context("SOCKS5 UDP datagram domain name is not valid UTF-8")?
        }
        ATYP_IPV6 => {
            let end = offset + 16;
            let octets: [u8; 16] = data
                .get(offset..end)
                .context("SOCKS5 UDP datagram truncated in IPv6 address")?
                .try_into()
                .expect("slice of length 16");
            offset = end;
            format!("[{}]", Ipv6Addr::from(octets))
        }
        other => bail!("unsupported SOCKS5 UDP address type {other}"),
    };

    let port_end = offset + 2;
    let port_bytes = data
        .get(offset..port_end)
        .context("SOCKS5 UDP datagram truncated in port")?;
    let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);

    Ok((host, port, &data[port_end..]))
}

/// Builds a SOCKS5 UDP response datagram wrapping `payload` as coming from `host:port`,
/// the inverse of [`parse_udp_datagram`]. `host` is written as a raw IP address when it
/// parses as one (stripping the `[...]` IPv6 brackets `read_address` adds), and as a
/// domain name otherwise.
pub(crate) fn build_udp_datagram(host: &str, port: u16, payload: &[u8]) -> Vec<u8> {
    let mut datagram = vec![0x00, 0x00, 0x00];
    let bracketed_ipv6 = host.strip_prefix('[').and_then(|h| h.strip_suffix(']'));

    if let Ok(addr) = host.parse::<Ipv4Addr>() {
        datagram.push(ATYP_IPV4);
        datagram.extend_from_slice(&addr.octets());
    } else if let Ok(addr) = bracketed_ipv6.unwrap_or(host).parse::<Ipv6Addr>() {
        datagram.push(ATYP_IPV6);
        datagram.extend_from_slice(&addr.octets());
    } else {
        // Domain names longer than 255 bytes cannot be represented; truncation here would
        // silently corrupt the target, so this is treated as a bug in the caller rather
        // than handled gracefully.
        let host_bytes = host.as_bytes();
        assert!(host_bytes.len() <= 255, "SOCKS5 UDP domain name too long");
        datagram.push(ATYP_DOMAIN);
        datagram.push(host_bytes.len() as u8);
        datagram.extend_from_slice(host_bytes);
    }

    datagram.extend_from_slice(&port.to_be_bytes());
    datagram.extend_from_slice(payload);
    datagram
}

async fn read_address(client: &mut TcpStream, address_type: u8) -> Result<String> {
    match address_type {
        ATYP_IPV4 => {
            let mut octets = [0_u8; 4];
            client
                .read_exact(&mut octets)
                .await
                .context("read SOCKS5 IPv4 address failed")?;
            Ok(std::net::Ipv4Addr::from(octets).to_string())
        }
        ATYP_DOMAIN => {
            let mut len = [0_u8; 1];
            client
                .read_exact(&mut len)
                .await
                .context("read SOCKS5 domain length failed")?;
            let mut domain = vec![0_u8; len[0] as usize];
            client
                .read_exact(&mut domain)
                .await
                .context("read SOCKS5 domain name failed")?;
            String::from_utf8(domain).context("SOCKS5 domain name is not valid UTF-8")
        }
        ATYP_IPV6 => {
            let mut octets = [0_u8; 16];
            client
                .read_exact(&mut octets)
                .await
                .context("read SOCKS5 IPv6 address failed")?;
            Ok(format!("[{}]", std::net::Ipv6Addr::from(octets)))
        }
        other => bail!("unsupported SOCKS5 address type {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    async fn connected_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    fn connect_authority(command: Socks5Command) -> String {
        match command {
            Socks5Command::Connect(request) => request.authority,
            Socks5Command::UdpAssociate => panic!("expected a Connect command"),
        }
    }

    #[tokio::test]
    async fn parses_domain_connect_request() {
        let (mut client, mut server) = connected_pair().await;

        let write_task = tokio::spawn(async move {
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut method_reply = [0_u8; 2];
            client.read_exact(&mut method_reply).await.unwrap();
            assert_eq!(method_reply, [0x05, 0x00]);

            let domain = b"example.com";
            let mut request = vec![0x05, 0x01, 0x00, 0x03, domain.len() as u8];
            request.extend_from_slice(domain);
            request.extend_from_slice(&443_u16.to_be_bytes());
            client.write_all(&request).await.unwrap();
        });

        let command = read_socks5_request(&mut server).await.unwrap();
        write_task.await.unwrap();

        assert_eq!(
            command,
            Socks5Command::Connect(Socks5Request {
                authority: "example.com:443".to_owned(),
            })
        );
    }

    #[tokio::test]
    async fn parses_ipv4_connect_request() {
        let (mut client, mut server) = connected_pair().await;

        let write_task = tokio::spawn(async move {
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut method_reply = [0_u8; 2];
            client.read_exact(&mut method_reply).await.unwrap();

            let mut request = vec![0x05, 0x01, 0x00, 0x01];
            request.extend_from_slice(&[127, 0, 0, 1]);
            request.extend_from_slice(&8080_u16.to_be_bytes());
            client.write_all(&request).await.unwrap();
        });

        let command = read_socks5_request(&mut server).await.unwrap();
        write_task.await.unwrap();

        assert_eq!(connect_authority(command), "127.0.0.1:8080");
    }

    #[tokio::test]
    async fn parses_ipv6_connect_request() {
        let (mut client, mut server) = connected_pair().await;

        let write_task = tokio::spawn(async move {
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut method_reply = [0_u8; 2];
            client.read_exact(&mut method_reply).await.unwrap();

            let mut request = vec![0x05, 0x01, 0x00, 0x04];
            request.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
            request.extend_from_slice(&443_u16.to_be_bytes());
            client.write_all(&request).await.unwrap();
        });

        let command = read_socks5_request(&mut server).await.unwrap();
        write_task.await.unwrap();

        assert_eq!(connect_authority(command), "[::1]:443");
    }

    #[tokio::test]
    async fn rejects_unsupported_auth_method() {
        let (mut client, mut server) = connected_pair().await;

        let write_task = tokio::spawn(async move {
            client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
            let mut method_reply = [0_u8; 2];
            client.read_exact(&mut method_reply).await.unwrap();
            assert_eq!(method_reply, [0x05, 0xFF]);
        });

        assert!(read_socks5_request(&mut server).await.is_err());
        write_task.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_unsupported_command() {
        let (mut client, mut server) = connected_pair().await;

        let write_task = tokio::spawn(async move {
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut method_reply = [0_u8; 2];
            client.read_exact(&mut method_reply).await.unwrap();

            // BIND instead of CONNECT.
            let mut request = vec![0x05, 0x02, 0x00, 0x01];
            request.extend_from_slice(&[127, 0, 0, 1]);
            request.extend_from_slice(&8080_u16.to_be_bytes());
            client.write_all(&request).await.unwrap();
        });

        assert!(read_socks5_request(&mut server).await.is_err());
        write_task.await.unwrap();
    }

    #[tokio::test]
    async fn parses_udp_associate_request() {
        let (mut client, mut server) = connected_pair().await;

        let write_task = tokio::spawn(async move {
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut method_reply = [0_u8; 2];
            client.read_exact(&mut method_reply).await.unwrap();

            // UDP ASSOCIATE, DST.ADDR/DST.PORT left as 0.0.0.0:0 as most clients do.
            let mut request = vec![0x05, 0x03, 0x00, 0x01];
            request.extend_from_slice(&[0, 0, 0, 0]);
            request.extend_from_slice(&0_u16.to_be_bytes());
            client.write_all(&request).await.unwrap();
        });

        let command = read_socks5_request(&mut server).await.unwrap();
        write_task.await.unwrap();

        assert_eq!(command, Socks5Command::UdpAssociate);
    }

    #[test]
    fn builds_udp_associate_reply_for_ipv4() {
        let reply = udp_associate_reply("127.0.0.1:40000".parse().unwrap());
        assert_eq!(
            reply,
            [0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x9c, 0x40]
        );
    }

    #[test]
    fn builds_udp_associate_reply_for_ipv6() {
        let reply = udp_associate_reply("[::1]:40000".parse().unwrap());
        assert_eq!(reply[0..4], [0x05, 0x00, 0x00, 0x04]);
        assert_eq!(reply.len(), 4 + 16 + 2);
    }

    #[test]
    fn round_trips_ipv4_udp_datagram() {
        let datagram = build_udp_datagram("8.8.8.8", 53, b"payload");
        let (host, port, payload) = parse_udp_datagram(&datagram).unwrap();
        assert_eq!(host, "8.8.8.8");
        assert_eq!(port, 53);
        assert_eq!(payload, b"payload");
    }

    #[test]
    fn round_trips_domain_udp_datagram() {
        let datagram = build_udp_datagram("example.com", 443, b"hello");
        let (host, port, payload) = parse_udp_datagram(&datagram).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
        assert_eq!(payload, b"hello");
    }

    #[test]
    fn round_trips_bracketed_ipv6_udp_datagram() {
        // IPv6 hosts are always bracketed in this codebase (matching `read_address`), both
        // going in and coming back out.
        let datagram = build_udp_datagram("[::1]", 53, b"hi");
        let (host, port, payload) = parse_udp_datagram(&datagram).unwrap();
        assert_eq!(host, "[::1]");
        assert_eq!(port, 53);
        assert_eq!(payload, b"hi");
    }

    #[test]
    fn rejects_truncated_udp_datagram() {
        assert!(parse_udp_datagram(&[0x00, 0x00, 0x00, 0x01, 1, 2, 3]).is_err());
        assert!(parse_udp_datagram(&[]).is_err());
    }

    #[test]
    fn rejects_fragmented_udp_datagram() {
        let mut datagram = build_udp_datagram("8.8.8.8", 53, b"payload");
        datagram[2] = 0x01; // FRAG != 0
        assert!(parse_udp_datagram(&datagram).is_err());
    }
}
