use hbb_common::{
    anyhow::{anyhow, ensure},
    private_tcp::{register_client, ClientHandshake, SessionCipher},
    protobuf::Message,
    rendezvous_proto::*,
    sodiumoxide::crypto::sign,
    tcp::FramedStream,
    tokio, ResultType,
};
use std::time::Duration;

fn validate_target(host: &str, public: &str) -> ResultType<()> {
    let (_, port) = host
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("explicit_test_port_required"))?;
    let port: u16 = port.parse()?;
    ensure!(port != 0 && port != 48944, "production_port_refused");
    ensure!(
        public != "8JlBVwhzY1Vk1I1He0S7GwvBA1X++8KcziSU7lbxXis=",
        "production_key_refused"
    );
    ensure!(
        base64::decode(public)?.len() == 32,
        "invalid_server_public_key"
    );
    Ok(())
}

async fn connect(host: &str) -> ResultType<FramedStream> {
    let stream = hbb_common::timeout(5000, tokio::net::TcpStream::connect(host)).await??;
    let addr = stream.local_addr()?;
    let mut stream = FramedStream::from(stream, addr);
    stream.set_send_timeout(3000);
    Ok(stream)
}

async fn receive(stream: &mut FramedStream) -> ResultType<RendezvousMessage> {
    let bytes = stream
        .next_timeout(5000)
        .await
        .ok_or_else(|| anyhow!("probe_response_timeout"))??;
    Ok(RendezvousMessage::parse_from_bytes(&bytes)?)
}

async fn heartbeat(
    stream: &mut FramedStream,
    cipher: &mut SessionCipher,
    id: &str,
) -> ResultType<()> {
    let mut request = RendezvousMessage::new();
    request.set_register_peer(RegisterPeer {
        id: id.to_owned(),
        ..Default::default()
    });
    let mut outer = RendezvousMessage::new();
    outer.set_private_tcp_frame(cipher.seal(&request)?);
    stream.send(&outer).await?;
    let outer = receive(stream).await?;
    let response = cipher.open(outer.private_tcp_frame())?;
    ensure!(
        matches!(response.union, Some(rendezvous_message::Union::RegisterPeerResponse(ref r)) if !r.request_pk),
        "invalid_heartbeat_ack"
    );
    Ok(())
}

async fn controller(host: &str, id: &str, public: &str) -> ResultType<FramedStream> {
    let mut stream = connect(host).await?;
    let mut request = RendezvousMessage::new();
    request.set_punch_hole_request(PunchHoleRequest {
        id: id.to_owned(),
        licence_key: public.to_owned(),
        version: "1.4.6".to_owned(),
        ..Default::default()
    });
    stream.send(&request).await?;
    Ok(stream)
}

async fn raw_receive(stream: &mut FramedStream, expected: &[u8]) -> ResultType<()> {
    let mut all = Vec::new();
    while all.len() < expected.len() {
        let bytes = stream
            .next_timeout(5000)
            .await
            .ok_or_else(|| anyhow!("relay_data_timeout"))??;
        ensure!(!bytes.is_empty(), "relay_closed");
        all.extend_from_slice(&bytes);
        ensure!(all.len() <= expected.len(), "unexpected_relay_data");
    }
    ensure!(all == expected, "relay_data_mismatch");
    Ok(())
}

async fn relay_bytes(host: &str, id: &str, public: &str, session: &str) -> ResultType<()> {
    let mut left = connect(host).await?;
    let mut right = connect(host).await?;
    let mut request = RendezvousMessage::new();
    request.set_request_relay(RequestRelay {
        id: id.to_owned(),
        uuid: session.to_owned(),
        licence_key: public.to_owned(),
        ..Default::default()
    });
    left.send(&request).await?;
    right.send(&request).await?;
    left.set_raw();
    right.set_raw();
    left.send_raw(b"M2 relay forward probe".to_vec()).await?;
    raw_receive(&mut right, b"M2 relay forward probe").await?;
    right.send_raw(b"M2 relay reverse probe".to_vec()).await?;
    raw_receive(&mut left, b"M2 relay reverse probe").await?;
    Ok(())
}

async fn legacy_route(
    host: &str,
    id: &str,
    public: &str,
    pin: &sign::PublicKey,
    device: &sign::SecretKey,
    controlled: &mut FramedStream,
    cipher: &mut SessionCipher,
) -> ResultType<()> {
    let mut control = controller(host, id, public).await?;
    let outer = receive(controlled).await?;
    let notification = cipher.open(outer.private_tcp_frame())?;
    let punch = match notification.union {
        Some(rendezvous_message::Union::PunchHole(punch)) => punch,
        _ => return Err(anyhow!("missing_encrypted_punch_notification")),
    };
    ensure!(
        punch.nat_type.enum_value() == Ok(NatType::SYMMETRIC),
        "udp_punch_required"
    );
    validate_target(&punch.relay_server, public)?;
    let session = uuid::Uuid::new_v4().to_string();
    let mut callback = connect(host).await?;
    let mut response = RelayResponse {
        socket_addr: punch.socket_addr,
        uuid: session.clone(),
        relay_server: punch.relay_server.clone(),
        version: "1.4.6".to_owned(),
        ..Default::default()
    };
    response.set_id(id.to_owned());
    let mut message = RendezvousMessage::new();
    message.set_relay_response(response);
    callback.send(&message).await?;
    let reply = receive(&mut control).await?;
    ensure!(
        matches!(
            reply.union,
            Some(rendezvous_message::Union::RelayResponse(_))
        ),
        "missing_controller_relay_reply"
    );
    let reply = reply.relay_response();
    ensure!(reply.uuid == session, "wrong_relay_session");
    let signed =
        sign::verify(reply.pk(), pin).map_err(|_| anyhow!("invalid_signed_device_identity"))?;
    let identity = hbb_common::message_proto::IdPk::parse_from_bytes(&signed)?;
    ensure!(
        identity.id == id && identity.pk.as_ref() == device.public_key().as_ref(),
        "wrong_signed_device_identity"
    );
    relay_bytes(&punch.relay_server, id, public, &session).await
}

async fn udp_registration(host: &str) -> ResultType<()> {
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(host).await?;
    let (public, _) = sign::gen_keypair();
    let mut message = RendezvousMessage::new();
    message.set_register_pk(RegisterPk {
        id: format!("M2-PROBE-{}", uuid::Uuid::new_v4()),
        uuid: uuid::Uuid::new_v4().as_bytes().to_vec().into(),
        pk: public.as_ref().to_vec().into(),
        ..Default::default()
    });
    socket.send(&message.write_to_bytes()?).await?;
    let mut bytes = [0; 2048];
    let length = hbb_common::timeout(5000, socket.recv(&mut bytes)).await??;
    let reply = RendezvousMessage::parse_from_bytes(&bytes[..length])?;
    ensure!(
        matches!(reply.union, Some(rendezvous_message::Union::RegisterPkResponse(ref r))
        if r.result.enum_value() == Ok(register_pk_response::Result::OK)),
        "legacy_udp_registration_failed"
    );
    Ok(())
}

// Registers only ephemeral M2-PROBE identities in an explicitly isolated endpoint.
// It never initializes Config, writes local device keys, or authenticates a desktop.
#[tokio::main]
async fn main() -> ResultType<()> {
    let args: Vec<String> = std::env::args().collect();
    ensure!(
        (3..=4).contains(&args.len()) && (args.len() == 3 || args[3] == "--udp"),
        "Usage: private_tcp_smoke <isolated-hbbs:port> <test-public-key> [--udp]"
    );
    let (host, public) = (&args[1], &args[2]);
    validate_target(host, public)?;
    let pin = sign::PublicKey::from_slice(&base64::decode(public)?)
        .ok_or_else(|| anyhow!("invalid_pin"))?;
    let (_, device) = sign::gen_keypair();
    let id = format!("M2-PROBE-{}", uuid::Uuid::new_v4());
    let machine = uuid::Uuid::new_v4().as_bytes().to_vec();
    let check_udp = args.len() == 4;
    hbb_common::timeout(120_000, async {
        if check_udp {
            udp_registration(host).await?;
            println!(
                "{}",
                serde_json::json!({"server": host, "legacyUdpRegistration": true,
                "stage": "udp_accepted", "remoteDesktopAccepted": false})
            );
        }
        for generation in 0..3 {
            let mut stream = connect(host).await?;
            let state = ClientHandshake::new(id.clone(), machine.clone(), &device.public_key())?;
            let (mut cipher, _) = register_client(&mut stream, state, &pin, &device).await?;
            heartbeat(&mut stream, &mut cipher, &id).await?;
            if generation == 0 {
                for _ in 0..4 {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    heartbeat(&mut stream, &mut cipher, &id).await?;
                }
            }
            legacy_route(host, &id, public, &pin, &device, &mut stream, &mut cipher).await?;
            drop(stream);
            tokio::time::sleep(Duration::from_millis(300)).await;
            let mut query = controller(host, &id, public).await?;
            let reply = receive(&mut query).await?;
            ensure!(
                matches!(reply.union, Some(rendezvous_message::Union::PunchHoleResponse(ref r))
                if r.failure.enum_value() == Ok(punch_hole_response::Failure::OFFLINE)),
                "disconnected_peer_not_offline"
            );
        }
        println!(
            "{}",
            serde_json::json!({"server": host, "id": id,
            "authenticatedRegistrations": 3, "heartbeatBeyond30Seconds": true,
            "legacyControllerSignedRelay": true, "relayBytesBothDirections": true,
            "disconnectReportedOffline": true, "legacyUdpRegistration": check_udp,
            "remoteDesktopAccepted": false})
        );
        Ok::<(), hbb_common::anyhow::Error>(())
    })
    .await??;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_known_production_id_port_and_server_key() {
        assert!(validate_target("yxrrihie.sealoshzh.site:48944", "not-a-key").is_err());
        assert!(validate_target(
            "127.0.0.1:49999",
            "8JlBVwhzY1Vk1I1He0S7GwvBA1X++8KcziSU7lbxXis="
        )
        .is_err());
    }

    #[test]
    fn requires_an_explicit_test_port_and_a_32_byte_public_key() {
        assert!(validate_target("example.test", "not-a-key").is_err());
        assert!(validate_target("example.test:49999", "not-a-key").is_err());
        assert!(validate_target("example.test:49999", &base64::encode([1; 32])).is_ok());
    }
}
