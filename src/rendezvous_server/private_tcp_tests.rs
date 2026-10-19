use super::*;
use hbb_common::private_tcp::{ClientHandshake, SessionCipher};

fn peer() -> LockPeer {
    Arc::new(tokio::sync::RwLock::new(Peer {
        guid: vec![1; 16],
        uuid: b"machine".to_vec().into(),
        pk: vec![1; 32].into(),
        ..Default::default()
    }))
}

async fn activate(
    routes: &PrivateConnections,
    peer: LockPeer,
    generation: u8,
) -> mpsc::Receiver<RendezvousMessage> {
    routes
        .activate(
            "ZBX-TEST",
            peer,
            vec![generation; 32].into(),
            b"machine",
            &[1; 32],
            "127.0.0.1:1234".parse().unwrap(),
        )
        .await
        .unwrap()
}

fn message() -> RendezvousMessage {
    let mut message = RendezvousMessage::new();
    message.set_request_relay(RequestRelay::new());
    message
}

#[tokio::test]
async fn private_tcp_old_cleanup_cannot_evict_a_replacement() {
    let routes = PrivateConnections::default();
    let peer = peer();
    let mut first = activate(&routes, peer.clone(), 1).await;
    let mut second = activate(&routes, peer.clone(), 2).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), first.recv())
            .await
            .unwrap()
            .is_none()
    );
    assert!(!routes.remove("ZBX-TEST", &[1; 32]).await);
    assert!(!routes.heartbeat("ZBX-TEST", &[1; 32]).await);
    assert!(routes.heartbeat("ZBX-TEST", &[2; 32]).await);
    assert!(routes.notify("ZBX-TEST", message()).await.unwrap());
    assert_eq!(second.recv().await.unwrap(), message());
}

#[tokio::test]
async fn private_tcp_cleanup_preserves_a_newer_udp_registration() {
    let routes = PrivateConnections::default();
    let peer = peer();
    let _receiver = activate(&routes, peer.clone(), 1).await;
    let now = Instant::now();
    {
        let mut peer = peer.write().await;
        peer.private_tcp_generation = None;
        peer.socket_addr = "127.0.0.1:5678".parse().unwrap();
        peer.last_reg_time = now;
    }
    assert!(!routes.heartbeat("ZBX-TEST", &[1; 32]).await);
    assert!(!routes.notify("ZBX-TEST", message()).await.unwrap());
    assert!(routes.remove("ZBX-TEST", &[1; 32]).await);
    let peer = peer.read().await;
    assert_eq!(peer.last_reg_time, now);
    assert_eq!(peer.socket_addr.port(), 5678);
}

#[tokio::test]
async fn private_tcp_failed_activation_preserves_existing_route() {
    let routes = PrivateConnections::default();
    let peer = peer();
    let mut original = activate(&routes, peer.clone(), 1).await;
    assert!(routes
        .activate(
            "ZBX-TEST",
            peer.clone(),
            vec![2; 32].into(),
            b"other",
            &[2; 32],
            "127.0.0.1:9999".parse().unwrap()
        )
        .await
        .is_err());
    assert!(routes.notify("ZBX-TEST", message()).await.unwrap());
    assert_eq!(original.recv().await.unwrap(), message());
}

#[tokio::test]
async fn private_tcp_notify_queue_is_bounded_and_failure_expires_its_generation() {
    let routes = PrivateConnections::default();
    let peer = peer();
    let _receiver = activate(&routes, peer.clone(), 1).await;
    for _ in 0..16 {
        assert!(routes.notify("ZBX-TEST", message()).await.unwrap());
    }
    assert!(routes.notify("ZBX-TEST", message()).await.is_err());
    assert!(peer.read().await.private_tcp_generation.is_none());
    assert!(peer.read().await.last_reg_time.elapsed().as_secs() >= 30);
}

async fn server_fixture() -> (RendezvousServer, sign::PublicKey, Receiver) {
    sodiumoxide::init().unwrap();
    let (public, secret) = sign::gen_keypair();
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../.tmp/m2-peer-tests")
        .join(format!("{}.sqlite3", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let pm = PeerMap::from_database(
        crate::database::Database::new(path.to_str().unwrap())
            .await
            .unwrap(),
    );
    let (tx, receiver) = mpsc::unbounded_channel();
    let server = RendezvousServer {
        private_connections: Default::default(),
        tcp_punch: Default::default(),
        pm,
        tx,
        relay_servers: Arc::new(vec!["127.0.0.1:21117".to_owned()]),
        relay_servers0: Default::default(),
        rendezvous_servers: Default::default(),
        inner: Arc::new(Inner {
            serial: 0,
            version: String::new(),
            software_url: String::new(),
            mask: None,
            local_ip: String::new(),
            sk: Some(secret),
        }),
    };
    (server, public, receiver)
}

async fn receive(stream: &mut FramedStream) -> RendezvousMessage {
    RendezvousMessage::parse_from_bytes(
        &stream
            .next_timeout(1000)
            .await
            .expect("response deadline")
            .expect("socket response"),
    )
    .unwrap()
}

async fn connect(addr: SocketAddr) -> FramedStream {
    let stream = TcpStream::connect(addr).await.unwrap();
    let local = stream.local_addr().unwrap();
    let mut stream = FramedStream::from(stream, local);
    stream
        .codec_mut()
        .set_max_packet_length(hbb_common::private_tcp::MAX_PLAINTEXT + 128);
    stream.set_send_timeout(1000);
    stream
}

async fn authenticate(
    stream: &mut FramedStream,
    public: &sign::PublicKey,
    device: &sign::SecretKey,
) -> SessionCipher {
    let client =
        ClientHandshake::new("ZBX-TEST".into(), b"machine".to_vec(), &device.public_key()).unwrap();
    let (cipher, keep_alive) = hbb_common::private_tcp::register_client(stream, client, public, device).await.unwrap();
    assert!(keep_alive <= Duration::from_secs(10));
    cipher
}

async fn send_encrypted(
    stream: &mut FramedStream,
    cipher: &mut SessionCipher,
    message: &RendezvousMessage,
) {
    let mut envelope = RendezvousMessage::new();
    envelope.set_private_tcp_frame(cipher.seal(message).unwrap());
    stream.send(&envelope).await.unwrap();
}

async fn listeners(
    server: RendezvousServer,
    public: sign::PublicKey,
    count: usize,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut jobs = Vec::new();
        for _ in 0..count {
            let (stream, addr) = listener.accept().await.unwrap();
            let mut server = server.clone();
            let key = base64::encode(public.as_ref());
            jobs.push(tokio::spawn(async move {
                server
                    .handle_listener_inner(stream, addr, &key, false)
                    .await
            }));
        }
        for job in jobs {
            job.await.unwrap().unwrap();
        }
    });
    (addr, task)
}

#[tokio::test]
async fn private_tcp_real_registration_heartbeat_and_disconnect_are_truthful() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (server, public, _receiver) = server_fixture().await;
        let observed = server.clone();
        let (addr, task) = listeners(server, public, 1).await;
        let (_, device) = sign::gen_keypair();
        let mut stream = connect(addr).await;
        let mut cipher = authenticate(&mut stream, &public, &device).await;
        let peer = observed.pm.get_in_memory("ZBX-TEST").await.unwrap();
        assert!(peer.read().await.private_tcp_generation.is_some());
        let mut message = RendezvousMessage::new();
        message.set_register_peer(RegisterPeer {
            id: "ZBX-TEST".to_owned(),
            ..Default::default()
        });
        send_encrypted(&mut stream, &mut cipher, &message).await;
        let reply = receive(&mut stream).await;
        assert!(matches!(
            cipher.open(reply.private_tcp_frame()).unwrap().union,
            Some(rendezvous_message::Union::RegisterPeerResponse(_))
        ));
        drop(stream);
        task.await.unwrap();
        assert!(peer.read().await.private_tcp_generation.is_none());
        assert!(peer.read().await.last_reg_time.elapsed().as_secs() >= 30);
        assert_eq!(
            observed
                .pm
                .db
                .get_peer("ZBX-TEST")
                .await
                .unwrap()
                .unwrap()
                .pk,
            device.public_key().as_ref()
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn private_tcp_legacy_controller_gets_relay_signalling_and_signed_device_key() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (server, public, _receiver) = server_fixture().await;
        let (addr, task) = listeners(server, public, 3).await;
        let (_, device) = sign::gen_keypair();
        let mut controlled = connect(addr).await;
        let mut cipher = authenticate(&mut controlled, &public, &device).await;
        let mut controller = connect(addr).await;
        let mut request = RendezvousMessage::new();
        request.set_punch_hole_request(PunchHoleRequest {
            id: "ZBX-TEST".to_owned(),
            licence_key: base64::encode(public.as_ref()),
            version: "1.4.6".to_owned(),
            ..Default::default()
        });
        controller.send(&request).await.unwrap();
        let notification = receive(&mut controlled).await;
        let notification = cipher.open(notification.private_tcp_frame()).unwrap();
        let punch = notification.punch_hole();
        assert_eq!(punch.nat_type.enum_value().unwrap(), NatType::SYMMETRIC);
        assert_eq!(punch.relay_server, "127.0.0.1:21117");
        let mut reply = connect(addr).await;
        let mut response = RelayResponse {
            socket_addr: punch.socket_addr.clone(),
            uuid: "test-session".to_owned(),
            relay_server: punch.relay_server.clone(),
            version: "1.4.6".to_owned(),
            ..Default::default()
        };
        response.set_id("ZBX-TEST".to_owned());
        request.set_relay_response(response);
        reply.send(&request).await.unwrap();
        let response = receive(&mut controller).await;
        assert_eq!(response.relay_response().uuid, "test-session");
        let identity = sign::verify(response.relay_response().pk(), &public).unwrap();
        let identity = hbb_common::message_proto::IdPk::parse_from_bytes(&identity).unwrap();
        assert_eq!(identity.id, "ZBX-TEST");
        assert_eq!(identity.pk.as_ref(), device.public_key().as_ref());
        drop((reply, controller, controlled));
        task.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn private_tcp_udp_heartbeat_takes_ownership_without_stale_cleanup() {
    let (mut server, _, _receiver) = server_fixture().await;
    let peer = server
        .pm
        .admit_private(
            "ZBX-TEST",
            b"machine",
            &[1; 32],
            "127.0.0.1:1234".parse().unwrap(),
        )
        .await
        .unwrap();
    let _outgoing = activate(&server.private_connections, peer.clone(), 1).await;
    peer.write().await.last_reg_time = get_expired_time();
    let mut socket = FramedSocket::new("127.0.0.1:0").await.unwrap();
    server
        .update_addr(
            "ZBX-TEST".to_owned(),
            "127.0.0.1:5678".parse().unwrap(),
            &mut socket,
        )
        .await
        .unwrap();
    assert!(peer.read().await.private_tcp_generation.is_none());
    let udp_time = peer.read().await.last_reg_time;
    server
        .private_connections
        .remove("ZBX-TEST", &[1; 32])
        .await;
    assert_eq!(peer.read().await.last_reg_time, udp_time);
}

#[tokio::test]
async fn private_tcp_udp_public_key_registration_revokes_private_generation() {
    let (mut server, _, _receiver) = server_fixture().await;
    let peer = server
        .pm
        .admit_private(
            "ZBX-TEST",
            b"machine",
            &[1; 32],
            "127.0.0.1:1234".parse().unwrap(),
        )
        .await
        .unwrap();
    let _outgoing = activate(&server.private_connections, peer.clone(), 1).await;
    peer.write().await.last_reg_time = get_expired_time();
    assert_eq!(
        server
            .pm
            .update_pk(
                "ZBX-TEST".to_owned(),
                peer.clone(),
                "127.0.0.1:5678".parse().unwrap(),
                b"machine".to_vec().into(),
                vec![1; 32].into(),
                "127.0.0.1".to_owned()
            )
            .await,
        register_pk_response::Result::OK
    );
    assert!(peer.read().await.private_tcp_generation.is_none());
}

#[tokio::test]
async fn private_tcp_fresh_authenticated_route_cannot_be_displaced_by_udp() {
    let (mut server, _, _receiver) = server_fixture().await;
    let peer = server
        .pm
        .admit_private(
            "ZBX-TEST",
            b"machine",
            &[1; 32],
            "127.0.0.1:1234".parse().unwrap(),
        )
        .await
        .unwrap();
    let _outgoing = activate(&server.private_connections, peer.clone(), 1).await;
    let mut socket = FramedSocket::new("127.0.0.1:0").await.unwrap();
    server
        .update_addr(
            "ZBX-TEST".to_owned(),
            "127.0.0.1:5678".parse().unwrap(),
            &mut socket,
        )
        .await
        .unwrap();
    assert!(peer.read().await.private_tcp_generation.is_some());
    assert_eq!(peer.read().await.socket_addr.port(), 1234);
    assert_eq!(
        server
            .pm
            .update_pk(
                "ZBX-TEST".to_owned(),
                peer.clone(),
                "127.0.0.1:5678".parse().unwrap(),
                b"machine".to_vec().into(),
                vec![1; 32].into(),
                "127.0.0.1".to_owned()
            )
            .await,
        TOO_FREQUENT
    );
    assert!(peer.read().await.private_tcp_generation.is_some());
}

#[tokio::test]
async fn private_tcp_forged_proof_never_creates_a_durable_record() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (mut server, _, _receiver) = server_fixture().await;
        let observed = server.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (stream, addr) = listener.accept().await.unwrap();
            server.handle_listener_inner(stream, addr, "", false).await
        });
        let mut stream = connect(addr).await;
        let (_, device) = sign::gen_keypair();
        let client =
            ClientHandshake::new("ZBX-TEST".into(), b"machine".to_vec(), &device.public_key())
                .unwrap();
        let mut message = RendezvousMessage::new();
        message.set_private_tcp_hello(client.hello().clone());
        stream.send(&message).await.unwrap();
        receive(&mut stream).await;
        message.set_private_tcp_proof(PrivateTcpProof {
            version: 1,
            signature: vec![0; 64].into(),
            ..Default::default()
        });
        stream.send(&message).await.unwrap();
        assert!(task.await.unwrap().is_err());
        assert!(observed.pm.db.get_peer("ZBX-TEST").await.unwrap().is_none());
        assert_eq!(
            observed.private_connections.pending.available_permits(),
            128
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn private_tcp_direct_relay_request_uses_authenticated_route() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (server, public, _receiver) = server_fixture().await;
        let (addr, task) = listeners(server, public, 2).await;
        let (_, device) = sign::gen_keypair();
        let mut controlled = connect(addr).await;
        let mut cipher = authenticate(&mut controlled, &public, &device).await;
        let mut controller = connect(addr).await;
        let mut message = RendezvousMessage::new();
        message.set_request_relay(RequestRelay {
            id: "ZBX-TEST".to_owned(),
            uuid: "test-relay".to_owned(),
            licence_key: base64::encode(public.as_ref()),
            relay_server: "127.0.0.1:21117".to_owned(),
            ..Default::default()
        });
        controller.send(&message).await.unwrap();
        let incoming = receive(&mut controlled).await;
        let incoming = cipher.open(incoming.private_tcp_frame()).unwrap();
        assert_eq!(incoming.request_relay().uuid, "test-relay");
        assert!(!incoming.request_relay().socket_addr.is_empty());
        drop((controlled, controller));
        task.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn private_tcp_real_reconnect_keeps_new_generation_alive() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (server, public, _receiver) = server_fixture().await;
        let observed = server.clone();
        let (addr, task) = listeners(server, public, 2).await;
        let (_, device) = sign::gen_keypair();
        let mut first = connect(addr).await;
        let _first_cipher = authenticate(&mut first, &public, &device).await;
        let peer = observed.pm.get_in_memory("ZBX-TEST").await.unwrap();
        let first_generation = peer.read().await.private_tcp_generation.clone().unwrap();
        let mut second = connect(addr).await;
        let mut cipher = authenticate(&mut second, &public, &device).await;
        assert_ne!(
            peer.read().await.private_tcp_generation.as_ref().unwrap(),
            &first_generation
        );
        drop(first);
        let mut message = RendezvousMessage::new();
        message.set_register_peer(RegisterPeer {
            id: "ZBX-TEST".to_owned(),
            ..Default::default()
        });
        send_encrypted(&mut second, &mut cipher, &message).await;
        let reply = receive(&mut second).await;
        assert!(matches!(
            cipher.open(reply.private_tcp_frame()).unwrap().union,
            Some(rendezvous_message::Union::RegisterPeerResponse(_))
        ));
        drop(second);
        task.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn private_tcp_authenticated_wrong_identity_does_not_evict_current_connection() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (server, public, _receiver) = server_fixture().await;
        let observed = server.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut jobs = Vec::new();
            for _ in 0..2 {
                let (stream, addr) = listener.accept().await.unwrap();
                let mut server = server.clone();
                jobs.push(tokio::spawn(async move {
                    server.handle_listener_inner(stream, addr, "", false).await
                }));
            }
            let mut rejected = 0;
            for job in jobs {
                if job.await.unwrap().is_err() {
                    rejected += 1;
                }
            }
            assert_eq!(rejected, 1);
        });
        let (_, device) = sign::gen_keypair();
        let mut original = connect(addr).await;
        let mut original_cipher = authenticate(&mut original, &public, &device).await;
        let peer = observed.pm.get_in_memory("ZBX-TEST").await.unwrap();
        let generation = peer.read().await.private_tcp_generation.clone();
        let (_, other) = sign::gen_keypair();
        let mut changed = connect(addr).await;
        let client =
            ClientHandshake::new("ZBX-TEST".into(), b"machine".to_vec(), &other.public_key())
                .unwrap();
        let mut message = RendezvousMessage::new();
        message.set_private_tcp_hello(client.hello().clone());
        changed.send(&message).await.unwrap();
        let challenge = receive(&mut changed).await;
        let (proof, mut cipher) = client
            .respond(challenge.private_tcp_challenge(), &public, &other)
            .unwrap();
        message.set_private_tcp_proof(proof);
        changed.send(&message).await.unwrap();
        let reply = receive(&mut changed).await;
        let rejection = cipher.open(reply.private_tcp_frame()).unwrap();
        assert_eq!(
            rejection
                .register_pk_response()
                .result
                .enum_value()
                .unwrap(),
            UUID_MISMATCH
        );
        assert_eq!(peer.read().await.private_tcp_generation, generation);
        message.set_register_peer(RegisterPeer {
            id: "ZBX-TEST".to_owned(),
            ..Default::default()
        });
        send_encrypted(&mut original, &mut original_cipher, &message).await;
        let reply = receive(&mut original).await;
        assert!(original_cipher.open(reply.private_tcp_frame()).is_ok());
        drop((changed, original));
        task.await.unwrap();
    })
    .await
    .unwrap();
}
