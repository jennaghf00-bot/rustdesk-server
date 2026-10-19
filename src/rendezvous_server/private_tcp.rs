use super::*;
use hbb_common::private_tcp::{ServerHandshake, SessionCipher, MAX_PLAINTEXT};
use std::sync::Mutex as StdMutex;

#[derive(Clone)]
struct PrivateRoute {
    generation: Bytes,
    uuid: Bytes,
    public_key: Bytes,
    peer: LockPeer,
    sender: mpsc::Sender<RendezvousMessage>,
}

#[derive(Clone)]
pub(super) struct PrivateConnections {
    routes: Arc<StdMutex<HashMap<String, PrivateRoute>>>,
    pending: Arc<tokio::sync::Semaphore>,
}

impl Default for PrivateConnections {
    fn default() -> Self {
        Self {
            routes: Default::default(),
            pending: Arc::new(tokio::sync::Semaphore::new(128)),
        }
    }
}

impl PrivateConnections {
    fn route(&self, id: &str) -> Option<PrivateRoute> {
        self.routes.lock().unwrap().get(id).cloned()
    }

    fn owns(&self, id: &str, route: &PrivateRoute, peer: &Peer) -> bool {
        peer.private_tcp_generation.as_ref() == Some(&route.generation)
            && peer.uuid == route.uuid
            && peer.pk == route.public_key
            && self
                .routes
                .lock()
                .unwrap()
                .get(id)
                .map(|current| current.generation == route.generation)
                .unwrap_or(false)
    }

    pub(super) async fn activate(
        &self,
        id: &str,
        peer: LockPeer,
        generation: Bytes,
        uuid: &[u8],
        pk: &[u8],
        addr: SocketAddr,
    ) -> ResultType<mpsc::Receiver<RendezvousMessage>> {
        hbb_common::anyhow::ensure!(generation.len() == 32, "private_tcp_invalid_generation");
        let (sender, receiver) = mpsc::channel(16);
        {
            let mut current = peer.write().await;
            hbb_common::anyhow::ensure!(
                !current.guid.is_empty()
                    && current.uuid.as_ref() == uuid
                    && current.pk.as_ref() == pk,
                "private_tcp_identity_mismatch"
            );
            // Lock ordering: acquire the peer first, then the short synchronous route lock.
            // No mutex/peer guard is held across an await or a socket operation.
            let mut routes = self.routes.lock().unwrap();
            hbb_common::anyhow::ensure!(
                routes
                    .get(id)
                    .map(|old| old.generation != generation)
                    .unwrap_or(true),
                "private_tcp_duplicate_generation"
            );
            current.private_tcp_generation = Some(generation.clone());
            current.socket_addr = addr;
            current.last_reg_time = Instant::now();
            routes.insert(
                id.to_owned(),
                PrivateRoute {
                    generation,
                    uuid: current.uuid.clone(),
                    public_key: current.pk.clone(),
                    peer: peer.clone(),
                    sender,
                },
            );
        }
        Ok(receiver)
    }

    pub(super) async fn heartbeat(&self, id: &str, generation: &[u8]) -> bool {
        let route = match self.route(id) {
            Some(route) if route.generation.as_ref() == generation => route,
            _ => return false,
        };
        let mut peer = route.peer.write().await;
        if !self.owns(id, &route, &peer)
            || peer.last_reg_time.elapsed().as_millis() >= REG_TIMEOUT as u128
        {
            return false;
        }
        peer.last_reg_time = Instant::now();
        true
    }

    async fn current(&self, id: &str, generation: &[u8]) -> bool {
        let route = match self.route(id) {
            Some(route) if route.generation.as_ref() == generation => route,
            _ => return false,
        };
        let peer = route.peer.read().await;
        self.owns(id, &route, &peer)
            && peer.last_reg_time.elapsed().as_millis() < REG_TIMEOUT as u128
    }

    pub(super) async fn notify(&self, id: &str, message: RendezvousMessage) -> ResultType<bool> {
        let route = match self.route(id) {
            Some(route) => route,
            None => return Ok(false),
        };
        let queued = {
            let peer = route.peer.read().await;
            if !self.owns(id, &route, &peer)
                || peer.last_reg_time.elapsed().as_millis() >= REG_TIMEOUT as u128
            {
                return Ok(false);
            }
            route.sender.try_send(message).is_ok()
        };
        if !queued {
            self.remove(id, &route.generation).await;
            bail!("private_tcp_route_unavailable");
        }
        Ok(true)
    }

    pub(super) async fn remove(&self, id: &str, generation: &[u8]) -> bool {
        let route = match self.route(id) {
            Some(route) if route.generation.as_ref() == generation => route,
            _ => return false,
        };
        let mut peer = route.peer.write().await;
        let mut routes = self.routes.lock().unwrap();
        if routes
            .get(id)
            .map(|current| current.generation.as_ref() != generation)
            .unwrap_or(true)
        {
            return false;
        }
        routes.remove(id);
        if peer
            .private_tcp_generation
            .as_ref()
            .map(|value| value.as_ref())
            == Some(generation)
        {
            peer.private_tcp_generation = None;
            peer.last_reg_time = get_expired_time();
        }
        true
    }
}

type PrivateRead = hbb_common::futures_util::stream::SplitStream<Framed<TcpStream, BytesCodec>>;

async fn send_plain(sink: &mut TcpStreamSink, message: &RendezvousMessage) -> ResultType<()> {
    timeout(3000, sink.send(Bytes::from(message.write_to_bytes()?))).await??;
    Ok(())
}

async fn send_private(
    sink: &mut TcpStreamSink,
    cipher: &mut SessionCipher,
    message: &RendezvousMessage,
) -> ResultType<()> {
    let mut envelope = RendezvousMessage::new();
    envelope.set_private_tcp_frame(cipher.seal(message)?);
    send_plain(sink, &envelope).await
}

pub(super) enum PrivateDispatch {
    Legacy,
    Queued,
    Reply(RendezvousMessage),
}

impl RendezvousServer {
    pub(super) async fn private_session(
        &mut self,
        hello: PrivateTcpHello,
        sink: &mut TcpStreamSink,
        stream: &mut PrivateRead,
        addr: SocketAddr,
    ) -> ResultType<()> {
        let permit = self
            .private_connections
            .pending
            .clone()
            .try_acquire_owned()
            .map_err(|_| hbb_common::anyhow::anyhow!("private_tcp_handshake_busy"))?;
        let server_key = self
            .inner
            .sk
            .as_ref()
            .ok_or_else(|| hbb_common::anyhow::anyhow!("private_tcp_server_key_unavailable"))?;
        let pending = ServerHandshake::new(&hello, server_key, Instant::now())?;
        let generation = pending.challenge().nonce.clone();
        let mut message = RendezvousMessage::new();
        message.set_private_tcp_challenge(pending.challenge().clone());
        send_plain(sink, &message).await?;
        let bytes = timeout(10_000, stream.next())
            .await?
            .ok_or_else(|| hbb_common::anyhow::anyhow!("private_tcp_handshake_closed"))??;
        hbb_common::anyhow::ensure!(bytes.len() <= 4096, "private_tcp_handshake_too_large");
        let proof = RendezvousMessage::parse_from_bytes(&bytes)?;
        let proof = match proof.union {
            Some(rendezvous_message::Union::PrivateTcpProof(proof)) => proof,
            _ => bail!("private_tcp_invalid_proof"),
        };
        let mut cipher = pending.finish(&proof, Instant::now())?;
        let peer = match self
            .pm
            .admit_private(&hello.id, &hello.uuid, &hello.public_key, addr)
            .await
        {
            Ok(peer) => peer,
            Err(error) => {
                let result = if error.to_string() == "private_tcp_identity_mismatch" {
                    UUID_MISMATCH
                } else {
                    register_pk_response::Result::SERVER_ERROR
                };
                message.set_register_pk_response(RegisterPkResponse {
                    result: result.into(),
                    ..Default::default()
                });
                send_private(sink, &mut cipher, &message).await?;
                return Err(error);
            }
        };
        let mut notifications = self
            .private_connections
            .activate(
                &hello.id,
                peer,
                generation.clone(),
                &hello.uuid,
                &hello.public_key,
                addr,
            )
            .await?;
        message.set_register_pk_response(RegisterPkResponse {
            result: register_pk_response::Result::OK.into(),
            keep_alive: 10,
            ..Default::default()
        });
        let acknowledged = send_private(sink, &mut cipher, &message).await;
        drop(permit);
        let result = match acknowledged {
            Ok(()) => {
                self.private_session_loop(
                    &hello.id,
                    &generation,
                    sink,
                    stream,
                    &mut cipher,
                    &mut notifications,
                )
                .await
            }
            Err(error) => Err(error),
        };
        self.private_connections
            .remove(&hello.id, &generation)
            .await;
        result
    }

    async fn private_session_loop(
        &self,
        id: &str,
        generation: &[u8],
        sink: &mut TcpStreamSink,
        stream: &mut PrivateRead,
        cipher: &mut SessionCipher,
        notifications: &mut mpsc::Receiver<RendezvousMessage>,
    ) -> ResultType<()> {
        let mut last_heartbeat = Instant::now();
        loop {
            tokio::select! {
                _ = tokio::time::sleep_until((last_heartbeat + Duration::from_millis(REG_TIMEOUT as u64)).into()) => {
                    bail!("private_tcp_heartbeat_timeout");
                }
                incoming = stream.next() => {
                    let bytes = match incoming { Some(bytes) => bytes?, None => return Ok(()) };
                    hbb_common::anyhow::ensure!(bytes.len() <= MAX_PLAINTEXT + 128, "private_tcp_frame_too_large");
                    let outer = RendezvousMessage::parse_from_bytes(&bytes)?;
                    let frame = match outer.union {
                        Some(rendezvous_message::Union::PrivateTcpFrame(frame)) => frame,
                        _ => bail!("private_tcp_unencrypted_message"),
                    };
                    let message = cipher.open(&frame)?;
                    match message.union {
                        Some(rendezvous_message::Union::RegisterPeer(peer)) if peer.id == id => {
                            hbb_common::anyhow::ensure!(self.private_connections.heartbeat(id, generation).await,
                                "private_tcp_stale_generation");
                            last_heartbeat = Instant::now();
                            let mut reply = RendezvousMessage::new();
                            reply.set_register_peer_response(RegisterPeerResponse::new());
                            send_private(sink, cipher, &reply).await?;
                        }
                        _ => bail!("private_tcp_unexpected_message"),
                    }
                }
                notification = notifications.recv() => {
                    let message = match notification { Some(message) => message, None => return Ok(()) };
                    hbb_common::anyhow::ensure!(self.private_connections.current(id, generation).await,
                        "private_tcp_stale_generation");
                    send_private(sink, cipher, &message).await?;
                }
            }
        }
    }

    pub(super) async fn private_punch_dispatch(
        &self,
        addr: SocketAddr,
        request: &PunchHoleRequest,
        key: &str,
    ) -> ResultType<PrivateDispatch> {
        if !key.is_empty() && request.licence_key != key {
            return Ok(PrivateDispatch::Legacy);
        }
        let peer = match self.pm.get_in_memory(&request.id).await {
            Some(peer) => peer,
            None => return Ok(PrivateDispatch::Legacy),
        };
        let (private, fresh, peer_addr) = {
            let peer = peer.read().await;
            (
                peer.private_tcp_generation.is_some(),
                peer.last_reg_time.elapsed().as_millis() < REG_TIMEOUT as u128,
                peer.socket_addr,
            )
        };
        if !private {
            return Ok(PrivateDispatch::Legacy);
        }
        if fresh {
            let mut message = RendezvousMessage::new();
            message.set_punch_hole(PunchHole {
                socket_addr: AddrMangle::encode(addr).into(),
                relay_server: self.get_relay_server(addr.ip(), peer_addr.ip()),
                nat_type: NatType::SYMMETRIC.into(),
                ..Default::default()
            });
            match self.private_connections.notify(&request.id, message).await {
                Ok(true) => return Ok(PrivateDispatch::Queued),
                Err(error) => log::debug!("private punch dispatch failed: {error}"),
                Ok(false) => {}
            }
        }
        let mut reply = RendezvousMessage::new();
        reply.set_punch_hole_response(PunchHoleResponse {
            failure: punch_hole_response::Failure::OFFLINE.into(),
            ..Default::default()
        });
        Ok(PrivateDispatch::Reply(reply))
    }
}

#[cfg(test)]
#[path = "private_tcp_tests.rs"]
mod tests;
