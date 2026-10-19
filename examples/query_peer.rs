use hbb_common::{protobuf::Message, rendezvous_proto::*, tcp::FramedStream, tokio, ResultType};

fn describe_response(message: &RendezvousMessage) -> serde_json::Value {
    match &message.union {
        Some(rendezvous_message::Union::PunchHoleResponse(response)) => serde_json::json!({
            "type": "punch_hole_response",
            "failure": if response.socket_addr.is_empty() && response.pk.is_empty() {
                Some(response.failure.enum_value().map(|value| format!("{value:?}"))
                    .unwrap_or_else(|_| "UNKNOWN".to_owned()))
            } else { None },
            "socketAddrPresent": !response.socket_addr.is_empty(),
            "publicKeyPresent": !response.pk.is_empty(),
        }),
        Some(rendezvous_message::Union::RelayResponse(_)) => serde_json::json!({
            "type": "relay_response",
        }),
        _ => serde_json::json!({"type": "unexpected"}),
    }
}

// Sends normal connection signalling only: no registration, identity write or remote authentication.
#[tokio::main]
async fn main() -> ResultType<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        hbb_common::bail!("Usage: query_peer <hbbs-host:port> <remote-id> <server-public-key>");
    }
    let stream = hbb_common::timeout(5000, tokio::net::TcpStream::connect(&args[1])).await??;
    let local_addr = stream.local_addr()?;
    let mut stream = FramedStream::from(stream, local_addr);
    stream.set_send_timeout(5000);
    let mut request = RendezvousMessage::new();
    request.set_punch_hole_request(PunchHoleRequest {
        id: args[2].clone(),
        licence_key: args[3].clone(),
        version: "1.4.6".to_owned(),
        ..Default::default()
    });
    stream.send(&request).await?;
    let response = match stream.next_timeout(8000).await {
        Some(Ok(bytes)) => describe_response(&RendezvousMessage::parse_from_bytes(&bytes)?),
        Some(Err(error)) => return Err(error.into()),
        None => serde_json::json!({"type": "no_response"}),
    };
    println!(
        "{}",
        serde_json::json!({"server": args[1], "id": args[2], "response": response})
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinguishes_missing_id_from_offline_without_registering() {
        for (failure, expected) in [
            (punch_hole_response::Failure::ID_NOT_EXIST, "ID_NOT_EXIST"),
            (punch_hole_response::Failure::OFFLINE, "OFFLINE"),
            (
                punch_hole_response::Failure::LICENSE_MISMATCH,
                "LICENSE_MISMATCH",
            ),
        ] {
            let mut message = RendezvousMessage::new();
            message.set_punch_hole_response(PunchHoleResponse {
                failure: failure.into(),
                ..Default::default()
            });
            assert_eq!(describe_response(&message)["failure"], expected);
        }
    }

    #[test]
    fn unexpected_response_is_not_claimed_as_offline_or_missing() {
        assert_eq!(
            describe_response(&RendezvousMessage::new())["type"],
            "unexpected"
        );
    }

    #[test]
    fn connection_response_with_default_enum_is_not_reported_as_missing_id() {
        let mut message = RendezvousMessage::new();
        message.set_punch_hole_response(PunchHoleResponse {
            socket_addr: vec![1, 2, 3, 4].into(),
            ..Default::default()
        });
        assert!(describe_response(&message)["failure"].is_null());
    }
}
