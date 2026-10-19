use super::*;
use hbb_common::tokio;

async fn fixture() -> (PeerMap, std::path::PathBuf) {
    let root =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.tmp/m2-peer-tests");
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join(format!("{}.sqlite3", uuid::Uuid::new_v4()));
    let db = database::Database::new(path.to_str().unwrap())
        .await
        .unwrap();
    (PeerMap::from_database(db), path)
}

#[tokio::test]
async fn private_tcp_admission_persists_but_does_not_mark_online() {
    let (pm, _) = fixture().await;
    let peer = pm
        .admit_private(
            "ZBX-TEST",
            b"machine",
            &[1; 32],
            "127.0.0.1:1234".parse().unwrap(),
        )
        .await
        .unwrap();
    let saved = pm.db.get_peer("ZBX-TEST").await.unwrap().unwrap();
    assert_eq!(saved.uuid, b"machine");
    assert_eq!(saved.pk, [1; 32]);
    assert_eq!(peer.read().await.guid, saved.guid);
    assert!(peer.read().await.last_reg_time.elapsed().as_secs() >= 30);
}

#[tokio::test]
async fn private_tcp_reconnect_accepts_ip_change_without_rotating_keys() {
    let (pm, _) = fixture().await;
    pm.admit_private(
        "ZBX-TEST",
        b"machine",
        &[1; 32],
        "192.0.2.1:1234".parse().unwrap(),
    )
    .await
    .unwrap();
    let first = pm.db.get_peer("ZBX-TEST").await.unwrap().unwrap();
    pm.admit_private(
        "ZBX-TEST",
        b"machine",
        &[1; 32],
        "192.0.2.2:2345".parse().unwrap(),
    )
    .await
    .unwrap();
    let second = pm.db.get_peer("ZBX-TEST").await.unwrap().unwrap();
    assert_eq!(
        (first.guid, first.uuid, first.pk),
        (second.guid, second.uuid, second.pk)
    );
    assert_eq!(
        serde_json::from_str::<PeerInfo>(&second.info).unwrap().ip,
        "192.0.2.2"
    );
}

#[tokio::test]
async fn private_tcp_ownership_mismatch_leaves_saved_identity_unchanged() {
    let (pm, _) = fixture().await;
    pm.admit_private(
        "ZBX-TEST",
        b"machine",
        &[1; 32],
        "192.0.2.1:1234".parse().unwrap(),
    )
    .await
    .unwrap();
    let before = pm.db.get_peer("ZBX-TEST").await.unwrap().unwrap();
    for (uuid, pk) in [
        (b"other".as_slice(), [1; 32]),
        (b"machine".as_slice(), [2; 32]),
    ] {
        assert!(pm
            .admit_private("ZBX-TEST", uuid, &pk, "192.0.2.1:9999".parse().unwrap())
            .await
            .is_err());
    }
    let after = pm.db.get_peer("ZBX-TEST").await.unwrap().unwrap();
    assert_eq!(
        (before.guid, before.uuid, before.pk, before.info),
        (after.guid, after.uuid, after.pk, after.info)
    );
}

#[tokio::test]
async fn private_tcp_failed_insert_does_not_publish_an_identity() {
    use sqlx::{Connection, Executor};
    let (pm, path) = fixture().await;
    let mut connection = sqlx::SqliteConnection::connect(path.to_str().unwrap())
        .await
        .unwrap();
    connection.execute("DROP TABLE peer").await.unwrap();
    assert!(pm
        .admit_private(
            "ZBX-TEST",
            b"machine",
            &[1; 32],
            "127.0.0.1:1234".parse().unwrap()
        )
        .await
        .is_err());
    let peer = pm.get_in_memory("ZBX-TEST").await.unwrap();
    let peer = peer.read().await;
    assert!(peer.guid.is_empty());
    assert!(peer.pk.is_empty());
    assert!(peer.last_reg_time.elapsed().as_secs() >= 30);
}

#[tokio::test]
async fn private_tcp_competing_identities_cannot_overwrite_each_other() {
    let (pm, _) = fixture().await;
    let a = pm.clone();
    let b = pm.clone();
    let (first, second) = tokio::join!(
        a.admit_private(
            "ZBX-TEST",
            b"machine-a",
            &[1; 32],
            "127.0.0.1:1234".parse().unwrap()
        ),
        b.admit_private(
            "ZBX-TEST",
            b"machine-b",
            &[2; 32],
            "127.0.0.1:2345".parse().unwrap()
        )
    );
    assert_ne!(first.is_ok(), second.is_ok());
    let saved = pm.db.get_peer("ZBX-TEST").await.unwrap().unwrap();
    assert_eq!(
        saved.pk,
        if first.is_ok() {
            vec![1; 32]
        } else {
            vec![2; 32]
        }
    );
}

#[tokio::test]
async fn private_tcp_checks_durable_identity_when_memory_is_stale() {
    use sqlx::Connection;
    let (pm, path) = fixture().await;
    pm.admit_private(
        "ZBX-TEST",
        b"machine",
        &[1; 32],
        "127.0.0.1:1234".parse().unwrap(),
    )
    .await
    .unwrap();
    let mut connection = sqlx::SqliteConnection::connect(path.to_str().unwrap())
        .await
        .unwrap();
    sqlx::query("UPDATE peer SET pk = ? WHERE id = ?")
        .bind(vec![2u8; 32])
        .bind("ZBX-TEST")
        .execute(&mut connection)
        .await
        .unwrap();
    assert!(pm
        .admit_private(
            "ZBX-TEST",
            b"machine",
            &[1; 32],
            "127.0.0.1:2345".parse().unwrap()
        )
        .await
        .is_err());
    assert_eq!(
        pm.db.get_peer("ZBX-TEST").await.unwrap().unwrap().pk,
        vec![2; 32]
    );
}
