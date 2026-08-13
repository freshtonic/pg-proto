#![no_main]

use std::sync::{Arc, Mutex};

use libfuzzer_sys::fuzz_target;
use pg_proto::{
    Client, ClientTlsPolicy, ConnectTarget, StartupParameters, TrustClientAuthentication,
};
use tokio::io::{AsyncWriteExt as _, duplex};

fuzz_target!(|data: &[u8]| {
    let input = data.to_vec();
    tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(async move {
        let (client_io, mut peer) = duplex(input.len().saturating_add(4096));
        tokio::spawn(async move {
            let _ = peer.write_all(&input).await;
            let _ = peer.shutdown().await;
        });
        let transport = Arc::new(Mutex::new(Some(client_io)));
        let client = Client::builder()
            .connector(move |_| {
                let io = transport.lock().unwrap().take().unwrap();
                async move { Ok::<_, std::convert::Infallible>(io) }
            })
            .tls(ClientTlsPolicy::Disabled)
            .authentication(TrustClientAuthentication)
            .build()
            .unwrap();
        if let Ok(connection) = client
            .connect(ConnectTarget::new("fuzz"), StartupParameters::new("fuzz"), ())
            .await
        {
            let _ = connection.into_parts();
        }
    });
});
