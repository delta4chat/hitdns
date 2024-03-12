use crate::*;

use core::str::FromStr;
use http_types::{Mime, Response, StatusCode};
use smol::net::TcpListener;

#[derive(Debug)]
pub struct HitdnsAPI {
  listener: TcpListener,
  daemon: Arc<DNSDaemon>,
}

impl HitdnsAPI {
  pub async fn new(
    listen: SocketAddr,
    daemon: Arc<DNSDaemon>,
  ) -> anyhow::Result<Self> {
    if !listen.ip().is_loopback() {
      anyhow::bail!("currently API does not support external access. you can specify a loopback IP such as 127.0.0.0/8 or [::1]");
    }

    let listener = TcpListener::bind(listen).await?;

    Ok(Self { listener, daemon })
  }

  fn mime_json() -> Mime {
    Mime::from_str("text/json; charset=utf-8").unwrap()
  }
  fn mime_txt() -> Mime {
    Mime::from_str("text/plain; charset=utf-8").unwrap()
  }

  pub async fn run(&self) -> anyhow::Result<()> {
    loop {
      let (conn, peer) =
        self.listener.accept().await.log_warn()?;

      let daemon = self.daemon.clone();
      smolscale2::spawn(async_h1::accept(
        conn,
        move |req| {
          let daemon = daemon.clone();
          async move {
            log::info!(
              "API accept HTTP request from {peer:?}"
            );
            let url = req.url();
            match url.path() {
              "/snap" => {
                let json = DatabaseSnapshot::export()
                  .await?
                  .to_json();

                let mut res =
                  Response::new(StatusCode::Ok);
                res.set_body(format!("{json:#}"));
                res.set_content_type(Self::mime_json());

                Ok(res)
              },

              "/metrics" => {
                let mut all_metrics =
                  serde_json::Map::new();
                for ds in
                  daemon.context.cache.resolvers.list.iter()
                {
                  let upstream = ds.dns_upstream();
                  let mut metrics =
                    ds.dns_metrics().await.to_json();

                  {
                    let obj =
                      metrics.as_object_mut().unwrap();
                    obj.remove("upstream");
                  }

                  all_metrics.insert(upstream, metrics);
                }

                let all_metrics =
                  serde_json::Value::Object(all_metrics);

                let mut res =
                  Response::new(StatusCode::Ok);
                res.set_body(format!("{all_metrics:#}"));
                res.set_content_type(Self::mime_json());

                Ok(res)
              },

              _ => {
                let mut res =
                  Response::new(StatusCode::NotFound);
                res.set_body(
                  "
List of avaliable commands:
/snap      ->  take a snapshot of database.
/metrics   ->  get all metrics for each resolvers
/version   (TODO)
/info      (TODO)
/stat      (TODO)
",
                );
                res.set_content_type(Self::mime_txt());
                Ok(res)
              },
            } // match
          } // async move
        },
      ))
      .detach();
    }
  }
}
