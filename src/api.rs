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
        Mime::from_str("text/json; charset=utf-8")
            .unwrap()
    }
    fn mime_txt() -> Mime {
        Mime::from_str("text/plain; charset=utf-8")
            .unwrap()
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        loop {
            let (conn, peer) = self
                .listener
                .accept()
                .await
                .log_warn()?;

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
            match url.path().to_lowercase().as_str(){
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

              "/reload" => {
                  let mut res =
                      Response::new(StatusCode::Ok);
                  res.set_content_type(Self::mime_txt());

                  let t = Instant::now();
                  let ret = daemon.context
                            .cache.load().await;
                  let t = t.elapsed();
                  match ret {
                      Ok(_) => {
                          res.set_body(format!("DNS Cache reloaded from disk db. (used time: {t:?})"));
                      },
                      Err(e) => {
                          res.set_status(StatusCode::InternalServerError);
                          res.set_body(format!("Failed to reload dns cache (used time: {t:?}): Error={e:?}"));
                      }
                  }

                  Ok(res)
              },

              #[cfg(feature = "rsinfo")]
              "/info" => {
                  let mut res = Response::new(StatusCode::Ok);
                  res.set_content_type(Self::mime_json());
                  res.set_body(
                      format!(
                          "{:#}",
                          rsinfo::ALL_INFO.to_json()
                      )
                  );
                  Ok(res)

              },

              "/version" => {
                  let mut res =
                      Response::new(StatusCode::Ok);
                  res.set_content_type(Self::mime_txt());
                  res.set_body(option_env!("CARGO_PKG_VERSION").unwrap_or("N/A"));
                  Ok(res)
              },

              "/stats" => {
                  let mut res =
                      Response::new(StatusCode::Ok);

                  res.set_content_type(Self::mime_json());
                  res.set_body(format!("{:#}", daemon.context.stats.json().await));
                  Ok(res)

              },

              _ => {
                let mut res =
                  Response::new(StatusCode::NotFound);
                res.set_body(
                  "
List of avaliable commands:
GET /snap      ->  take a snapshot of database.
GET /metrics   ->  get all metrics for each resolvers.
GET /reload    ->  reload DNS cache entries from disk database.
GET /version   ->  current version 
GET /info      ->  get build info
GET /stats     ->  get DNS query analysis
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
