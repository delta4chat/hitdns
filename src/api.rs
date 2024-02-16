use crate::*;

use core::str::FromStr;
use http_types::{Response, StatusCode, Mime};
use smol::net::TcpListener;

pub struct HitdnsAPI {
    listener: TcpListener
}
impl HitdnsAPI {
    pub async fn new(listen: SocketAddr)
        -> anyhow::Result<Self>
    {
        if ! listen.ip().is_loopback() {
            anyhow::bail!("currently API does not support external access. you can specify a loopback IP such as 127.0.0.0/8 or [::1]");
        }

        let listener = TcpListener::bind(listen).await?;

        Ok(Self {
            listener,
        })
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        loop {
            let (conn, peer) =
                self.listener.accept().await.log_warn()?;

            smolscale2::spawn(async move {
                async_h1::accept(conn, |req| async move {
                    log::info!("API accept HTTP request from {peer:?}");
                    let url = req.url();
                    match url.path() {
                        "/snap" => {
                            let json =
                                DatabaseSnapshot::export()
                                .await?.to_json();
                            let mut res =
                                Response::new(StatusCode::Ok);
                            res.set_body(
                                format!("{:#}", json)
                            );
                            res.set_content_type(
                                Mime::from_str(
                                    "text/json; charset=utf-8"
                                )?
                            );
                            Ok(res)
                        },

                        "/stat" => {
                            todo!()
                        },

                        _ => {
                            let mut res =
                                Response::new(StatusCode::Ok);
                            res.set_body(
                                "
                                List of avaliable commands:
                                /snap
                                /version
                                /info
                                /stat
                                ");
                            res.set_content_type(
                                Mime::from_str(
                                "text/plain; charset=utf-8"
                                )?
                            );
                            Ok(res)
                        }
                    }
                }).await.unwrap();
            }).detach();
        }
    }
}


