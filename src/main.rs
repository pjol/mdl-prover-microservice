use http_body_util::{combinators::BoxBody, BodyExt};
use hyper::body::Bytes;
use http_body_util::Full;
use http_body_util::Empty;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{body::Incoming as IncomingBody, Request, Response};
use hyper::{Method, StatusCode};
use tokio::net::TcpListener;

use std::net::SocketAddr;
use hyper_util::rt::TokioIo;

mod routes;
mod evm;

pub fn mk_response(s: String) ->  Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    Ok(Response::new(full(s)))
}

pub fn mk_err(s: String, e: hyper::StatusCode) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let mut resp = Response::new(full(s));
    *resp.status_mut() = e;
    return Ok(resp);
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr: SocketAddr = ([127, 0, 0, 1], 3000).into();

    let listener = TcpListener::bind(addr).await?;
    println!("Listening on http://{}", addr);

    evm::test_provider().await;

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new().serve_connection(io, service_fn(call)).await {
                println!("Failed to serve connection: {:?}", err);
            }
        });
    }
}

async fn call(req: Request<IncomingBody>) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let res = match (req.method(), req.uri().path()) {
        (&Method::POST, "/prove") => routes::prove(req).await,
        _ => {
            let mut not_found = Response::new(empty());
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            return Ok(not_found)
        },
    };

    res
}

pub fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}
pub fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}