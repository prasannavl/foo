extern crate bytes;
extern crate hyper;
extern crate futures;
extern crate scheduled_thread_pool;
extern crate tokio_core;
extern crate tokio_openssl;
extern crate tokio_io_timeout;
extern crate openssl;

use bytes::BytesMut;
use futures::future::{Future, BoxFuture};
use futures::stream::{self, Stream};
use futures::sink::{self, Sink};
use futures::sync::mpsc;
use futures::sync::oneshot;
use hyper::server::{Service, Http, Request as HyperRequest, Response as HyperResponse};
use hyper::{Method, Uri, HttpVersion, Headers, Body, StatusCode, Chunk};
use std::sync::Arc;
use scheduled_thread_pool::ScheduledThreadPool;
use std::io::{self, Read, Write, Cursor};
use tokio_core::net::TcpListener;
use tokio_core::reactor::Core;
use tokio_io_timeout::TimeoutStream;
use std::time::Duration;
use openssl::ssl::{SslAcceptorBuilder, SslMethod};
use openssl::x509::X509_FILETYPE_PEM;
use tokio_openssl::SslAcceptorExt;

fn main() {
    let mut core = Core::new().unwrap();
    let handle = core.handle();

    let mut acceptor = SslAcceptorBuilder::mozilla_intermediate_raw(SslMethod::tls()).unwrap();
    acceptor.builder_mut().set_certificate_chain_file("test/cert.pem").unwrap();
    acceptor.builder_mut().set_private_key_file("test/key.pem", X509_FILETYPE_PEM).unwrap();
    let acceptor = acceptor.build();

    let http = Http::new();

    let pool = Arc::new(ScheduledThreadPool::new(4));
    let addr = "127.0.0.1:1337".parse().unwrap();

    let fut = TcpListener::bind(&addr, &handle)
        .unwrap()
        .incoming()
        .map_err(|e| {
            println!("error accepting: {}", e);
            ()
        })
        .for_each(|(s, addr)| {
            let mut s = TimeoutStream::new(s, &handle);
            s.set_read_timeout(Some(Duration::from_secs(30)));
            s.set_write_timeout(Some(Duration::from_secs(30)));

            let http = &http;
            let handle = &handle;
            let pool = pool.clone();
            acceptor.accept_async(s)
                .map_err(|e| {
                    println!("error handshaking: {}", e);
                    ()
                })
                .and_then(move |s| {
                    http.bind_connection(handle, s, addr, Handler(pool));
                    Ok(())
                })
        });

    core.run(fut).unwrap();
}

struct Handler(Arc<ScheduledThreadPool>);

impl Service for Handler {
    type Request = HyperRequest;
    type Response = HyperResponse;
    type Error = hyper::Error;
    type Future = BoxFuture<HyperResponse, hyper::Error>;

    fn call(&self, req: HyperRequest) -> BoxFuture<HyperResponse, hyper::Error> {
        let req = Request::new(req);
        let (tx, rx) = oneshot::channel();
        self.0.execute(|| handle(req, tx));
        rx.map(|resp| resp.into())
            .or_else(|_| {
                Ok(HyperResponse::new().with_status(
                    StatusCode::InternalServerError,
                ))
            })
            .boxed()
    }
}

struct Request {
    method: Method,
    uri: Uri,
    version: HttpVersion,
    headers: Headers,
    body: Body,
}

impl Request {
    fn new(req: HyperRequest) -> Request {
        let (method, uri, version, headers, body) = req.deconstruct();
        Request {
            method,
            uri,
            version,
            headers,
            body,
        }
    }

    pub fn method(&self) -> &Method {
        &self.method
    }

    pub fn uri(&self) -> &Uri {
        &self.uri
    }

    pub fn version(&self) -> &HttpVersion {
        &self.version
    }

    pub fn headers(&self) -> &Headers {
        &self.headers
    }

    pub fn body(self) -> RequestBody {
        RequestBody {
            it: self.body.wait(),
            buf: Cursor::new(Chunk::from("")),
        }
    }
}

struct RequestBody {
    it: stream::Wait<Body>,
    buf: Cursor<Chunk>,
}

impl Read for RequestBody {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.buf.read(buf) {
                Ok(0) => {
                    match self.it.next() {
                        Some(Ok(chunk)) => self.buf = Cursor::new(chunk),
                        Some(Err(e)) => return Err(io::Error::new(io::ErrorKind::Other, e)),
                        None => return Ok(0),
                    }
                }
                Ok(n) => return Ok(n),
                Err(e) => return Err(e),
            }
        }
    }
}

struct ResponseBody {
    buf: BytesMut,
    tx: sink::Wait<mpsc::Sender<hyper::Result<Chunk>>>,
}

impl Write for ResponseBody {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buf.extend(buf);
        if self.buf.len() >= 8192 {
            self.tx.send(Ok(self.buf.take().freeze().into())).map_err(
                |e| {
                    io::Error::new(io::ErrorKind::Other, e)
                },
            )?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.buf.len() > 0 {
            self.tx.send(Ok(self.buf.take().freeze().into())).map_err(
                |e| {
                    io::Error::new(io::ErrorKind::Other, e)
                },
            )?;
        }
        self.tx.flush().map_err(
            |e| io::Error::new(io::ErrorKind::Other, e),
        )
    }
}

fn handle(req: Request, resp: oneshot::Sender<HyperResponse>) {
    let (tx, rx) = mpsc::channel(1);
    let _ = resp.send(HyperResponse::new().with_body(rx));
    let mut body = ResponseBody {
        buf: BytesMut::new(),
        tx: tx.wait(),
    };
    let _ = io::copy(&mut req.body(), &mut body);
    let _ = body.flush();
}
