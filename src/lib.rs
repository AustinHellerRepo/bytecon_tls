use std::{error::Error, future::Future, marker::PhantomData, net::SocketAddr, path::PathBuf, sync::Arc};
use bytecon::{ByteConverter, ByteStreamReaderAsync, ByteStreamWriterAsync};
use cloneless_cow::ClonelessCow;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{rustls::{Certificate, ClientConfig, PrivateKey, RootCertStore, ServerConfig, ServerName}, TlsAcceptor, TlsConnector, TlsStream};

pub struct ByteConClient<TRequest: ByteConverter, TResponse: ByteConverter> {
    server_address: String,
    server_port: u16,
    server_public_key_file_path: PathBuf,
    server_domain: String,
    phantom_request: PhantomData<TRequest>,
    phantom_response: PhantomData<TResponse>,
}

impl<TRequest: ByteConverter, TResponse: ByteConverter> ByteConClient<TRequest, TResponse> {
    pub fn new(server_address: String, server_port: u16, server_public_key_file_path: PathBuf, server_domain: String) -> Self {
        Self {
            server_address,
            server_port,
            server_public_key_file_path,
            server_domain,
            phantom_request: PhantomData::default(),
            phantom_response: PhantomData::default(),
        }
    }
    async fn connect(&self) -> Result<TlsStream<TcpStream>, Box<dyn Error>> {
        
        let config = {
            let cert_file = std::fs::File::open(&self.server_public_key_file_path)?;
            let mut reader = std::io::BufReader::new(cert_file);
            let certs = rustls_pemfile::certs(&mut reader)?;

            let mut root_cert_store = RootCertStore::empty();
            for cert in certs {
                root_cert_store.add(&Certificate(cert))?;
            }

            ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(root_cert_store)
                .with_no_client_auth()
        };

        let connector = TlsConnector::from(Arc::new(config));
        let connecting_address = format!("{}:{}", self.server_address, self.server_port);
        let tcp_stream = TcpStream::connect(connecting_address)
            .await?;
        let server_name = ServerName::try_from(self.server_domain.as_str())?;
        let tls_stream = connector.connect(server_name, tcp_stream)
            .await?;

        Ok(tls_stream.into())
    }
    pub async fn send_message(&self, message: &TRequest) -> Result<TResponse, Box<dyn Error>> {
        let server_request = ServerRequest::SendMessage {
            server_request: ClonelessCow::Borrowed(message),
        };
        let mut tls_stream = self.connect()
            .await?;
        tls_stream.write_from_byte_converter(&server_request)
            .await?;
        let server_response = tls_stream.read_to_byte_converter::<ServerResponse<TResponse>>()
            .await?;
        match server_response {
            ServerResponse::SentMessage {
                server_response
            } => {
                Ok(server_response)
            },
            #[allow(unreachable_patterns)]
            _ => {
                Err(ServerClientByteConError::UnexpectedServerResponse {
                    server_request: String::from(std::any::type_name::<TRequest>()),
                    server_response: String::from(std::any::type_name::<TResponse>()),
                }.into())
            }
        }
    }
}

enum ServerRequest<'a, TServerRequest: ByteConverter> {
    SendMessage {
        server_request: ClonelessCow<'a, TServerRequest>,
    },
}

impl<'a, TServerRequest: ByteConverter> ByteConverter for ServerRequest<'a, TServerRequest> {
    fn append_to_bytes(&self, bytes: &mut Vec<u8>) -> Result<(), Box<dyn Error>> {
        match self {
            Self::SendMessage {
                server_request,
            } => {
                // byte
                0u8.append_to_bytes(bytes)?;

                // TServerRequest
                server_request.as_ref().append_to_bytes(bytes)?;
            },
        }

        Ok(())
    }
    fn extract_from_bytes(bytes: &Vec<u8>, index: &mut usize) -> Result<Self, Box<dyn Error>> where Self: Sized {
        let enum_variant_byte = u8::extract_from_bytes(bytes, index)?;

        match enum_variant_byte {
            0 => {
                Ok(Self::SendMessage {
                    server_request: ClonelessCow::Owned(TServerRequest::extract_from_bytes(bytes, index)?),
                })
            },
            _ => {
                Err(ServerClientByteConError::UnexpectedEnumVariantByte {
                    enum_variant_byte,
                    enum_variant_name: String::from(std::any::type_name::<Self>()),
                }.into())
            }
        }
    }
}

enum ServerResponse<TServerResponse: ByteConverter> {
    SentMessage {
        server_response: TServerResponse,
    },
}

impl<TServerResponse: ByteConverter> ByteConverter for ServerResponse<TServerResponse> {
    fn append_to_bytes(&self, bytes: &mut Vec<u8>) -> Result<(), Box<dyn Error>> {
        match self {
            Self::SentMessage {
                server_response,
            } => {
                // byte
                0u8.append_to_bytes(bytes)?;

                // TServerResponse
                server_response.append_to_bytes(bytes)?;
            },
        }

        Ok(())
    }
    fn extract_from_bytes(bytes: &Vec<u8>, index: &mut usize) -> Result<Self, Box<dyn Error>> where Self: Sized {
        let enum_variant_byte = u8::extract_from_bytes(bytes, index)?;

        match enum_variant_byte {
            0 => {
                Ok(Self::SentMessage {
                    server_response: TServerResponse::extract_from_bytes(bytes, index)?,
                })
            },
            _ => {
                Err(ServerClientByteConError::UnexpectedEnumVariantByte {
                    enum_variant_byte,
                    enum_variant_name: String::from(std::any::type_name::<Self>()),
                }.into())
            }
        }
    }
}

pub struct ByteConServer<TMessageProcessor>
where
    TMessageProcessor: MessageProcessor + Send + Sync + 'static,
    TMessageProcessor::TInput: Send + Sync + 'static,
    TMessageProcessor::TOutput: Send + Sync + 'static,
{
    bind_address: String,
    bind_port: u16,
    public_key_file_path: PathBuf,
    private_key_file_path: PathBuf,
    message_processor: Arc<TMessageProcessor>,
}

impl<TMessageProcessor> ByteConServer<TMessageProcessor>
where
    TMessageProcessor: MessageProcessor + Send + Sync + 'static,
    TMessageProcessor::TInput: Send + Sync + 'static,
    TMessageProcessor::TOutput: Send + Sync + 'static,
{
    pub fn new(
        bind_address: String,
        bind_port: u16,
        public_key_file_path: PathBuf,
        private_key_file_path: PathBuf,
        message_processor: Arc<TMessageProcessor>
    ) -> Self {
        Self {
            bind_address,
            bind_port,
            public_key_file_path,
            private_key_file_path,
            message_processor,
        }
    }
    pub async fn start(&self) -> Result<(), Box<dyn Error>> {
        let certs = {
            let cert_file = std::fs::File::open(&self.public_key_file_path)?;
            let mut reader = std::io::BufReader::new(cert_file);
            let certs = rustls_pemfile::certs(&mut reader)?
                .into_iter()
                .map(Certificate)
                .collect();
            certs
        };

        let key = {
            let key_file = std::fs::File::open(&self.private_key_file_path)?;
            let mut reader = std::io::BufReader::new(key_file);
            let keys = rustls_pemfile::pkcs8_private_keys(&mut reader)?;
            PrivateKey(keys[0].clone())
        };

        // configure the TLS server
        let tls_config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;
        let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

        let listening_address = format!("{}:{}", self.bind_address, self.bind_port);
        println!("Server binding to address {}", listening_address);
        let listener = TcpListener::bind(&listening_address)
            .await?;

        loop {
            let (tcp_stream, client_address) = listener.accept()
                .await?;
            let tls_acceptor = tls_acceptor.clone();
            let message_processor = self.message_processor.clone();

            let _process_task = tokio::spawn(async move {
                match ByteConServer::<TMessageProcessor>::process_tcp_stream(tls_acceptor, tcp_stream, client_address, message_processor).await {
                    Ok(_) => {
                        println!("{}: successfully processed request from client {}.", chrono::Utc::now(), client_address);
                    },
                    Err(error) => {
                        eprintln!("{}: failed to fully process request from client {} with error {:?}", chrono::Utc::now(), client_address, error);
                    },
                }
            });
        }
    }
    async fn process_tcp_stream(tls_acceptor: TlsAcceptor, tcp_stream: TcpStream, client_address: SocketAddr, message_processor: Arc<TMessageProcessor>) -> Result<(), Box<dyn Error>> {
        println!("{}: accepting TLS stream from client {}.", chrono::Utc::now(), client_address);
        match tls_acceptor.accept(tcp_stream).await {
            Ok(tls_stream) => {
                let mut tls_stream = TlsStream::Server(tls_stream);

                println!("{}: reading request from client {}.", chrono::Utc::now(), client_address);
                let server_request = tls_stream.read_to_byte_converter::<ServerRequest<TMessageProcessor::TInput>>()
                    .await?;
                match server_request {
                    ServerRequest::SendMessage {
                        server_request,
                    } => {
                        println!("{}: processing message from client {}.", chrono::Utc::now(), client_address);
                        let server_response = message_processor.process_message(server_request.as_ref())
                            .await?;
                        println!("{}: writing response to client {}.", chrono::Utc::now(), client_address);
                        tls_stream.write_from_byte_converter(&ServerResponse::SentMessage {
                            server_response,
                        })
                            .await?;
                    },
                }
                Ok(())
            },
            Err(e) => {
                eprintln!("{}: failed to accept TLS connection from client {} with error {:?}.", chrono::Utc::now(), client_address, e);
                Err(e.into())
            },
        }
    }
}

pub trait MessageProcessor {
    type TInput: ByteConverter;
    type TOutput: ByteConverter;

    fn process_message(&self, message: &Self::TInput) -> impl Future<Output = Result<Self::TOutput, Box<dyn Error>>> + Send;
}

#[derive(thiserror::Error, Debug)]
enum ServerClientByteConError {
    #[error("Unexpected enum variant byte {enum_variant_byte} for enum {enum_variant_name}.")]
    UnexpectedEnumVariantByte {
        enum_variant_byte: u8,
        enum_variant_name: String,
    },
    #[error("Unexpected server response {server_response} given initial server request {server_request}.")]
    UnexpectedServerResponse {
        server_response: String,
        server_request: String,
    },
}