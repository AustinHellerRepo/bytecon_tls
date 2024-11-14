use std::{error::Error, future::Future, net::SocketAddr, path::PathBuf, sync::Arc};
use bytecon::{ByteConverter, ByteStreamReaderAsync, ByteStreamWriterAsync};
use rand::{rngs::StdRng, Rng};
use tokio::net::{TcpListener, TcpStream};

pub struct Client {
    server_address: String,
    server_port: u16,
    //public_key_file_path: PathBuf,
    //private_key_file_path: PathBuf,
    //nonce_generator: StdRng,
    //server_public_key_file_path: PathBuf,
}

impl Client {
    pub fn new(server_address: String, server_port: u16) -> Self {
        //todo!("Setup public and private key");
        Self {
            server_address,
            server_port,
        }
    }
    async fn connect(&self) -> Result<TcpStream, Box<dyn Error>> {
        // TODO keep `self` as a reference and add a mutex for connecting to the server once
        //let nonce: u128 = self.nonce_generator.gen();
        //todo!("Sign the nonce with my private key");
        let connecting_address = format!("{}:{}", self.server_address, self.server_port);
        let tcp_stream = TcpStream::connect(connecting_address)
            .await?;
        //tcp_stream.write_from_byte_converter(&UnencryptedServerRequest::RequestPublicKey {
        //    client_public_key_bytes,
        //    signed_payload,
        //})
        //    .await?;
        //let response = tcp_stream.read_to_byte_converter::<ServerResponse>()
        //    .await?;

        Ok(tcp_stream)
    }
    pub async fn send_message<TMessage: ByteConverter, TResponse: ByteConverter>(&self, message: TMessage) -> Result<TResponse, Box<dyn Error>> {
        //todo!("React to the `connect` function not yet being called.");
        //todo!("Sign message with client private key");
        //todo!("Encrypt signed message with server public key");
        let server_request = ServerRequest::SendMessage {
            server_request: message,
            bytecon_type_name: String::from(std::any::type_name::<TMessage>()),
        };
        let mut stream = self.connect()
            .await?;
        stream.write_from_byte_converter(&server_request)
            .await?;
        let server_response = stream.read_to_byte_converter()
            .await?;
        Ok(server_response)
    }
}

enum ServerRequest<TServerRequest: ByteConverter> {
    SendMessage {
        server_request: TServerRequest,
        bytecon_type_name: String,
    },
    RequestPublicKey {
        client_public_key_bytes: Vec<u8>,
        signed_payload: Vec<u8>,
    },
}

impl<TServerRequest: ByteConverter> ByteConverter for ServerRequest<TServerRequest> {
    fn append_to_bytes(&self, bytes: &mut Vec<u8>) -> Result<(), Box<dyn Error>> {
        match self {
            Self::SendMessage {
                server_request,
                bytecon_type_name
            } => {
                // byte
                0u8.append_to_bytes(bytes)?;

                // TServerRequest
                server_request.append_to_bytes(bytes)?;

                // string
                bytecon_type_name.append_to_bytes(bytes)?;
            },
            Self::RequestPublicKey {
                client_public_key_bytes,
                signed_payload,
            } => {
                // byte
                1u8.append_to_bytes(bytes)?;

                // vec<u8>
                client_public_key_bytes.append_to_bytes(bytes)?;

                // vec<u8>
                signed_payload.append_to_bytes(bytes)?;
            },
        }

        Ok(())
    }
    fn extract_from_bytes(bytes: &Vec<u8>, index: &mut usize) -> Result<Self, Box<dyn Error>> where Self: Sized {
        let enum_variant_byte = u8::extract_from_bytes(bytes, index)?;

        match enum_variant_byte {
            0 => {
                Ok(Self::SendMessage {
                    server_request: TServerRequest::extract_from_bytes(bytes, index)?,
                    bytecon_type_name: String::extract_from_bytes(bytes, index)?,
                })
            },
            1 => {
                Ok(Self::RequestPublicKey {
                    client_public_key_bytes: Vec::<u8>::extract_from_bytes(bytes, index)?,
                    signed_payload: Vec::<u8>::extract_from_bytes(bytes, index)?,
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
    SendPublicKey {
        public_key_bytes: Vec<u8>,
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
            Self::SendPublicKey {
                public_key_bytes
            } => {
                // byte
                1u8.append_to_bytes(bytes)?;

                // vec<u8>
                public_key_bytes.append_to_bytes(bytes)?;
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
            1 => {
                Ok(Self::SendPublicKey {
                    public_key_bytes: Vec::<u8>::extract_from_bytes(bytes, index)?,
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

pub struct Server<TMessageProcessor>
where
    TMessageProcessor: MessageProcessor + Send + Sync + 'static,
    TMessageProcessor::TInput: Send + Sync + 'static,
    TMessageProcessor::TOutput: Send + Sync + 'static,
{
    bind_address: String,
    bind_port: u16,
    //public_key_file_path: PathBuf,  // TODO may need to store the actual tempfile instance
    //private_key_file_path: PathBuf,
    message_processor: Arc<TMessageProcessor>,
}

impl<TMessageProcessor> Server<TMessageProcessor>
where
    TMessageProcessor: MessageProcessor + Send + Sync + 'static,
    TMessageProcessor::TInput: Send + Sync + 'static,
    TMessageProcessor::TOutput: Send + Sync + 'static,
{
    pub fn new(bind_address: String, bind_port: u16, message_processor: Arc<TMessageProcessor>) -> Self {
        //todo!("Create public and private key temp files.");
        Self {
            bind_address,
            bind_port,
            //public_key_file_path,
            //private_key_file_path,
            message_processor,
        }
    }
    pub async fn start(&self) -> Result<(), Box<dyn Error>> {
        //todo!("Bind to address and spawn tokio thread to handle requests.")

        let listening_address = format!("{}:{}", self.bind_address, self.bind_port);
        println!("Server binding to address {}", listening_address);
        let listener = TcpListener::bind(&listening_address)
            .await?;

        loop {
            let (tcp_stream, client_address) = listener.accept()
                .await?;
            let message_processor = self.message_processor.clone();

            let _process_task = tokio::spawn(async move {
                match Server::<TMessageProcessor>::process_tcp_stream(tcp_stream, client_address, message_processor).await {
                    Ok(_) => {
                        println!("{}: processed request from client {}.", chrono::Utc::now(), client_address);
                    },
                    Err(error) => {
                        eprintln!("{}: failed to fully process request from client {} with error {:?}", chrono::Utc::now(), client_address, error);
                    },
                }
            });
        }
    }
    async fn process_tcp_stream(mut tcp_stream: TcpStream, client_address: SocketAddr, message_processor: Arc<TMessageProcessor>) -> Result<(), Box<dyn Error>> {
        println!("{}: reading request from client {}.", chrono::Utc::now(), client_address);
        let message = tcp_stream.read_to_byte_converter::<TMessageProcessor::TInput>()
            .await?;
        println!("{}: processing request from client {}.", chrono::Utc::now(), client_address);
        let response = message_processor.process_message(&message)
            .await?;
        println!("{}: writing response to client {}.", chrono::Utc::now(), client_address);
        tcp_stream.write_from_byte_converter(&response)
            .await?;
        Ok(())
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
}