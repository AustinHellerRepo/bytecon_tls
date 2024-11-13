use std::{error::Error, future::Future, path::PathBuf, sync::Arc};
use bytecon::{ByteConverter, ByteStreamReaderAsync, ByteStreamWriterAsync};
use rand::{rngs::StdRng, Rng};
use tokio::net::TcpStream;

pub struct Client {
    server_address: String,
    server_port: u16,
    public_key_file_path: PathBuf,
    private_key_file_path: PathBuf,
    nonce_generator: StdRng,
    server_public_key_file_path: PathBuf,
}

impl Client {
    pub fn new(server_address: String, server_port: u16) -> Self {
        todo!("Setup public and private key");
        Self {
            server_address,
            server_port,
        }
    }
    async fn connect(&mut self) -> Result<TcpStream, Box<dyn Error>> {
        let nonce: u128 = self.nonce_generator.gen();
        todo!("Sign the nonce with my private key");
        let connecting_address = format!("{}:{}", self.server_address, self.server_port);
        let mut tcp_stream = TcpStream::connect(connecting_address)
            .await?;
        tcp_stream.write_from_byte_converter(&UnencryptedServerRequest::RequestPublicKey {
            client_public_key_bytes,
            signed_payload,
        })
            .await?;
        let response = tcp_stream.read_to_byte_converter::<ServerResponse>()
            .await?;

        Ok(tcp_stream)
    }
    pub async fn send_message<TMessage: ByteConverter, TResponse: ByteConverter>(&self, message: TMessage) -> Result<TResponse, Box<dyn Error>> {
        todo!("Sign message with client private key");
        todo!("Encrypt signed message with server public key");
    }
}

enum UnencryptedServerRequest {
    RequestPublicKey {
        client_public_key_bytes: Vec<u8>,
        signed_payload: Vec<u8>,
    },
    SendMessage {
        message_bytes: Vec<u8>,
        bytecon_type_name: String,
    },
}

impl ByteConverter for UnencryptedServerRequest {
    fn append_to_bytes(&self, bytes: &mut Vec<u8>) -> Result<(), Box<dyn Error>> {
        match self {
            Self::RequestPublicKey {
                client_public_key_bytes,
                signed_payload,
            } => {
                // byte
                0u8.append_to_bytes(bytes)?;

                // vec<u8>
                client_public_key_bytes.append_to_bytes(bytes)?;

                // vec<u8>
                signed_payload.append_to_bytes(bytes)?;
            },
            Self::SendMessage {
                message_bytes,
                bytecon_type_name
            } => {
                // byte
                1u8.append_to_bytes(bytes)?;

                // vec<u8>
                message_bytes.append_to_bytes(bytes)?;

                // string
                bytecon_type_name.append_to_bytes(bytes)?;
            },
        }

        Ok(())
    }
    fn extract_from_bytes(bytes: &Vec<u8>, index: &mut usize) -> Result<Self, Box<dyn Error>> where Self: Sized {
        let enum_variant_byte = u8::extract_from_bytes(bytes, index)?;

        match enum_variant_byte {
            0 => {
                Ok(Self::RequestPublicKey {
                    client_public_key_bytes: Vec::<u8>::extract_from_bytes(bytes, index)?,
                    signed_payload: Vec::<u8>::extract_from_bytes(bytes, index)?,
                })
            },
            1 => {
                Ok(Self::SendMessage {
                    message_bytes: Vec::<u8>::extract_from_bytes(bytes, index)?,
                    bytecon_type_name: String::extract_from_bytes(bytes, index)?,
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

enum ServerResponse {
    SendPublicKey {
        public_key_bytes: Vec<u8>,
    },
    SentMessage,
}

impl ByteConverter for ServerResponse {
    fn append_to_bytes(&self, bytes: &mut Vec<u8>) -> Result<(), Box<dyn Error>> {
        match self {
            Self::SendPublicKey {
                public_key_bytes
            } => {
                // byte
                0u8.append_to_bytes(bytes)?;

                // vec<u8>
                public_key_bytes.append_to_bytes(bytes)?;
            },
            Self::SentMessage => {
                // byte
                1u8.append_to_bytes(bytes)?;
            },
        }

        Ok(())
    }
    fn extract_from_bytes(bytes: &Vec<u8>, index: &mut usize) -> Result<Self, Box<dyn Error>> where Self: Sized {
        let enum_variant_byte = u8::extract_from_bytes(bytes, index)?;

        match enum_variant_byte {
            0 => {
                Ok(Self::SendPublicKey {
                    public_key_bytes: Vec::<u8>::extract_from_bytes(bytes, index)?,
                })
            },
            1 => {
                Ok(Self::SentMessage)
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

pub struct Server<TMessageProcessor: MessageProcessor> {
    bind_address: String,
    bind_port: u16,
    public_key_file_path: PathBuf,  // TODO may need to store the actual tempfile instance
    private_key_file_path: PathBuf,
    message_processor: Arc<TMessageProcessor>,
}

impl<TMessageProcessor: MessageProcessor> Server<TMessageProcessor> {
    pub fn new(bind_address: String, bind_port: u16, message_processor: Arc<TMessageProcessor>) -> Self {
        todo!("Create public and private key temp files.");
        Self {
            bind_address,
            bind_port,
            public_key_file_path,
            private_key_file_path,
            message_processor,
        }
    }
    pub async fn start(&self) -> Result<(), Box<dyn Error>> {
        todo!("Bind to address and spawn tokio thread to handle requests.")
    }
}

trait MessageProcessor {
    type TInput: ByteConverter;
    type TOutput: ByteConverter;

    fn process_message(&self, message: &Self::TInput) -> impl Future<Output = Result<Self::TOutput, Box<dyn Error>>>;
}

#[derive(thiserror::Error, Debug)]
enum ServerClientByteConError {
    #[error("Unexpected enum variant byte {enum_variant_byte} for enum {enum_variant_name}.")]
    UnexpectedEnumVariantByte {
        enum_variant_byte: u8,
        enum_variant_name: String,
    },
}