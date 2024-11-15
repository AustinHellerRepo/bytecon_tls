#[cfg(test)]
mod server_client_tests {
    use std::{io::Write, path::PathBuf, sync::Arc, time::Duration};

    use bytecon::ByteConverter;
    use rand::{Rng, SeedableRng};
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use server_client_bytecon::{ByteConClient, ByteConServer, MessageProcessor};
    use tokio::{sync::Mutex, time::sleep};

    struct EchoMessageProcessor;

    #[derive(Clone)]
    struct EchoRequest {
        message: String,
    }

    impl ByteConverter for EchoRequest {
        fn append_to_bytes(&self, bytes: &mut Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
            self.message.append_to_bytes(bytes)?;
            Ok(())
        }
        fn extract_from_bytes(bytes: &Vec<u8>, index: &mut usize) -> Result<Self, Box<dyn std::error::Error>> where Self: Sized {
            Ok(Self {
                message: String::extract_from_bytes(bytes, index)?,
            })
        }
    }

    struct EchoResponse {
        message: String,
    }

    impl ByteConverter for EchoResponse {
        fn append_to_bytes(&self, bytes: &mut Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
            self.message.append_to_bytes(bytes)?;
            Ok(())
        }
        fn extract_from_bytes(bytes: &Vec<u8>, index: &mut usize) -> Result<Self, Box<dyn std::error::Error>> where Self: Sized {
            Ok(Self {
                message: String::extract_from_bytes(bytes, index)?,
            })
        }
    }

    impl MessageProcessor for EchoMessageProcessor {
        type TInput = EchoRequest;
        type TOutput = EchoResponse;

        async fn process_message(&self, message: &Self::TInput) -> Result<Self::TOutput, Box<dyn std::error::Error>> {
            Ok(EchoResponse {
                message: message.message.clone(),
            })
        }
    }

    #[tokio::test]
    async fn test_u3h8_send_message() {

        let server_address = String::from("localhost");
        let server_port = 8080;
        let server_domain = String::from("localhost");

        let mut server_public_key_tempfile = tempfile::NamedTempFile::new().unwrap();
        println!("public key: {:?}", server_public_key_tempfile.path());

        let mut server_private_key_tempfile = tempfile::NamedTempFile::new().unwrap();
        println!("private key: {:?}", server_private_key_tempfile.path());

        // generate self-signed keys
        let (public_key_bytes, private_key_bytes) = {
            let CertifiedKey { cert, key_pair } = generate_simple_self_signed(vec![server_domain.clone()])
                .expect("Failed to generate self-signed cert.");

            let cert_pem = cert.pem();
            let private_key_pem = key_pair.serialize_pem();

            (cert_pem.into_bytes(), private_key_pem.into_bytes())
        };

        server_public_key_tempfile.write_all(&public_key_bytes)
            .expect("Failed to write public key bytes.");
        server_private_key_tempfile.write_all(&private_key_bytes)
            .expect("Failed to write private key bytes.");
        
        let server_task_error: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let _server_task = {
            let server_address = server_address.clone();
            let server_task_error = server_task_error.clone();
            let server_public_key_file_path: PathBuf = server_public_key_tempfile.path().into();
            let server_private_key_file_path: PathBuf = server_private_key_tempfile.path().into();
            tokio::spawn(async move {
                'process_thread: {
                    let server = ByteConServer::new(
                        server_address,
                        server_port,
                        server_public_key_file_path,
                        server_private_key_file_path,
                        Arc::new(EchoMessageProcessor),
                    );
                    let start_result = server.start()
                        .await
                        .map_err(|error| {
                            format!("Error within server task: {:?}", error)
                        });
                    if let Err(error) = start_result {
                        *server_task_error
                            .lock()
                            .await = Some(error);
                        break 'process_thread;
                    }
                }
            })
        };

        sleep(Duration::from_millis(1000)).await;

        if let Some(error) = server_task_error.lock().await.as_ref() {
            eprintln!("{}", error);
        }
        assert!(server_task_error.lock().await.is_none());

        let client = ByteConClient::<EchoRequest, EchoResponse>::new(
            server_address,
            server_port,
            server_public_key_tempfile.path().into(),
            server_domain,
        );

        let mut random = rand::rngs::StdRng::from_entropy();

        for _ in 0..100 {
            let random_number: u128 = random.gen();
            let message = String::from(format!("{}", random_number));
            let response = client.send_message(&EchoRequest {
                message: message.clone(),
            })
                .await
                .expect("Failed to send message from client to server.");
            assert_eq!(message, response.message);
        }
    }
}