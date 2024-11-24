#[cfg(test)]
mod bytecon_certificate_tests {
    use std::io::Write;

    use bytecon_tls::{ByteConCertificate, ByteConPublicKey};
    use rcgen::{generate_simple_self_signed, CertifiedKey};


    #[test]
    fn test_s9a6_file_path_transition_between_variants() {
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

        println!("test: original public key bytes: {}", public_key_bytes.len());

        server_public_key_tempfile.write_all(&public_key_bytes)
            .expect("Failed to write public key bytes.");
        server_private_key_tempfile.write_all(&private_key_bytes)
            .expect("Failed to write private key bytes.");

        // file path to file path
        {
            println!("test: file path to file path");
            let current = ByteConCertificate::FilePath(server_public_key_tempfile.path().to_path_buf());
            let next_public_key_tempfile = tempfile::NamedTempFile::new().unwrap();
            let next_public_key_certificate = current.as_file_path_variant(next_public_key_tempfile.path().to_path_buf()).unwrap();
            assert_eq!(
                ByteConPublicKey::new(current).get_certificates().unwrap(),
                ByteConPublicKey::new(next_public_key_certificate).get_certificates().unwrap(),
            );
        }
        
        // file path to raw cert
        {
            println!("test: file path to raw cert");
            let current = ByteConCertificate::FilePath(server_public_key_tempfile.path().to_path_buf());
            let next_public_key_certificate = current.as_raw_certs_bytes_variant().unwrap();
            assert_eq!(
                ByteConPublicKey::new(current).get_certificates().unwrap(),
                ByteConPublicKey::new(next_public_key_certificate).get_certificates().unwrap(),
            );
        }

        // file path to base64
        {
            println!("test: file path to base64");
            let current = ByteConCertificate::FilePath(server_public_key_tempfile.path().to_path_buf());
            let next_public_key_certificate = current.as_base64_variant().unwrap();
            assert_eq!(
                ByteConPublicKey::new(current).get_certificates().unwrap(),
                ByteConPublicKey::new(next_public_key_certificate).get_certificates().unwrap(),
            );
        }

        // raw cert to file path
        {
            println!("test: raw cert to file path");
            let cert_file = std::fs::File::open(server_public_key_tempfile.path().to_path_buf()).unwrap();
            let mut reader = std::io::BufReader::new(cert_file);
            let cert_bytes = rustls_pemfile::certs(&mut reader).unwrap();
            let current = ByteConCertificate::RawCertsBytes(cert_bytes);
            let next_public_key_tempfile = tempfile::NamedTempFile::new().unwrap();
            let next_public_key_certificate = current.as_file_path_variant(next_public_key_tempfile.path().to_path_buf()).unwrap();
            assert_eq!(
                ByteConPublicKey::new(current).get_certificates().unwrap(),
                ByteConPublicKey::new(next_public_key_certificate).get_certificates().unwrap(),
            );
        }
        
        // raw cert to raw cert
        {
            println!("test: raw cert to raw cert");
            let cert_file = std::fs::File::open(server_public_key_tempfile.path().to_path_buf()).unwrap();
            let mut reader = std::io::BufReader::new(cert_file);
            let current = ByteConCertificate::RawCertsBytes(rustls_pemfile::certs(&mut reader).unwrap());
            let next_public_key_certificate = current.as_raw_certs_bytes_variant().unwrap();
            assert_eq!(
                ByteConPublicKey::new(current).get_certificates().unwrap(),
                ByteConPublicKey::new(next_public_key_certificate).get_certificates().unwrap(),
            );
        }

        // raw cert to base64
        {
            println!("test: raw cert to base64");
            let cert_file = std::fs::File::open(server_public_key_tempfile.path().to_path_buf()).unwrap();
            let mut reader = std::io::BufReader::new(cert_file);
            let current = ByteConCertificate::RawCertsBytes(rustls_pemfile::certs(&mut reader).unwrap());
            let next_public_key_certificate = current.as_base64_variant().unwrap();
            assert_eq!(
                ByteConPublicKey::new(current).get_certificates().unwrap(),
                ByteConPublicKey::new(next_public_key_certificate).get_certificates().unwrap(),
            );
        }

        // base64 to file path
        {
            println!("test: base64 to file path");
            let current = {
                let cert_file = std::fs::File::open(server_public_key_tempfile.path().to_path_buf()).unwrap();
                let mut reader = std::io::BufReader::new(cert_file);
                let current = ByteConCertificate::RawCertsBytes(rustls_pemfile::certs(&mut reader).unwrap());
                current.as_base64_variant().unwrap()
            };
            let next_public_key_tempfile = tempfile::NamedTempFile::new().unwrap();
            let next_public_key_certificate = current.as_file_path_variant(next_public_key_tempfile.path().to_path_buf()).unwrap();
            assert_eq!(
                ByteConPublicKey::new(current).get_certificates().unwrap(),
                ByteConPublicKey::new(next_public_key_certificate).get_certificates().unwrap(),
            );
        }

        // base64 to raw cert
        {
            println!("test: base64 to raw cert");
            let current = {
                let cert_file = std::fs::File::open(server_public_key_tempfile.path().to_path_buf()).unwrap();
                let mut reader = std::io::BufReader::new(cert_file);
                let current = ByteConCertificate::RawCertsBytes(rustls_pemfile::certs(&mut reader).unwrap());
                current.as_base64_variant().unwrap()
            };
            let next_public_key_certificate = current.as_raw_certs_bytes_variant().unwrap();
            assert_eq!(
                ByteConPublicKey::new(current).get_certificates().unwrap(),
                ByteConPublicKey::new(next_public_key_certificate).get_certificates().unwrap(),
            );
        }

        // base64 to base64
        {
            println!("test: base64 to base64");
            let current = {
                let cert_file = std::fs::File::open(server_public_key_tempfile.path().to_path_buf()).unwrap();
                let mut reader = std::io::BufReader::new(cert_file);
                let current = ByteConCertificate::RawCertsBytes(rustls_pemfile::certs(&mut reader).unwrap());
                current.as_base64_variant().unwrap()
            };
            let next_public_key_certificate = current.as_base64_variant().unwrap();
            assert_eq!(
                ByteConPublicKey::new(current).get_certificates().unwrap(),
                ByteConPublicKey::new(next_public_key_certificate).get_certificates().unwrap(),
            );
        }
    }
}