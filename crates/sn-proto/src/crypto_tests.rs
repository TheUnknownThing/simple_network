#[cfg(test)]
mod tests {
    use crate::crypto::{derive_node_key, open, random_nonce12, seal};
    use crate::wire::{MsgType, NodeId, WIRE_VERSION};

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let psk = [7u8; 32];
        let node_id = NodeId(uuid::Uuid::from_bytes([1u8; 16]));
        let key = derive_node_key(&psk, node_id);

        let nonce = random_nonce12();
        let aad = {
            let mut v = Vec::new();
            v.push(WIRE_VERSION);
            v.push(MsgType::Encrypted as u8);
            v.extend_from_slice(node_id.as_bytes());
            v.extend_from_slice(node_id.as_bytes());
            v
        };

        let pt = b"hello";
        let ct = seal(&key, &nonce, pt, &aad).unwrap();
        let out = open(&key, &nonce, &ct, &aad).unwrap();
        assert_eq!(&out, pt);
    }
}
