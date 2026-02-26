use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let proto_root = manifest_dir.join("../../proto");

    prost_build::compile_protos(
        &[proto_root.join("pod_protocol.proto")],
        &[&proto_root],
    )
    .expect("failed to compile pod_protocol.proto");
}
