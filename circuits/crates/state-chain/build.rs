use std::env;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("proto");
    let proto_files = vec![root.join("tx.proto")];

    //prost_build::compile_protos(&["proto/tx.proto"], &["proto"]).unwrap();
    for proto_file in &proto_files {
        println!("cargo:rerun-if-changed={}", proto_file.display());
    }

    let descriptor_path = PathBuf::from(env::var("OUT_DIR").unwrap()).join("proto_descriptor.bin");

    prost_build::Config::new()
        // Save descriptors to file
        .file_descriptor_set_path(&descriptor_path)
        // Override prost-types with pbjson-types
        .compile_well_known_types()
        .extern_path(".google.protobuf", "::pbjson_types")
        // Generate prost structs
        .compile_protos(&proto_files, &[root])?;

    //let descriptor_set = std::fs::read(descriptor_path)?;
    //pbjson_build::Builder::new()
    //    .register_descriptors(&descriptor_set)?
    //    .build(&[".goat.goat.v1"])?;
    Ok(())
}
