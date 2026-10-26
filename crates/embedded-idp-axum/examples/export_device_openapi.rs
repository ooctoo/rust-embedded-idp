fn main() {
    println!(
        "{}",
        embedded_idp_axum::openapi::device_document()
            .to_pretty_json()
            .unwrap()
    );
}
