fn main() {
    println!(
        "{}",
        embedded_idp_axum::openapi::scan_document()
            .to_pretty_json()
            .unwrap()
    );
}
