fn main() {
    println!(
        "{}",
        embedded_idp_axum::openapi::business_document()
            .to_pretty_json()
            .unwrap()
    );
}
