fn main() {
    println!(
        "{}",
        embedded_idp_axum::openapi::shared_oidc_document()
            .to_pretty_json()
            .unwrap()
    );
}
